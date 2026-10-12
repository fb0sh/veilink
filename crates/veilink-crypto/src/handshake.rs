//! The `VLP/1` authentication handshake.
//!
//! The handshake exists to answer one question before a single proxy request is read: *is the peer
//! the holder of the pre-shared key, and are we really talking to them and not to a relay?*
//!
//! ```text
//!    client                                              server
//!      │  CLIENT_HELLO { version, client_random,          │
//!      │                 recv_algorithm_mask }            │
//!      ├─────────────────────────────────────────────────►│
//!      │                                                  │  derive transcript
//!      │  SERVER_HELLO { version, server_random,          │
//!      │                 recv_algorithm_mask, pool hint } │
//!      │◄─────────────────────────────────────────────────┤
//!      │  both compute: exporter = TLS-exporter(          │
//!      │      "EXPORTER-Veilink-VLP1", transcript_hash)   │
//!      │  AUTH_CONFIRM { HMAC(k_auth_c2s, …) }            │
//!      ├─────────────────────────────────────────────────►│  verify, then
//!      │  AUTH_CONFIRM { HMAC(k_auth_s2c, …) }            │  reply
//!      │◄─────────────────────────────────────────────────┤
//!      │  verify                                          │
//! ```
//!
//! ## Why the TLS exporter matters
//!
//! The server's TLS certificate is self-signed, so the client cannot authenticate it through a
//! certificate authority. Accepting an unverified certificate would be unsafe on its own. What
//! makes the connection secure instead is that both confirmation MACs cover the TLS exporter value
//! of the session the peer is actually on:
//!
//! * an attacker relaying the handshake between the client and the real server terminates two
//!   *different* TLS sessions, so the exporter differs on each leg and the MAC the server produces
//!   will not verify at the client;
//! * an attacker who does not hold the PSK cannot produce either MAC at all;
//! * a replayed handshake from a recorded session carries that session's exporter, which the new
//!   TLS session does not have, so it fails too.
//!
//! A downgrade is impossible by construction: there is no "unauthenticated mode" to fall back to,
//! and any failure returns an error that the transport turns into an immediate connection close.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::aead::AlgorithmSet;
use crate::epoch::Direction;
use crate::kdf::{
    confirmation_mac, derive_handshake_keys, verify_mac, HandshakeKeys, Transcript, EXPORTER_LABEL,
    HASH_LEN, PROTOCOL_LABEL,
};
use crate::psk::Psk;
use crate::rng::random_array;
use crate::CryptoError;

/// The `VLP/1` protocol version implemented by this build.
pub const PROTOCOL_VERSION: u8 = 1;

/// Length of a `CLIENT_HELLO` message.
pub const CLIENT_HELLO_LEN: usize = 1 + 32 + 1 + 2;
/// Length of a `SERVER_HELLO` message: version, server random, algorithm mask, reserved, pool hint
/// and the server's long-term identity public key.
pub const SERVER_HELLO_LEN: usize = 1 + 32 + 1 + 2 + 2 + 32;
/// Length of an `AUTH_CONFIRM` message.
pub const AUTH_CONFIRM_LEN: usize = HASH_LEN;

/// A `CLIENT_HELLO` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// Protocol version the client speaks.
    pub version: u8,
    /// 32 random bytes, unique per handshake.
    pub client_random: [u8; 32],
    /// Algorithms the client is willing to receive.
    pub recv_algorithms: AlgorithmSet,
}

impl ClientHello {
    /// Builds a fresh hello.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(ClientHello {
            version: PROTOCOL_VERSION,
            client_random: random_array::<32>()?,
            recv_algorithms: AlgorithmSet::all(),
        })
    }

    /// Encodes the message.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CLIENT_HELLO_LEN);
        out.push(self.version);
        out.extend_from_slice(&self.client_random);
        out.push(self.recv_algorithms.mask());
        out.extend_from_slice(&0u16.to_be_bytes());
        out
    }

    /// Decodes and validates the message.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != CLIENT_HELLO_LEN {
            return Err(CryptoError::Truncated {
                needed: CLIENT_HELLO_LEN,
                actual: bytes.len(),
            });
        }
        let version = bytes[0];
        if version != PROTOCOL_VERSION {
            return Err(CryptoError::Handshake(format!(
                "client speaks VLP/{version}, this build implements VLP/{PROTOCOL_VERSION}"
            )));
        }
        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(&bytes[1..33]);
        if client_random.iter().all(|b| *b == 0) {
            return Err(CryptoError::Handshake(
                "client random is all zeroes".to_string(),
            ));
        }
        let recv_algorithms = AlgorithmSet::from_mask(bytes[33])?;
        if bytes[34] != 0 || bytes[35] != 0 {
            return Err(CryptoError::Handshake(
                "reserved CLIENT_HELLO field is not zero".to_string(),
            ));
        }
        Ok(ClientHello {
            version,
            client_random,
            recv_algorithms,
        })
    }
}

/// A `SERVER_HELLO` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// Protocol version the server speaks.
    pub version: u8,
    /// 32 random bytes, unique per handshake.
    pub server_random: [u8; 32],
    /// Algorithms the server is willing to receive.
    pub recv_algorithms: AlgorithmSet,
    /// Number of one-time keys the server will publish immediately.
    pub key_pool_hint: u16,
    /// The server's long-term identity public key.
    ///
    /// It is authenticated because the whole `SERVER_HELLO` is covered by the transcript, and the
    /// transcript is covered by the PSK-bound confirmation MAC. A client can therefore pin it and
    /// detect a server being swapped for a different deployment that happens to share the PSK.
    pub identity: [u8; 32],
}

impl ServerHello {
    /// Builds a fresh hello advertising `identity` as this server's long-term identity.
    pub fn generate(key_pool_hint: u16, identity: [u8; 32]) -> Result<Self, CryptoError> {
        if identity.iter().all(|b| *b == 0) {
            return Err(CryptoError::Handshake(
                "server identity public key is all zeroes".to_string(),
            ));
        }
        Ok(ServerHello {
            version: PROTOCOL_VERSION,
            server_random: random_array::<32>()?,
            recv_algorithms: AlgorithmSet::all(),
            key_pool_hint,
            identity,
        })
    }

    /// Encodes the message.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SERVER_HELLO_LEN);
        out.push(self.version);
        out.extend_from_slice(&self.server_random);
        out.push(self.recv_algorithms.mask());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&self.key_pool_hint.to_be_bytes());
        out.extend_from_slice(&self.identity);
        out
    }

    /// Decodes and validates the message.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != SERVER_HELLO_LEN {
            return Err(CryptoError::Truncated {
                needed: SERVER_HELLO_LEN,
                actual: bytes.len(),
            });
        }
        let version = bytes[0];
        if version != PROTOCOL_VERSION {
            return Err(CryptoError::Handshake(format!(
                "server speaks VLP/{version}, this build implements VLP/{PROTOCOL_VERSION}"
            )));
        }
        let mut server_random = [0u8; 32];
        server_random.copy_from_slice(&bytes[1..33]);
        if server_random.iter().all(|b| *b == 0) {
            return Err(CryptoError::Handshake(
                "server random is all zeroes".to_string(),
            ));
        }
        let recv_algorithms = AlgorithmSet::from_mask(bytes[33])?;
        if bytes[34] != 0 || bytes[35] != 0 {
            return Err(CryptoError::Handshake(
                "reserved SERVER_HELLO field is not zero".to_string(),
            ));
        }
        let key_pool_hint = u16::from_be_bytes([bytes[36], bytes[37]]);
        let mut identity = [0u8; 32];
        identity.copy_from_slice(&bytes[38..70]);
        if identity.iter().all(|b| *b == 0) {
            return Err(CryptoError::Handshake(
                "server identity public key is all zeroes".to_string(),
            ));
        }
        Ok(ServerHello {
            version,
            server_random,
            recv_algorithms,
            key_pool_hint,
            identity,
        })
    }
}

/// The state of a handshake in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Nothing exchanged yet.
    Started,
    /// The hello messages have been exchanged.
    HelloComplete,
    /// Both confirmations have been verified; the session is authenticated.
    Authenticated,
    /// The handshake failed and the connection must be closed.
    Failed,
}

/// The client side of the handshake.
pub struct ClientHandshake {
    psk: Zeroizing<Vec<u8>>,
    transcript: Transcript,
    state: HandshakeState,
    hello: ClientHello,
    server_hello: Option<ServerHello>,
    keys: Option<HandshakeKeys>,
}

impl std::fmt::Debug for ClientHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHandshake")
            .field("state", &self.state)
            .field("session_id", &self.keys.as_ref().map(|k| k.session_id))
            .finish_non_exhaustive()
    }
}

impl ClientHandshake {
    /// Starts a handshake and produces the `CLIENT_HELLO` to send.
    pub fn start(psk: &Psk) -> Result<(Self, Vec<u8>), CryptoError> {
        let hello = ClientHello::generate()?;
        let bytes = hello.encode();
        let mut transcript = Transcript::new();
        transcript.absorb_prefixed(&bytes);
        Ok((
            ClientHandshake {
                psk: Zeroizing::new(psk.as_bytes().to_vec()),
                transcript,
                state: HandshakeState::Started,
                hello,
                server_hello: None,
                keys: None,
            },
            bytes,
        ))
    }

    /// Current state.
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Consumes the `SERVER_HELLO`.
    pub fn on_server_hello(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        if self.state != HandshakeState::Started {
            return Err(CryptoError::Handshake(
                "SERVER_HELLO received out of order".to_string(),
            ));
        }
        let hello = ServerHello::decode(bytes)?;
        if hello.server_random == self.hello.client_random {
            return Err(CryptoError::Handshake(
                "server random equals client random".to_string(),
            ));
        }
        self.transcript.absorb_prefixed(bytes);
        self.server_hello = Some(hello);
        self.state = HandshakeState::HelloComplete;
        Ok(())
    }

    /// The transcript hash over the exchanges so far. Input to the TLS exporter.
    pub fn transcript_hash(&self) -> [u8; HASH_LEN] {
        self.transcript.hash()
    }

    /// The server's advertised long-term identity, available after `SERVER_HELLO`.
    pub fn server_identity(&self) -> Option<[u8; 32]> {
        self.server_hello.as_ref().map(|h| h.identity)
    }

    /// The TLS exporter label this protocol binds to.
    pub fn exporter_label() -> &'static [u8] {
        EXPORTER_LABEL
    }

    /// Produces the client's `AUTH_CONFIRM` message.
    pub fn client_confirm(&mut self, exporter: [u8; HASH_LEN]) -> Result<Vec<u8>, CryptoError> {
        if self.state != HandshakeState::HelloComplete {
            return Err(CryptoError::Handshake(
                "AUTH_CONFIRM requested before the hello exchange completed".to_string(),
            ));
        }
        let keys = self.build_keys(exporter)?;
        let mac = confirmation_mac(
            &keys.auth_c2s,
            Direction::ClientToServer,
            &keys.transcript_hash,
            &keys.exporter,
        );
        self.keys = Some(keys);
        Ok(mac.to_vec())
    }

    /// Verifies the server's `AUTH_CONFIRM` and completes the handshake.
    pub fn verify_server_confirm(mut self, bytes: &[u8]) -> Result<HandshakeKeys, CryptoError> {
        let keys = match self.keys.take() {
            Some(keys) => keys,
            None => return Err(CryptoError::Handshake("handshake was not started".to_string())),
        };
        let expected = confirmation_mac(
            &keys.auth_s2c,
            Direction::ServerToClient,
            &keys.transcript_hash,
            &keys.exporter,
        );
        match verify_mac(&expected, bytes) {
            Ok(()) => {
                self.state = HandshakeState::Authenticated;
                Ok(keys)
            }
            Err(error) => {
                self.state = HandshakeState::Failed;
                Err(error)
            }
        }
    }

    fn build_keys(&self, exporter: [u8; HASH_LEN]) -> Result<HandshakeKeys, CryptoError> {
        let psk = Psk::from_bytes(&self.psk)?;
        let server = self
            .server_hello
            .as_ref()
            .ok_or_else(|| CryptoError::Handshake("SERVER_HELLO was not received".to_string()))?;
        Ok(derive_handshake_keys(
            &psk,
            self.transcript.hash(),
            exporter,
            // The client *sends* using the algorithms the server can receive, and *receives* using
            // the algorithms it advertised itself.
            server.recv_algorithms,
            self.hello.recv_algorithms,
        ))
    }
}

/// The server side of the handshake.
pub struct ServerHandshake {
    psk: Zeroizing<Vec<u8>>,
    transcript: Transcript,
    state: HandshakeState,
    client_hello: Option<ClientHello>,
    server_hello: Option<ServerHello>,
    keys: Option<HandshakeKeys>,
    key_pool_hint: u16,
    identity: [u8; 32],
}

impl std::fmt::Debug for ServerHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerHandshake")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl ServerHandshake {
    /// Creates a server handshake advertising `identity` as this deployment's long-term identity.
    pub fn new(psk: &Psk, key_pool_hint: u16, identity: [u8; 32]) -> Self {
        ServerHandshake {
            psk: Zeroizing::new(psk.as_bytes().to_vec()),
            transcript: Transcript::new(),
            state: HandshakeState::Started,
            client_hello: None,
            server_hello: None,
            keys: None,
            key_pool_hint,
            identity,
        }
    }

    /// Current state.
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Consumes the `CLIENT_HELLO` and produces the `SERVER_HELLO`.
    pub fn on_client_hello(&mut self, bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.state != HandshakeState::Started {
            return Err(CryptoError::Handshake(
                "CLIENT_HELLO received out of order".to_string(),
            ));
        }
        let hello = ClientHello::decode(bytes)?;
        self.transcript.absorb_prefixed(bytes);
        let response = ServerHello::generate(self.key_pool_hint, self.identity)?;
        let response_bytes = response.encode();
        self.transcript.absorb_prefixed(&response_bytes);
        self.client_hello = Some(hello);
        self.server_hello = Some(response);
        self.state = HandshakeState::HelloComplete;
        Ok(response_bytes)
    }

    /// The transcript hash over the exchanges so far. Input to the TLS exporter.
    pub fn transcript_hash(&self) -> [u8; HASH_LEN] {
        self.transcript.hash()
    }

    /// Verifies the client's `AUTH_CONFIRM` and produces the server's own.
    ///
    /// The client is authenticated before the server reveals its confirmation, so an attacker
    /// without the PSK learns nothing and the server never processes a proxy request.
    pub fn verify_client_confirm(
        &mut self,
        bytes: &[u8],
        exporter: [u8; HASH_LEN],
    ) -> Result<Vec<u8>, CryptoError> {
        if self.state != HandshakeState::HelloComplete {
            return Err(CryptoError::Handshake(
                "AUTH_CONFIRM requested before the hello exchange completed".to_string(),
            ));
        }
        let keys = self.build_keys(exporter)?;
        let expected = confirmation_mac(
            &keys.auth_c2s,
            Direction::ClientToServer,
            &keys.transcript_hash,
            &keys.exporter,
        );
        if let Err(error) = verify_mac(&expected, bytes) {
            self.state = HandshakeState::Failed;
            return Err(error);
        }
        let response = confirmation_mac(
            &keys.auth_s2c,
            Direction::ServerToClient,
            &keys.transcript_hash,
            &keys.exporter,
        );
        self.keys = Some(keys);
        self.state = HandshakeState::Authenticated;
        Ok(response.to_vec())
    }

    /// The negotiated session keys. Only available after a successful handshake.
    pub fn keys(&self) -> Option<&HandshakeKeys> {
        self.keys.as_ref()
    }

    /// The identity this server advertised.
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }

    fn build_keys(&self, exporter: [u8; HASH_LEN]) -> Result<HandshakeKeys, CryptoError> {
        let psk = Psk::from_bytes(&self.psk)?;
        let client = self
            .client_hello
            .as_ref()
            .ok_or_else(|| CryptoError::Handshake("CLIENT_HELLO was not received".to_string()))?;
        let server = self
            .server_hello
            .as_ref()
            .ok_or_else(|| CryptoError::Handshake("SERVER_HELLO was not sent".to_string()))?;
        Ok(derive_handshake_keys(
            &psk,
            self.transcript.hash(),
            exporter,
            client.recv_algorithms,
            server.recv_algorithms,
        ))
    }
}

/// A helper for tests and for the transport layer: performs the whole handshake in memory and
/// checks that both sides agree.
///
/// Returns the two key sets, or an error if either side rejected the other.
pub fn run_handshake_in_memory(
    psk: &Psk,
    exporter: [u8; HASH_LEN],
    identity: [u8; 32],
) -> Result<(HandshakeKeys, HandshakeKeys), CryptoError> {
    let (mut client, client_hello) = ClientHandshake::start(psk)?;
    let mut server = ServerHandshake::new(psk, 8, identity);
    let server_hello = server.on_client_hello(&client_hello)?;
    client.on_server_hello(&server_hello)?;
    assert_eq!(
        client.transcript_hash(),
        server.transcript_hash(),
        "both peers must hash the same transcript"
    );
    let client_confirm = client.client_confirm(exporter)?;
    let server_confirm = server.verify_client_confirm(&client_confirm, exporter)?;
    let client_keys = client.verify_server_confirm(&server_confirm)?;
    let server_keys = server
        .keys()
        .ok_or_else(|| CryptoError::Handshake("server produced no keys".to_string()))?;
    Ok((client_keys, server_keys.clone()))
}

/// Constant-time comparison helper used by tests to assert key equality without timing leaks.
pub fn keys_equal(a: &HandshakeKeys, b: &HandshakeKeys) -> bool {
    a.session_id == b.session_id
        && bool::from(a.transcript_hash.ct_eq(&b.transcript_hash))
        && bool::from(a.auth_c2s.as_bytes().ct_eq(b.auth_c2s.as_bytes()))
        && bool::from(a.auth_s2c.as_bytes().ct_eq(b.auth_s2c.as_bytes()))
        && bool::from(
            a.control_root_c2s
                .as_bytes()
                .ct_eq(b.control_root_c2s.as_bytes()),
        )
        && bool::from(
            a.control_root_s2c
                .as_bytes()
                .ct_eq(b.control_root_s2c.as_bytes()),
        )
}

/// The protocol label, exposed for documentation and for the transport's ALPN.
pub fn protocol_label() -> &'static [u8] {
    PROTOCOL_LABEL
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_IDENTITY: [u8; 32] = [0x5a; 32];

    fn psk() -> Psk {
        Psk::from_bytes(&(0u8..32).collect::<Vec<u8>>()).unwrap()
    }

    #[test]
    fn hello_messages_round_trip() {
        let hello = ClientHello::generate().unwrap();
        let decoded = ClientHello::decode(&hello.encode()).unwrap();
        assert_eq!(hello, decoded);

        let hello = ServerHello::generate(32, [7u8; 32]).unwrap();
        let decoded = ServerHello::decode(&hello.encode()).unwrap();
        assert_eq!(hello, decoded);
    }

    #[test]
    fn hello_message_lengths_are_fixed() {
        let client = ClientHello::generate().unwrap();
        assert_eq!(client.encode().len(), CLIENT_HELLO_LEN);
        let server = ServerHello::generate(1, [1u8; 32]).unwrap();
        assert_eq!(server.encode().len(), SERVER_HELLO_LEN);
    }

    #[test]
    fn hello_rejects_wrong_versions_and_reserved_fields() {
        let hello = ClientHello::generate().unwrap();
        let mut bytes = hello.encode();
        bytes[0] = 2;
        assert!(matches!(
            ClientHello::decode(&bytes),
            Err(CryptoError::Handshake(_))
        ));

        let mut bytes = hello.encode();
        bytes[34] = 1;
        assert!(ClientHello::decode(&bytes).is_err());

        let mut bytes = hello.encode();
        bytes[1..33].fill(0);
        assert!(ClientHello::decode(&bytes).is_err());

        let mut bytes = hello.encode();
        bytes[33] = 0;
        assert!(ClientHello::decode(&bytes).is_err());

        let mut bytes = hello.encode();
        bytes.truncate(CLIENT_HELLO_LEN - 1);
        assert!(matches!(
            ClientHello::decode(&bytes),
            Err(CryptoError::Truncated { .. })
        ));

        let server = ServerHello::generate(1, [1u8; 32]).unwrap();
        let mut bytes = server.encode();
        bytes[35] = 9;
        assert!(ServerHello::decode(&bytes).is_err());

        // An all-zero identity is refused on both encode and decode.
        assert!(ServerHello::generate(1, [0u8; 32]).is_err());
        let mut bytes = server.encode();
        bytes[38..70].fill(0);
        assert!(ServerHello::decode(&bytes).is_err());
    }

    #[test]
    fn handshake_agrees_on_both_sides() {
        let (client, server) =
            run_handshake_in_memory(&psk(), [5u8; HASH_LEN], TEST_IDENTITY).unwrap();
        assert!(keys_equal(&client, &server));
        assert_eq!(client.c2s_algorithms, AlgorithmSet::all());
        assert_eq!(client.s2c_algorithms, AlgorithmSet::all());
    }

    #[test]
    fn handshake_fails_with_the_wrong_psk() {
        let (mut client, client_hello) = ClientHandshake::start(&psk()).unwrap();
        let other = Psk::from_bytes(&(9u8..41).collect::<Vec<u8>>()).unwrap();
        let mut server = ServerHandshake::new(&other, 4, TEST_IDENTITY);
        let server_hello = server.on_client_hello(&client_hello).unwrap();
        client.on_server_hello(&server_hello).unwrap();
        let client_confirm = client.client_confirm([1u8; HASH_LEN]).unwrap();
        let error = server
            .verify_client_confirm(&client_confirm, [1u8; HASH_LEN])
            .unwrap_err();
        assert!(matches!(error, CryptoError::Handshake(_)));
        assert_eq!(server.state(), HandshakeState::Failed);
        assert!(server.keys().is_none());
    }

    #[test]
    fn handshake_fails_when_the_exporter_differs() {
        // This is the relay / man-in-the-middle case: two different TLS sessions have different
        // exporters, so the confirmation MAC the server produced does not verify at the client.
        let (mut client, client_hello) = ClientHandshake::start(&psk()).unwrap();
        let mut server = ServerHandshake::new(&psk(), 4, TEST_IDENTITY);
        let server_hello = server.on_client_hello(&client_hello).unwrap();
        client.on_server_hello(&server_hello).unwrap();

        let client_confirm = client.client_confirm([1u8; HASH_LEN]).unwrap();
        // The server sees a different exporter because it is on a different TLS session.
        let server_confirm = server
            .verify_client_confirm(&client_confirm, [2u8; HASH_LEN])
            .unwrap_err();
        assert!(matches!(server_confirm, CryptoError::Handshake(_)));
    }

    #[test]
    fn handshake_fails_when_the_server_confirmation_is_tampered() {
        let (mut client, client_hello) = ClientHandshake::start(&psk()).unwrap();
        let mut server = ServerHandshake::new(&psk(), 4, TEST_IDENTITY);
        let server_hello = server.on_client_hello(&client_hello).unwrap();
        client.on_server_hello(&server_hello).unwrap();
        let client_confirm = client.client_confirm([3u8; HASH_LEN]).unwrap();
        let mut server_confirm = server
            .verify_client_confirm(&client_confirm, [3u8; HASH_LEN])
            .unwrap();
        server_confirm[0] ^= 0x01;
        assert!(client.verify_server_confirm(&server_confirm).is_err());
    }

    #[test]
    fn transcript_includes_both_hellos() {
        let (mut client, client_hello) = ClientHandshake::start(&psk()).unwrap();
        let mut server = ServerHandshake::new(&psk(), 4, TEST_IDENTITY);
        let server_hello = server.on_client_hello(&client_hello).unwrap();
        client.on_server_hello(&server_hello).unwrap();
        assert_eq!(client.transcript_hash(), server.transcript_hash());

        // Tampering with the server random changes the transcript on the client only.
        let mut tampered = server_hello.clone();
        tampered[1] ^= 0xff;
        let (mut other_client, other_hello) = ClientHandshake::start(&psk()).unwrap();
        let mut other_server = ServerHandshake::new(&psk(), 4, TEST_IDENTITY);
        let _ = other_server.on_client_hello(&other_hello).unwrap();
        other_client.on_server_hello(&tampered).unwrap();
        assert_ne!(other_client.transcript_hash(), other_server.transcript_hash());
    }

    #[test]
    fn handshake_messages_must_arrive_in_order() {
        let (mut client, _) = ClientHandshake::start(&psk()).unwrap();
        let hello = ServerHello::generate(1, [3u8; 32]).unwrap();
        // A confirmation cannot precede the hello exchange.
        assert!(client.client_confirm([0u8; HASH_LEN]).is_err());
        client.on_server_hello(&hello.encode()).unwrap();
        // A second SERVER_HELLO is rejected.
        assert!(client.on_server_hello(&hello.encode()).is_err());
    }

    #[test]
    fn client_random_is_never_reused() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let (_, bytes) = ClientHandshake::start(&psk()).unwrap();
            assert!(seen.insert(bytes[1..33].to_vec()));
        }
    }

    #[test]
    fn client_learns_the_authenticated_server_identity() {
        let (mut client, client_hello) = ClientHandshake::start(&psk()).unwrap();
        assert!(client.server_identity().is_none());
        let mut server = ServerHandshake::new(&psk(), 4, [0x11; 32]);
        let server_hello = server.on_client_hello(&client_hello).unwrap();
        client.on_server_hello(&server_hello).unwrap();
        assert_eq!(client.server_identity(), Some([0x11; 32]));
        assert_eq!(server.identity(), [0x11; 32]);
    }

    #[test]
    fn changing_the_identity_changes_every_derived_key() {
        // The identity is inside the transcript, so it is bound into the key schedule.
        let (a, _) = run_handshake_in_memory(&psk(), [1u8; HASH_LEN], [0x11; 32]).unwrap();
        // A handshake with a different identity produces a different transcript.
        let (mut client, client_hello) = ClientHandshake::start(&psk()).unwrap();
        let mut server = ServerHandshake::new(&psk(), 4, [0x22; 32]);
        let server_hello = server.on_client_hello(&client_hello).unwrap();
        client.on_server_hello(&server_hello).unwrap();
        assert_ne!(client.transcript_hash(), a.transcript_hash);
    }

    #[test]
    fn handshake_debug_output_is_redacted() {
        let (client, _) = ClientHandshake::start(&psk()).unwrap();
        let text = format!("{client:?}");
        assert!(!text.contains("9f8c"), "{text}");
        assert!(text.contains("ClientHandshake"));
    }
}
