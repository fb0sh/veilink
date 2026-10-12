//! A minimal DNS stub server, used to prove where name resolution happens.
//!
//! It answers every A query with a configured address and records the names it was asked for, which
//! is what lets a test distinguish "the client resolved this name" from "the server did".

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use tokio::sync::oneshot;

/// A running DNS stub.
pub struct DnsStub {
    addr: SocketAddr,
    queries: Arc<Mutex<Vec<String>>>,
    shutdown: Option<oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
}

impl DnsStub {
    /// Starts a stub that answers every A query with `answer`.
    pub async fn start(answer: Ipv4Addr) -> std::io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        let queries = Arc::new(Mutex::new(Vec::new()));
        let task_queries = queries.clone();
        let (tx, mut rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    received = socket.recv_from(&mut buf) => {
                        let Ok((len, peer)) = received else { break };
                        let Some(name) = parse_question_name(&buf[..len]) else { continue };
                        if let Ok(mut list) = task_queries.lock() {
                            list.push(name.clone());
                        }
                        if let Some(response) = build_response(&buf[..len], answer) {
                            let _ = socket.send_to(&response, peer).await;
                        }
                    }
                }
            }
        });
        Ok(DnsStub {
            addr,
            queries,
            shutdown: Some(tx),
            handle,
        })
    }

    /// The stub's address, as `127.0.0.1:PORT`.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The names that were queried, lower-cased.
    pub fn queries(&self) -> Vec<String> {
        self.queries.lock().map(|q| q.clone()).unwrap_or_default()
    }

    /// Number of queries for `name`.
    pub fn count(&self, name: &str) -> usize {
        let name = name.to_ascii_lowercase();
        self.queries()
            .iter()
            .filter(|q| q.eq_ignore_ascii_case(&name))
            .count()
    }

    /// Stops the stub.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let handle = std::mem::replace(&mut self.handle, tokio::spawn(async {}));
        let _ = handle.await;
    }
}

impl Drop for DnsStub {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Parses the first question name from a DNS query.
fn parse_question_name(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 {
        return None;
    }
    let mut labels = Vec::new();
    let mut position = 12usize;
    loop {
        let &length = packet.get(position)?;
        if length == 0 {
            break;
        }
        // Compression pointers are not expected in a question.
        if length & 0xc0 != 0 {
            return None;
        }
        let start = position + 1;
        let end = start + length as usize;
        let label = packet.get(start..end)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        position = end;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// Builds a response with a single A record.
fn build_response(query: &[u8], answer: Ipv4Addr) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    // Header with QR=1, RD copied, RA=1 and one answer.
    let mut response = Vec::with_capacity(query.len() + 16);
    response.extend_from_slice(&query[0..2]); // transaction id
    response.extend_from_slice(&[0x81, 0x80]); // standard query response, recursion available
    response.extend_from_slice(&[0x00, 0x01]); // questions
    response.extend_from_slice(&[0x00, 0x01]); // answers
    response.extend_from_slice(&[0x00, 0x00]); // authority
    response.extend_from_slice(&[0x00, 0x00]); // additional

    // Question section: name, type, class.
    let mut position = 12usize;
    loop {
        let length = *query.get(position)? as usize;
        if length == 0 {
            response.extend_from_slice(&query[12..=position]);
            break;
        }
        if length & 0xc0 != 0 {
            return None;
        }
        position += 1 + length;
    }
    response.extend_from_slice(&[0x00, 0x01]); // type A
    response.extend_from_slice(&[0x00, 0x01]); // class IN

    // Answer: pointer to the question name.
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&[0x00, 0x01]); // type A
    response.extend_from_slice(&[0x00, 0x01]); // class IN
    response.extend_from_slice(&60u32.to_be_bytes()); // TTL
    response.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
    response.extend_from_slice(&answer.octets());
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_question_name() {
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(b"\x04test\x07example\x00");
        query.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(parse_question_name(&query).unwrap(), "test.example");
        assert!(parse_question_name(&[]).is_none());
    }

    #[tokio::test]
    async fn answers_and_records_queries() {
        let stub = DnsStub::start(Ipv4Addr::new(127, 0, 0, 1)).await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut query = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(b"\x05probe\x04test\x00");
        query.extend_from_slice(&[0, 1, 0, 1]);
        client.send_to(&query, stub.addr()).await.unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(len > 12);
        assert_eq!(stub.count("probe.test"), 1);
        assert_eq!(stub.queries(), vec!["probe.test".to_string()]);
        // The answer is the configured address.
        assert_eq!(&buf[len - 4..len], &[127, 0, 0, 1]);
        stub.stop().await;
    }
}
