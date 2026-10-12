//! Structured configuration diagnostics.
//!
//! Validation never fails on the first problem: it collects every issue it can find so that
//! `veilink check` can report the complete list with the exact field and rule that is wrong.

use std::fmt;

/// A single validation problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// Dotted path of the offending configuration field, e.g. `whitelist[2]`.
    pub field: String,
    /// Human-readable explanation.
    pub message: String,
}

impl Diagnostic {
    /// Creates a diagnostic for `field`.
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Diagnostic {
            field: field.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.field.is_empty() {
            f.write_str(&self.message)
        } else {
            write!(f, "{}: {}", self.field, self.message)
        }
    }
}

/// An ordered collection of validation problems.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Diagnostics {
    items: Vec<Diagnostic>,
}

impl Diagnostics {
    /// An empty collection.
    pub fn new() -> Self {
        Diagnostics::default()
    }

    /// Records a problem.
    pub fn push(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.items.push(Diagnostic::new(field, message));
    }

    /// Number of recorded problems.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True when no problem was recorded.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The recorded problems.
    pub fn items(&self) -> &[Diagnostic] {
        &self.items
    }

    /// Converts into an error when at least one problem was recorded.
    pub fn into_result(self) -> Result<(), Diagnostics> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(self)
        }
    }
}

impl From<Diagnostic> for Diagnostics {
    fn from(value: Diagnostic) -> Self {
        Diagnostics { items: vec![value] }
    }
}

impl FromIterator<Diagnostic> for Diagnostics {
    fn from_iter<T: IntoIterator<Item = Diagnostic>>(iter: T) -> Self {
        Diagnostics {
            items: iter.into_iter().collect(),
        }
    }
}

impl IntoIterator for Diagnostics {
    type Item = Diagnostic;
    type IntoIter = std::vec::IntoIter<Diagnostic>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

impl fmt::Display for Diagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.items.len() {
            0 => Ok(()),
            1 => write!(f, "{}", self.items[0]),
            n => {
                writeln!(f, "{n} configuration problems:")?;
                for (idx, item) in self.items.iter().enumerate() {
                    if idx + 1 == n {
                        write!(f, "  - {item}")?;
                    } else {
                        writeln!(f, "  - {item}")?;
                    }
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for Diagnostics {}
