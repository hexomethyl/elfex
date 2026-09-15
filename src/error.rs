//! Error types for ELF parsing, editing, and writing.
//!
//! Every recoverable failure returns an [`Error`]. An error carries an
//! [`ErrorKind`] and optional [`ErrorContext`]. The context records a file
//! offset, a virtual address, or a structure name to help locate the failure.

use alloc::string::String;
use core::fmt;

#[cfg(feature = "std")]
use std::io;

/// Result type alias for `elfex` operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Context about where an error occurred.
#[derive(Debug, Clone, Default)]
pub struct ErrorContext {
    /// File offset associated with the error.
    offset: Option<u64>,
    /// Virtual address associated with the error.
    vaddr: Option<u64>,
    /// Structure name associated with the error.
    structure: Option<String>,
}

impl ErrorContext {
    /// Records a file offset in the context.
    #[must_use]
    pub fn at_offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Records a virtual address in the context.
    #[must_use]
    pub fn at_vaddr(mut self, vaddr: u64) -> Self {
        self.vaddr = Some(vaddr);
        self
    }

    /// Records a structure name in the context.
    #[must_use]
    pub fn in_structure(mut self, name: impl Into<String>) -> Self {
        self.structure = Some(name.into());
        self
    }

    /// Returns the recorded file offset.
    #[must_use]
    pub const fn offset(&self) -> Option<u64> {
        self.offset
    }

    /// Returns the recorded virtual address.
    #[must_use]
    pub const fn vaddr(&self) -> Option<u64> {
        self.vaddr
    }

    /// Returns the recorded structure name.
    #[must_use]
    pub fn structure(&self) -> Option<&str> {
        self.structure.as_deref()
    }
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut separated = false;
        let mut write_part = |formatter: &mut fmt::Formatter<'_>, part: fmt::Arguments<'_>| {
            if separated {
                formatter.write_str(", ")?;
            }
            separated = true;
            formatter.write_fmt(part)
        };
        if let Some(structure) = &self.structure {
            write_part(formatter, format_args!("in {structure}"))?;
        }
        if let Some(offset) = self.offset {
            write_part(formatter, format_args!("at file offset {offset:#x}"))?;
        }
        if let Some(vaddr) = self.vaddr {
            write_part(formatter, format_args!("at virtual address {vaddr:#x}"))?;
        }
        Ok(())
    }
}

/// The kind of failure that occurred.
#[derive(Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    /// An input or output operation failed.
    #[cfg(feature = "std")]
    Io(io::Error),
    /// The ELF magic number was not `\x7fELF`.
    InvalidMagic,
    /// The `EI_CLASS` byte named an unknown class.
    InvalidClass(u8),
    /// The `EI_DATA` byte named an unknown data encoding.
    InvalidDataEncoding(u8),
    /// The `e_type` field named an unsupported object type.
    InvalidType(u16),
    /// The `e_machine` field named an unsupported machine.
    UnsupportedMachine(u16),
    /// A buffer was smaller than the required structure.
    BufferTooSmall {
        /// Number of bytes the structure requires.
        expected: usize,
        /// Number of bytes the buffer holds.
        actual: usize,
    },
    /// A section was malformed.
    InvalidSection(String),
    /// A file offset fell outside the readable range.
    OffsetOutOfBounds {
        /// The requested offset.
        offset: u64,
        /// The size of the readable range.
        size: u64,
    },
    /// A virtual address had no image mapping.
    InvalidVaddr(u64),
    /// A byte sequence was not valid UTF-8.
    InvalidUtf8,
    /// A failure with a free-form message.
    Generic(String),
}

/// A recoverable ELF error with optional location context.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    context: Option<ErrorContext>,
}

impl Error {
    /// Creates an error from a kind with no context.
    #[must_use]
    pub const fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            context: None,
        }
    }

    /// Attaches location context to the error.
    #[must_use]
    pub fn with_context(mut self, context: ErrorContext) -> Self {
        self.context = Some(context);
        self
    }

    /// Attaches a file offset to the error context.
    #[must_use]
    pub fn at_offset(mut self, offset: u64) -> Self {
        let context = self.context.take().unwrap_or_default();
        self.context = Some(context.at_offset(offset));
        self
    }

    /// Attaches a virtual address to the error context.
    #[must_use]
    pub fn at_vaddr(mut self, vaddr: u64) -> Self {
        let context = self.context.take().unwrap_or_default();
        self.context = Some(context.at_vaddr(vaddr));
        self
    }

    /// Attaches a structure name to the error context.
    #[must_use]
    pub fn in_structure(mut self, name: impl Into<String>) -> Self {
        let context = self.context.take().unwrap_or_default();
        self.context = Some(context.in_structure(name));
        self
    }

    /// Returns the error kind.
    #[must_use]
    pub const fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// Returns the location context when one is present.
    #[must_use]
    pub const fn context(&self) -> Option<&ErrorContext> {
        self.context.as_ref()
    }

    /// Creates an [`ErrorKind::InvalidMagic`] error.
    #[must_use]
    pub const fn invalid_magic() -> Self {
        Self::new(ErrorKind::InvalidMagic)
    }

    /// Creates an [`ErrorKind::InvalidClass`] error.
    #[must_use]
    pub const fn invalid_class(class: u8) -> Self {
        Self::new(ErrorKind::InvalidClass(class))
    }

    /// Creates an [`ErrorKind::InvalidDataEncoding`] error.
    #[must_use]
    pub const fn invalid_data_encoding(data: u8) -> Self {
        Self::new(ErrorKind::InvalidDataEncoding(data))
    }

    /// Creates an [`ErrorKind::InvalidType`] error.
    #[must_use]
    pub const fn invalid_type(object_type: u16) -> Self {
        Self::new(ErrorKind::InvalidType(object_type))
    }

    /// Creates an [`ErrorKind::UnsupportedMachine`] error.
    #[must_use]
    pub const fn unsupported_machine(machine: u16) -> Self {
        Self::new(ErrorKind::UnsupportedMachine(machine))
    }

    /// Creates an [`ErrorKind::BufferTooSmall`] error.
    #[must_use]
    pub const fn buffer_too_small(expected: usize, actual: usize) -> Self {
        Self::new(ErrorKind::BufferTooSmall { expected, actual })
    }

    /// Creates an [`ErrorKind::InvalidSection`] error.
    #[must_use]
    pub fn invalid_section(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidSection(message.into()))
    }

    /// Creates an [`ErrorKind::OffsetOutOfBounds`] error.
    #[must_use]
    pub const fn offset_out_of_bounds(offset: u64, size: u64) -> Self {
        Self::new(ErrorKind::OffsetOutOfBounds { offset, size })
    }

    /// Creates an [`ErrorKind::InvalidVaddr`] error.
    #[must_use]
    pub const fn invalid_vaddr(vaddr: u64) -> Self {
        Self::new(ErrorKind::InvalidVaddr(vaddr))
    }

    /// Creates an [`ErrorKind::InvalidUtf8`] error.
    #[must_use]
    pub const fn invalid_utf8() -> Self {
        Self::new(ErrorKind::InvalidUtf8)
    }

    /// Creates an [`ErrorKind::Generic`] error.
    #[must_use]
    pub fn generic(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Generic(message.into()))
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "std")]
            Self::Io(cause) => write!(formatter, "input or output error: {cause}"),
            Self::InvalidMagic => formatter.write_str("invalid ELF magic number"),
            Self::InvalidClass(class) => write!(formatter, "invalid ELF class {class:#x}"),
            Self::InvalidDataEncoding(data) => {
                write!(formatter, "invalid ELF data encoding {data:#x}")
            }
            Self::InvalidType(object_type) => {
                write!(formatter, "invalid ELF object type {object_type:#x}")
            }
            Self::UnsupportedMachine(machine) => {
                write!(formatter, "unsupported ELF machine {machine:#x}")
            }
            Self::BufferTooSmall { expected, actual } => write!(
                formatter,
                "buffer too small: expected {expected} bytes, found {actual}"
            ),
            Self::InvalidSection(message) => write!(formatter, "invalid section: {message}"),
            Self::OffsetOutOfBounds { offset, size } => write!(
                formatter,
                "offset {offset:#x} is out of bounds for size {size:#x}"
            ),
            Self::InvalidVaddr(vaddr) => {
                write!(formatter, "virtual address {vaddr:#x} is not in the image")
            }
            Self::InvalidUtf8 => formatter.write_str("invalid UTF-8 in ELF string"),
            Self::Generic(message) => formatter.write_str(message),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.kind)?;
        if let Some(context) = &self.context {
            write!(formatter, " ({context})")?;
        }
        Ok(())
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match &self.kind {
            #[cfg(feature = "std")]
            ErrorKind::Io(cause) => Some(cause),
            _ => None,
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind)
    }
}

#[cfg(feature = "std")]
impl From<io::Error> for Error {
    fn from(cause: io::Error) -> Self {
        Self::new(ErrorKind::Io(cause))
    }
}
