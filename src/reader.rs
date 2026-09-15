//! Positional reading of ELF byte sources.
//!
//! [`ReadAt`] reads bytes at an absolute offset without a shared cursor. It
//! supports in-memory slices, owned vectors, and, with the `std` feature,
//! files. Every multi-byte helper takes an [`Endian`] because ELF records its
//! byte order at run time.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::ident::Endian;

/// Reads bytes from an ELF source at absolute offsets.
///
/// Implement this trait to parse ELF structures from a custom source, such as
/// foreign-process memory. An implementation can return fewer bytes than the
/// buffer holds. The default helpers repeat reads when they need an exact
/// range.
pub trait ReadAt {
    /// Reads bytes at `offset` into `buf`.
    ///
    /// Returns the number of bytes read.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the source fails.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Returns the total size of the source when it is known.
    fn size(&self) -> Option<u64> {
        None
    }

    /// Reads exactly enough bytes to fill `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the source fails or ends before the buffer fills.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let expected = buf.len();
        let mut total = 0usize;
        while total < expected {
            let current = offset
                .checked_add(total as u64)
                .ok_or_else(|| Error::offset_out_of_bounds(offset, expected as u64))?;
            let count = self.read_at(current, &mut buf[total..])?;
            if count == 0 {
                return Err(Error::buffer_too_small(expected, total));
            }
            if count > expected - total {
                return Err(Error::generic(
                    "ReadAt::read_at reported more bytes than the supplied buffer",
                ));
            }
            total += count;
        }
        Ok(())
    }

    /// Reads a `u16` at `offset` in `endian` byte order.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the source cannot supply two bytes.
    fn read_u16_at(&self, offset: u64, endian: Endian) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.read_exact_at(offset, &mut buf)?;
        Ok(endian.u16(buf))
    }

    /// Reads a `u32` at `offset` in `endian` byte order.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the source cannot supply four bytes.
    fn read_u32_at(&self, offset: u64, endian: Endian) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read_exact_at(offset, &mut buf)?;
        Ok(endian.u32(buf))
    }

    /// Reads a `u64` at `offset` in `endian` byte order.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the source cannot supply eight bytes.
    fn read_u64_at(&self, offset: u64, endian: Endian) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.read_exact_at(offset, &mut buf)?;
        Ok(endian.u64(buf))
    }

    /// Reads an `i32` at `offset` in `endian` byte order.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the source cannot supply four bytes.
    fn read_i32_at(&self, offset: u64, endian: Endian) -> Result<i32> {
        let mut buf = [0u8; 4];
        self.read_exact_at(offset, &mut buf)?;
        Ok(endian.i32(buf))
    }

    /// Reads an `i64` at `offset` in `endian` byte order.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the source cannot supply eight bytes.
    fn read_i64_at(&self, offset: u64, endian: Endian) -> Result<i64> {
        let mut buf = [0u8; 8];
        self.read_exact_at(offset, &mut buf)?;
        Ok(endian.i64(buf))
    }

    /// Reads `len` bytes at `offset` into an owned vector.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the allocation fails or the source ends early.
    fn read_bytes_at(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.try_reserve_exact(len)
            .map_err(|_| Error::generic("reader request is too large to allocate"))?;
        buf.resize(len, 0);
        self.read_exact_at(offset, &mut buf)?;
        Ok(buf)
    }
}

/// A positional reader over a borrowed byte slice.
#[derive(Debug, Clone, Copy)]
pub struct SliceReader<'a> {
    data: &'a [u8],
}

impl<'a> SliceReader<'a> {
    /// Creates a reader over `data`.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Returns the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.data
    }
}

impl ReadAt for SliceReader<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let Ok(start) = usize::try_from(offset) else {
            return Ok(0);
        };
        let Some(available) = self.data.get(start..) else {
            return Ok(0);
        };
        let count = available.len().min(buf.len());
        buf[..count].copy_from_slice(&available[..count]);
        Ok(count)
    }

    fn size(&self) -> Option<u64> {
        Some(self.data.len() as u64)
    }
}

/// A positional reader that owns its byte vector.
#[derive(Debug, Clone)]
pub struct VecReader {
    data: Vec<u8>,
}

impl VecReader {
    /// Creates a reader that owns `data`.
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Returns the underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consumes the reader and returns the owned bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

impl ReadAt for VecReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        SliceReader::new(&self.data).read_at(offset, buf)
    }

    fn size(&self) -> Option<u64> {
        Some(self.data.len() as u64)
    }
}

#[cfg(feature = "std")]
pub use file::FileReader;

#[cfg(feature = "std")]
mod file {
    use std::cell::RefCell;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};
    use std::path::Path;

    use crate::error::Result;

    use super::ReadAt;

    /// A positional reader over a [`std::fs::File`].
    ///
    /// The reader seeks the file for each read. It uses interior mutability and
    /// is intended for single-threaded access.
    #[derive(Debug)]
    pub struct FileReader {
        file: RefCell<File>,
        size: u64,
    }

    impl FileReader {
        /// Wraps an open file.
        ///
        /// # Errors
        ///
        /// Returns an error when the file length cannot be determined.
        pub fn new(file: File) -> Result<Self> {
            let size = file.metadata()?.len();
            Ok(Self {
                file: RefCell::new(file),
                size,
            })
        }

        /// Opens a file at `path` for positional reading.
        ///
        /// # Errors
        ///
        /// Returns an error when the file cannot be opened or measured.
        pub fn open(path: impl AsRef<Path>) -> Result<Self> {
            Self::new(File::open(path)?)
        }
    }

    impl ReadAt for FileReader {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
            let mut file = self.file.borrow_mut();
            file.seek(SeekFrom::Start(offset))?;
            Ok(file.read(buf)?)
        }

        fn size(&self) -> Option<u64> {
            Some(self.size)
        }
    }
}
