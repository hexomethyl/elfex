//! ELF string table access.
//!
//! An ELF string table is a byte block of NUL-terminated strings. A name is a
//! byte offset into the block. [`StringTable`] borrows the block and resolves
//! offsets to string slices.

/// A borrowed view over an ELF string table.
#[derive(Debug, Clone, Copy)]
pub struct StringTable<'a> {
    data: &'a [u8],
}

impl<'a> StringTable<'a> {
    /// Creates a string table view over `data`.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Returns the string at `offset`.
    ///
    /// Returns `None` when the offset is out of range or the string is not
    /// valid UTF-8.
    #[must_use]
    pub fn get(&self, offset: usize) -> Option<&'a str> {
        let tail = self.data.get(offset..)?;
        let end = tail
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(tail.len());
        core::str::from_utf8(&tail[..end]).ok()
    }

    /// Returns the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.data
    }
}
