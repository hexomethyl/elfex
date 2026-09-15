//! ELF thread-local storage metadata.
//!
//! The `PT_TLS` program header describes the initialization image for
//! thread-local storage. [`TlsInfo`] captures that image without copying its
//! bytes.

use crate::program::ProgramHeader;

/// Thread-local storage layout derived from a `PT_TLS` segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsInfo {
    /// The virtual address of the initialization image.
    pub template_vaddr: u64,
    /// The number of initialized file bytes in the image.
    pub file_size: u64,
    /// The total size of the per-thread storage.
    pub mem_size: u64,
    /// The required alignment of the storage.
    pub align: u64,
}

impl TlsInfo {
    /// Builds thread-local storage metadata from a `PT_TLS` program header.
    #[must_use]
    pub const fn from_header(header: &ProgramHeader) -> Self {
        Self {
            template_vaddr: header.vaddr,
            file_size: header.filesz,
            mem_size: header.memsz,
            align: header.align,
        }
    }

    /// Returns the virtual address of the initialization image.
    #[must_use]
    pub const fn template_vaddr(&self) -> u64 {
        self.template_vaddr
    }

    /// Returns the number of initialized file bytes.
    #[must_use]
    pub const fn file_size(&self) -> u64 {
        self.file_size
    }

    /// Returns the total per-thread storage size.
    #[must_use]
    pub const fn mem_size(&self) -> u64 {
        self.mem_size
    }

    /// Returns the number of zero-filled bytes after the initialized image.
    #[must_use]
    pub const fn zero_fill_size(&self) -> u64 {
        self.mem_size.saturating_sub(self.file_size)
    }

    /// Returns the required alignment of the storage.
    #[must_use]
    pub const fn align(&self) -> u64 {
        self.align
    }
}
