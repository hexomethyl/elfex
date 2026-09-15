//! ELF program headers and loadable segments.
//!
//! A program header describes one segment of the runtime image. The loader
//! reads program headers to place the file in memory. [`Segment`] pairs a
//! header with the bytes that back it.

use alloc::vec::Vec;

use crate::error::Result;
use crate::ident::{ElfClass, Endian};
use crate::reader::ReadAt;

/// The segment type recorded in a program header's `p_type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SegmentType(pub u32);

impl SegmentType {
    /// Unused program header entry.
    pub const NULL: Self = Self(0);
    /// Loadable segment.
    pub const LOAD: Self = Self(1);
    /// Dynamic linking information.
    pub const DYNAMIC: Self = Self(2);
    /// Program interpreter path.
    pub const INTERP: Self = Self(3);
    /// Auxiliary note information.
    pub const NOTE: Self = Self(4);
    /// Reserved segment type.
    pub const SHLIB: Self = Self(5);
    /// The program header table itself.
    pub const PHDR: Self = Self(6);
    /// Thread-local storage template.
    pub const TLS: Self = Self(7);
    /// GNU exception-handling frame header.
    pub const GNU_EH_FRAME: Self = Self(0x6474_e550);
    /// GNU stack permission marker.
    pub const GNU_STACK: Self = Self(0x6474_e551);
    /// GNU read-only-after-relocation region.
    pub const GNU_RELRO: Self = Self(0x6474_e552);

    /// Returns the raw `p_type` value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}
/// Segment permission flags from a program header's `p_flags` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SegmentFlags(pub u32);

impl SegmentFlags {
    /// Execute permission (`PF_X`).
    pub const EXECUTE: u32 = 1;
    /// Write permission (`PF_W`).
    pub const WRITE: u32 = 2;
    /// Read permission (`PF_R`).
    pub const READ: u32 = 4;

    /// Returns the raw `p_flags` value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }

    /// Tests whether the segment permits instruction execution.
    #[must_use]
    pub const fn is_executable(self) -> bool {
        self.0 & Self::EXECUTE != 0
    }

    /// Tests whether the segment permits writes.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        self.0 & Self::WRITE != 0
    }

    /// Tests whether the segment permits reads.
    #[must_use]
    pub const fn is_readable(self) -> bool {
        self.0 & Self::READ != 0
    }
}

/// A parsed ELF program header with address fields widened to 64 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProgramHeader {
    /// The segment type.
    pub r#type: SegmentType,
    /// The segment permission flags.
    pub flags: SegmentFlags,
    /// The file offset of the segment bytes.
    pub offset: u64,
    /// The virtual address of the segment.
    pub vaddr: u64,
    /// The physical address of the segment.
    pub paddr: u64,
    /// The number of file bytes in the segment.
    pub filesz: u64,
    /// The number of memory bytes in the segment.
    pub memsz: u64,
    /// The required alignment of the segment.
    pub align: u64,
}

impl ProgramHeader {
    /// Returns the serialized size of a program header for `class`.
    #[must_use]
    pub const fn size(class: ElfClass) -> u64 {
        match class {
            ElfClass::Elf32 => 32,
            ElfClass::Elf64 => 56,
        }
    }

    /// Parses one program header at `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the source cannot supply the header.
    pub fn parse<R: ReadAt>(
        reader: &R,
        offset: u64,
        endian: Endian,
        class: ElfClass,
    ) -> Result<Self> {
        match class {
            ElfClass::Elf64 => Ok(Self {
                r#type: SegmentType(reader.read_u32_at(offset, endian)?),
                flags: SegmentFlags(reader.read_u32_at(offset + 4, endian)?),
                offset: reader.read_u64_at(offset + 8, endian)?,
                vaddr: reader.read_u64_at(offset + 16, endian)?,
                paddr: reader.read_u64_at(offset + 24, endian)?,
                filesz: reader.read_u64_at(offset + 32, endian)?,
                memsz: reader.read_u64_at(offset + 40, endian)?,
                align: reader.read_u64_at(offset + 48, endian)?,
            }),
            ElfClass::Elf32 => Ok(Self {
                r#type: SegmentType(reader.read_u32_at(offset, endian)?),
                offset: u64::from(reader.read_u32_at(offset + 4, endian)?),
                vaddr: u64::from(reader.read_u32_at(offset + 8, endian)?),
                paddr: u64::from(reader.read_u32_at(offset + 12, endian)?),
                filesz: u64::from(reader.read_u32_at(offset + 16, endian)?),
                memsz: u64::from(reader.read_u32_at(offset + 20, endian)?),
                flags: SegmentFlags(reader.read_u32_at(offset + 24, endian)?),
                align: u64::from(reader.read_u32_at(offset + 28, endian)?),
            }),
        }
    }

    /// Serializes the program header for `class` and appends it to `out`.
    pub fn write(&self, out: &mut Vec<u8>, endian: Endian, class: ElfClass) {
        match class {
            ElfClass::Elf64 => {
                out.extend_from_slice(&endian.u32_bytes(self.r#type.0));
                out.extend_from_slice(&endian.u32_bytes(self.flags.0));
                out.extend_from_slice(&endian.u64_bytes(self.offset));
                out.extend_from_slice(&endian.u64_bytes(self.vaddr));
                out.extend_from_slice(&endian.u64_bytes(self.paddr));
                out.extend_from_slice(&endian.u64_bytes(self.filesz));
                out.extend_from_slice(&endian.u64_bytes(self.memsz));
                out.extend_from_slice(&endian.u64_bytes(self.align));
            }
            ElfClass::Elf32 => {
                out.extend_from_slice(&endian.u32_bytes(self.r#type.0));
                out.extend_from_slice(&endian.u32_bytes(crate::low32(self.offset)));
                out.extend_from_slice(&endian.u32_bytes(crate::low32(self.vaddr)));
                out.extend_from_slice(&endian.u32_bytes(crate::low32(self.paddr)));
                out.extend_from_slice(&endian.u32_bytes(crate::low32(self.filesz)));
                out.extend_from_slice(&endian.u32_bytes(crate::low32(self.memsz)));
                out.extend_from_slice(&endian.u32_bytes(self.flags.0));
                out.extend_from_slice(&endian.u32_bytes(crate::low32(self.align)));
            }
        }
    }

    /// Tests whether the segment is loadable.
    #[must_use]
    pub const fn is_load(&self) -> bool {
        self.r#type.0 == SegmentType::LOAD.0
    }
}

/// A program header paired with the bytes it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// The segment's program header.
    pub header: ProgramHeader,
    /// The segment bytes, sized by the parse layout.
    pub data: Vec<u8>,
}

impl Segment {
    /// Creates a segment from a header and its bytes.
    #[must_use]
    pub const fn new(header: ProgramHeader, data: Vec<u8>) -> Self {
        Self { header, data }
    }

    /// Returns the segment permission flags.
    #[must_use]
    pub const fn flags(&self) -> SegmentFlags {
        self.header.flags
    }

    /// Returns the segment type.
    #[must_use]
    pub const fn segment_type(&self) -> SegmentType {
        self.header.r#type
    }

    /// Tests whether `vaddr` falls within the segment's memory range.
    #[must_use]
    pub const fn contains_vaddr(&self, vaddr: u64) -> bool {
        vaddr >= self.header.vaddr && vaddr < self.header.vaddr.saturating_add(self.header.memsz)
    }

    /// Returns up to `len` bytes starting at `vaddr` from the file-backed data.
    ///
    /// Returns `None` when `vaddr` is outside the segment or has no file bytes.
    #[must_use]
    pub fn data_at_vaddr(&self, vaddr: u64, len: usize) -> Option<&[u8]> {
        if !self.contains_vaddr(vaddr) {
            return None;
        }
        let start = usize::try_from(vaddr - self.header.vaddr).ok()?;
        let available = self.data.get(start..)?;
        Some(&available[..len.min(available.len())])
    }
}
