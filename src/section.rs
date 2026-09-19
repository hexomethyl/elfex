//! ELF section headers and sections.
//!
//! Sections form the link-time view of an ELF object. They are optional at run
//! time. This module parses section headers and resolves section names through
//! the section-name string table.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Result;
use crate::ident::{ElfClass, Endian};
use crate::reader::ReadAt;

/// The section type recorded in a section header's `sh_type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SectionType(pub u32);

impl SectionType {
    /// Inactive section header.
    pub const NULL: Self = Self(0);
    /// Program-defined contents.
    pub const PROGBITS: Self = Self(1);
    /// Symbol table.
    pub const SYMTAB: Self = Self(2);
    /// String table.
    pub const STRTAB: Self = Self(3);
    /// Relocation entries with explicit addends.
    pub const RELA: Self = Self(4);
    /// Symbol hash table.
    pub const HASH: Self = Self(5);
    /// Dynamic linking information.
    pub const DYNAMIC: Self = Self(6);
    /// Note information.
    pub const NOTE: Self = Self(7);
    /// Occupies no file space.
    pub const NOBITS: Self = Self(8);
    /// Relocation entries without explicit addends.
    pub const REL: Self = Self(9);
    /// Reserved, with unspecified semantics.
    pub const SHLIB: Self = Self(10);
    /// Dynamic linker symbol table.
    pub const DYNSYM: Self = Self(11);
    /// Array of constructors.
    pub const INIT_ARRAY: Self = Self(14);
    /// Array of destructors.
    pub const FINI_ARRAY: Self = Self(15);
    /// Array of pre-constructors.
    pub const PREINIT_ARRAY: Self = Self(16);
    /// Section group.
    pub const GROUP: Self = Self(17);
    /// Extended section indices for a symbol table.
    pub const SYMTAB_SHNDX: Self = Self(18);
    /// Packed relative relocation entries.
    pub const RELR: Self = Self(19);
    /// GNU-style symbol hash table.
    pub const GNU_HASH: Self = Self(0x6fff_fff6);
    /// GNU version definitions.
    pub const GNU_VERDEF: Self = Self(0x6fff_fffd);
    /// GNU version requirements.
    pub const GNU_VERNEED: Self = Self(0x6fff_fffe);
    /// GNU version symbol table.
    pub const GNU_VERSYM: Self = Self(0x6fff_ffff);

    /// Returns the raw `sh_type` value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// Section attribute flags from a section header's `sh_flags` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SectionFlags(pub u64);

impl SectionFlags {
    /// Writable during execution (`SHF_WRITE`).
    pub const WRITE: u64 = 1;
    /// Occupies memory during execution (`SHF_ALLOC`).
    pub const ALLOC: u64 = 2;
    /// Contains executable instructions (`SHF_EXECINSTR`).
    pub const EXECINSTR: u64 = 4;

    /// Returns the raw `sh_flags` value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Tests whether the section occupies memory during execution.
    #[must_use]
    pub const fn is_alloc(self) -> bool {
        self.0 & Self::ALLOC != 0
    }

    /// Tests whether the section is writable during execution.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        self.0 & Self::WRITE != 0
    }

    /// Tests whether the section contains executable instructions.
    #[must_use]
    pub const fn is_executable(self) -> bool {
        self.0 & Self::EXECINSTR != 0
    }
}

/// A parsed ELF section header with address fields widened to 64 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionHeader {
    /// The section name as a string-table offset.
    pub name_index: u32,
    /// The section type.
    pub r#type: SectionType,
    /// The section attribute flags.
    pub flags: SectionFlags,
    /// The virtual address of the section during execution.
    pub addr: u64,
    /// The file offset of the section bytes.
    pub offset: u64,
    /// The section size in bytes.
    pub size: u64,
    /// A section-type-specific link to another section.
    pub link: u32,
    /// Section-type-specific extra information.
    pub info: u32,
    /// The required alignment of the section.
    pub addralign: u64,
    /// The size of one fixed-size entry, or zero.
    pub entsize: u64,
}

impl SectionHeader {
    /// Returns the serialized size of a section header for `class`.
    #[must_use]
    pub const fn size(class: ElfClass) -> u64 {
        match class {
            ElfClass::Elf32 => 40,
            ElfClass::Elf64 => 64,
        }
    }

    /// Parses one section header at `offset`.
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
                name_index: reader.read_u32_at(offset, endian)?,
                r#type: SectionType(reader.read_u32_at(offset + 4, endian)?),
                flags: SectionFlags(reader.read_u64_at(offset + 8, endian)?),
                addr: reader.read_u64_at(offset + 16, endian)?,
                offset: reader.read_u64_at(offset + 24, endian)?,
                size: reader.read_u64_at(offset + 32, endian)?,
                link: reader.read_u32_at(offset + 40, endian)?,
                info: reader.read_u32_at(offset + 44, endian)?,
                addralign: reader.read_u64_at(offset + 48, endian)?,
                entsize: reader.read_u64_at(offset + 56, endian)?,
            }),
            ElfClass::Elf32 => Ok(Self {
                name_index: reader.read_u32_at(offset, endian)?,
                r#type: SectionType(reader.read_u32_at(offset + 4, endian)?),
                flags: SectionFlags(u64::from(reader.read_u32_at(offset + 8, endian)?)),
                addr: u64::from(reader.read_u32_at(offset + 12, endian)?),
                offset: u64::from(reader.read_u32_at(offset + 16, endian)?),
                size: u64::from(reader.read_u32_at(offset + 20, endian)?),
                link: reader.read_u32_at(offset + 24, endian)?,
                info: reader.read_u32_at(offset + 28, endian)?,
                addralign: u64::from(reader.read_u32_at(offset + 32, endian)?),
                entsize: u64::from(reader.read_u32_at(offset + 36, endian)?),
            }),
        }
    }

    /// Serializes the section header for `class` and appends it to `out`.
    pub fn write(&self, out: &mut Vec<u8>, endian: Endian, class: ElfClass) {
        match class {
            ElfClass::Elf64 => {
                out.extend_from_slice(&endian.u32_bytes(self.name_index));
                out.extend_from_slice(&endian.u32_bytes(self.r#type.0));
                out.extend_from_slice(&endian.u64_bytes(self.flags.0));
                out.extend_from_slice(&endian.u64_bytes(self.addr));
                out.extend_from_slice(&endian.u64_bytes(self.offset));
                out.extend_from_slice(&endian.u64_bytes(self.size));
                out.extend_from_slice(&endian.u32_bytes(self.link));
                out.extend_from_slice(&endian.u32_bytes(self.info));
                out.extend_from_slice(&endian.u64_bytes(self.addralign));
                out.extend_from_slice(&endian.u64_bytes(self.entsize));
            }
            ElfClass::Elf32 => {
                out.extend_from_slice(&endian.u32_bytes(self.name_index));
                out.extend_from_slice(&endian.u32_bytes(self.r#type.0));
                out.extend_from_slice(&endian.u32_bytes(crate::low32(self.flags.0)));
                out.extend_from_slice(&endian.u32_bytes(crate::low32(self.addr)));
                out.extend_from_slice(&endian.u32_bytes(crate::low32(self.offset)));
                out.extend_from_slice(&endian.u32_bytes(crate::low32(self.size)));
                out.extend_from_slice(&endian.u32_bytes(self.link));
                out.extend_from_slice(&endian.u32_bytes(self.info));
                out.extend_from_slice(&endian.u32_bytes(crate::low32(self.addralign)));
                out.extend_from_slice(&endian.u32_bytes(crate::low32(self.entsize)));
            }
        }
    }

    /// Tests whether the section occupies no file bytes.
    #[must_use]
    pub const fn is_nobits(&self) -> bool {
        self.r#type.0 == SectionType::NOBITS.0
    }
}

/// A section header paired with its resolved name and bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The section header.
    pub header: SectionHeader,
    /// The resolved section name.
    pub name: String,
    /// The section bytes, empty for a `NOBITS` section.
    pub data: Vec<u8>,
}

impl Section {
    /// Creates a section from a header, name, and bytes.
    #[must_use]
    pub const fn new(header: SectionHeader, name: String, data: Vec<u8>) -> Self {
        Self { header, name, data }
    }

    /// Returns the section attribute flags.
    #[must_use]
    pub const fn flags(&self) -> SectionFlags {
        self.header.flags
    }

    /// Returns the section type.
    #[must_use]
    pub const fn section_type(&self) -> SectionType {
        self.header.r#type
    }

    /// Tests whether `vaddr` falls within the section's memory range.
    #[must_use]
    pub const fn contains_vaddr(&self, vaddr: u64) -> bool {
        self.header.flags.is_alloc()
            && vaddr >= self.header.addr
            && vaddr < self.header.addr.saturating_add(self.header.size)
    }
}
