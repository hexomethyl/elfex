//! The ELF file header and the header-only view.
//!
//! [`ElfHeader`] widens every address field to 64 bits so one type serves both
//! the 32-bit and 64-bit classes. [`ElfHeaders`] parses the file header and the
//! program header table without loading segment data.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::ident::{EI_NIDENT, ElfClass, ElfIdent};
use crate::program::ProgramHeader;
use crate::reader::{ReadAt, SliceReader};

/// The object file type recorded in the `e_type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfType {
    /// No file type.
    None,
    /// Relocatable file.
    Rel,
    /// Executable file.
    Exec,
    /// Shared object or position-independent executable.
    Dyn,
    /// Core file.
    Core,
    /// Another processor-specific or unknown type.
    Other(u16),
}

impl ElfType {
    /// Converts a raw `e_type` value.
    #[must_use]
    pub const fn from_u16(value: u16) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Rel,
            2 => Self::Exec,
            3 => Self::Dyn,
            4 => Self::Core,
            other => Self::Other(other),
        }
    }

    /// Returns the raw `e_type` value.
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        match self {
            Self::None => 0,
            Self::Rel => 1,
            Self::Exec => 2,
            Self::Dyn => 3,
            Self::Core => 4,
            Self::Other(value) => value,
        }
    }
}

/// The machine architecture recorded in the `e_machine` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Machine(pub u16);

impl Machine {
    /// No machine.
    pub const NONE: Self = Self(0);
    /// Intel 80386.
    pub const I386: Self = Self(3);
    /// ARM 32-bit.
    pub const ARM: Self = Self(40);
    /// AMD x86-64.
    pub const X86_64: Self = Self(62);
    /// ARM 64-bit.
    pub const AARCH64: Self = Self(183);
    /// RISC-V.
    pub const RISCV: Self = Self(243);

    /// Returns the raw `e_machine` value.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Returns a stable short name when the machine is recognized.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        match self.0 {
            3 => Some("i386"),
            40 => Some("arm"),
            62 => Some("x86-64"),
            183 => Some("aarch64"),
            243 => Some("riscv"),
            _ => None,
        }
    }
}

/// A parsed ELF file header with address fields widened to 64 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfHeader {
    /// The identification array.
    pub ident: ElfIdent,
    /// The object file type.
    pub r#type: ElfType,
    /// The machine architecture.
    pub machine: Machine,
    /// The object file version.
    pub version: u32,
    /// The entry-point virtual address.
    pub entry: u64,
    /// The program header table file offset.
    pub phoff: u64,
    /// The section header table file offset.
    pub shoff: u64,
    /// The processor-specific flags.
    pub flags: u32,
    /// The ELF header size in bytes.
    pub ehsize: u16,
    /// The size of one program header.
    pub phentsize: u16,
    /// The number of program headers.
    pub phnum: u16,
    /// The size of one section header.
    pub shentsize: u16,
    /// The number of section headers.
    pub shnum: u16,
    /// The section index of the section-name string table.
    pub shstrndx: u16,
}

impl ElfHeader {
    /// Returns the serialized size of an ELF header for `class`.
    #[must_use]
    pub const fn size(class: ElfClass) -> u64 {
        match class {
            ElfClass::Elf32 => 52,
            ElfClass::Elf64 => 64,
        }
    }

    /// Parses the ELF header that follows the already-parsed `ident`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the source cannot supply the header.
    pub fn parse<R: ReadAt>(reader: &R, ident: ElfIdent) -> Result<Self> {
        let endian = ident.data;
        let class = ident.class;
        let machine_raw = reader.read_u16_at(18, endian)?;
        let (entry, phoff, shoff, tail) = match class {
            ElfClass::Elf64 => (
                reader.read_u64_at(24, endian)?,
                reader.read_u64_at(32, endian)?,
                reader.read_u64_at(40, endian)?,
                48u64,
            ),
            ElfClass::Elf32 => (
                u64::from(reader.read_u32_at(24, endian)?),
                u64::from(reader.read_u32_at(28, endian)?),
                u64::from(reader.read_u32_at(32, endian)?),
                36u64,
            ),
        };
        Ok(Self {
            ident,
            r#type: ElfType::from_u16(reader.read_u16_at(16, endian)?),
            machine: Machine(machine_raw),
            version: reader.read_u32_at(20, endian)?,
            entry,
            phoff,
            shoff,
            flags: reader.read_u32_at(tail, endian)?,
            ehsize: reader.read_u16_at(tail + 4, endian)?,
            phentsize: reader.read_u16_at(tail + 6, endian)?,
            phnum: reader.read_u16_at(tail + 8, endian)?,
            shentsize: reader.read_u16_at(tail + 10, endian)?,
            shnum: reader.read_u16_at(tail + 12, endian)?,
            shstrndx: reader.read_u16_at(tail + 14, endian)?,
        })
    }

    /// Serializes the ELF header and appends it to `out`.
    pub fn write(&self, out: &mut Vec<u8>) {
        let endian = self.ident.data;
        let class = self.ident.class;
        out.extend_from_slice(&self.ident.to_bytes());
        out.extend_from_slice(&endian.u16_bytes(self.r#type.to_u16()));
        out.extend_from_slice(&endian.u16_bytes(self.machine.0));
        out.extend_from_slice(&endian.u32_bytes(self.version));
        match class {
            ElfClass::Elf64 => {
                out.extend_from_slice(&endian.u64_bytes(self.entry));
                out.extend_from_slice(&endian.u64_bytes(self.phoff));
                out.extend_from_slice(&endian.u64_bytes(self.shoff));
            }
            ElfClass::Elf32 => {
                out.extend_from_slice(&endian.u32_bytes(crate::low32(self.entry)));
                out.extend_from_slice(&endian.u32_bytes(crate::low32(self.phoff)));
                out.extend_from_slice(&endian.u32_bytes(crate::low32(self.shoff)));
            }
        }
        out.extend_from_slice(&endian.u32_bytes(self.flags));
        out.extend_from_slice(&endian.u16_bytes(self.ehsize));
        out.extend_from_slice(&endian.u16_bytes(self.phentsize));
        out.extend_from_slice(&endian.u16_bytes(self.phnum));
        out.extend_from_slice(&endian.u16_bytes(self.shentsize));
        out.extend_from_slice(&endian.u16_bytes(self.shnum));
        out.extend_from_slice(&endian.u16_bytes(self.shstrndx));
    }
}

/// The ELF identity, file header, and parsed program headers.
///
/// This view reads structural headers without loading segment or section data.
/// It is the header-only counterpart to a full [`crate::ElfImage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfHeaders {
    /// The identification array.
    pub ident: ElfIdent,
    /// The file header.
    pub header: ElfHeader,
    /// The parsed program header table.
    pub program_headers: Vec<ProgramHeader>,
}

impl ElfHeaders {
    /// Parses the ELF identity, header, and program header table from `reader`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when a structural header cannot be read.
    pub fn read_from<R: ReadAt>(reader: &R) -> Result<Self> {
        let mut ident_bytes = [0u8; EI_NIDENT];
        reader.read_exact_at(0, &mut ident_bytes)?;
        let ident = ElfIdent::parse(&ident_bytes)?;
        let header = ElfHeader::parse(reader, ident)?;
        let endian = ident.data;
        let class = ident.class;
        let entry_size = ProgramHeader::size(class);
        let mut program_headers = Vec::new();
        for index in 0..u64::from(header.phnum) {
            let offset = header
                .phoff
                .checked_add(index * entry_size)
                .ok_or_else(|| Error::generic("program header table offset overflows"))?;
            program_headers.push(ProgramHeader::parse(reader, offset, endian, class)?);
        }
        Ok(Self {
            ident,
            header,
            program_headers,
        })
    }

    /// Parses the ELF identity, header, and program header table from `data`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when a structural header cannot be read.
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        Self::read_from(&SliceReader::new(data))
    }
}
