//! ELF relocation tables and dynamic relocation classification.
//!
//! Relocations live in `SHT_REL` or `SHT_RELA` sections. [`RelocationSection`]
//! decodes either form. [`relocation_kind`] and [`relocation_width`] classify
//! the common x86 dynamic relocation types for a generic consumer.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::header::Machine;
use crate::ident::{ElfClass, Endian};
use crate::parse_utils::{array4, array8};

/// One parsed relocation entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelocationEntry {
    /// The virtual address of the storage to relocate.
    pub offset: u64,
    /// The relocation's symbol index, zero when unused.
    pub symbol: u32,
    /// The processor-specific relocation type.
    pub r_type: u32,
    /// The explicit addend, present only in `RELA` forms.
    pub addend: Option<i64>,
}

impl RelocationEntry {
    /// Returns the virtual address of the relocated storage.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the relocation's symbol index.
    #[must_use]
    pub const fn symbol(&self) -> u32 {
        self.symbol
    }

    /// Returns the raw relocation type.
    #[must_use]
    pub const fn r_type(&self) -> u32 {
        self.r_type
    }

    /// Returns the explicit addend for `RELA` forms.
    #[must_use]
    pub const fn addend(&self) -> Option<i64> {
        self.addend
    }
}

/// One parsed `SHT_REL` or `SHT_RELA` section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelocationSection {
    /// The relocation entries in table order.
    pub entries: Vec<RelocationEntry>,
    /// Whether the table uses the `RELA` form with explicit addends.
    pub is_rela: bool,
}

impl RelocationSection {
    /// Parses a relocation table from its section bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the table is not a whole number of entries.
    pub fn parse(data: &[u8], is_rela: bool, endian: Endian, class: ElfClass) -> Result<Self> {
        let entry_size = match (class, is_rela) {
            (ElfClass::Elf64, false) => 16usize,
            (ElfClass::Elf64, true) => 24,
            (ElfClass::Elf32, false) => 8,
            (ElfClass::Elf32, true) => 12,
        };
        if !data.len().is_multiple_of(entry_size) {
            return Err(Error::invalid_section(
                "relocation table is not a whole number of entries",
            ));
        }
        let mut entries = Vec::with_capacity(data.len() / entry_size);
        for entry in data.chunks_exact(entry_size) {
            let (offset, info) = match class {
                ElfClass::Elf64 => (endian.u64(array8(entry, 0)?), endian.u64(array8(entry, 8)?)),
                ElfClass::Elf32 => (
                    u64::from(endian.u32(array4(entry, 0)?)),
                    u64::from(endian.u32(array4(entry, 4)?)),
                ),
            };
            let addend = if is_rela {
                Some(match class {
                    ElfClass::Elf64 => endian.i64(array8(entry, 16)?),
                    ElfClass::Elf32 => i64::from(endian.i32(array4(entry, 8)?)),
                })
            } else {
                None
            };
            entries.push(RelocationEntry {
                offset,
                symbol: split_symbol(class, info),
                r_type: split_type(class, info),
                addend,
            });
        }
        Ok(Self { entries, is_rela })
    }

    /// Returns the relocation entries in table order.
    #[must_use]
    pub fn entries(&self) -> &[RelocationEntry] {
        &self.entries
    }

    /// Tests whether the table uses the `RELA` form.
    #[must_use]
    pub const fn is_rela(&self) -> bool {
        self.is_rela
    }
}

const fn split_symbol(class: ElfClass, info: u64) -> u32 {
    match class {
        ElfClass::Elf64 => crate::low32(info >> 32),
        ElfClass::Elf32 => crate::low32(info >> 8),
    }
}

const fn split_type(class: ElfClass, info: u64) -> u32 {
    match class {
        ElfClass::Elf64 => crate::low32(info & 0xffff_ffff),
        ElfClass::Elf32 => crate::low32(info & 0xff),
    }
}

/// The common purpose of one relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelocKind {
    /// Adds the load-bias change to a stored pointer.
    Relative,
    /// Resolves a global symbol address into data storage.
    GlobalData,
    /// Resolves a global symbol address into a PLT slot.
    JumpSlot,
    /// Stores an absolute address.
    Absolute,
    /// Copies a dynamic symbol's initial bytes.
    Copy,
    /// Accesses thread-local storage.
    Tls,
    /// Has no common interpretation.
    Other,
}

/// Classifies a dynamic relocation type for `machine`.
///
/// The match recognizes the x86-64 and i386 dynamic relocation types. Other
/// machines fall back to [`RelocKind::Other`].
#[must_use]
pub const fn relocation_kind(machine: Machine, r_type: u32) -> RelocKind {
    match machine.value() {
        62 => match r_type {
            8 => RelocKind::Relative,
            6 => RelocKind::GlobalData,
            7 => RelocKind::JumpSlot,
            1 => RelocKind::Absolute,
            5 => RelocKind::Copy,
            16..=18 => RelocKind::Tls,
            _ => RelocKind::Other,
        },
        3 => match r_type {
            8 => RelocKind::Relative,
            6 => RelocKind::GlobalData,
            7 => RelocKind::JumpSlot,
            1 => RelocKind::Absolute,
            5 => RelocKind::Copy,
            14 | 15 | 35 | 36 | 37 => RelocKind::Tls,
            _ => RelocKind::Other,
        },
        _ => RelocKind::Other,
    }
}

/// Returns the storage width in bytes of a dynamic relocation type.
///
/// Returns `None` when the width depends on machine-specific semantics.
#[must_use]
pub const fn relocation_width(machine: Machine, r_type: u32) -> Option<u8> {
    match machine.value() {
        62 => match r_type {
            8 | 6 | 7 | 1 | 5 | 16 | 17 | 18 => Some(8),
            2 | 10 | 11 => Some(4),
            _ => None,
        },
        3 => match r_type {
            8 | 6 | 7 | 1 | 5 => Some(4),
            _ => None,
        },
        _ => None,
    }
}
