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

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{RelocKind, RelocationSection, relocation_kind, relocation_width};
    use crate::header::Machine;
    use crate::ident::{ElfClass, Endian};

    const X86_64: Machine = Machine(62);
    const I386: Machine = Machine(3);

    /// Every x86-64 dynamic relocation type the corpus can produce, plus the
    /// four-byte forms and the deliberately unclassified ones.
    #[test]
    fn x86_64_relocations_classify_and_size() {
        for (r_type, kind, width) in [
            (1u32, RelocKind::Absolute, Some(8u8)),
            (2, RelocKind::Other, Some(4)),
            (5, RelocKind::Copy, Some(8)),
            (6, RelocKind::GlobalData, Some(8)),
            (7, RelocKind::JumpSlot, Some(8)),
            (8, RelocKind::Relative, Some(8)),
            (10, RelocKind::Other, Some(4)),
            (11, RelocKind::Other, Some(4)),
            (16, RelocKind::Tls, Some(8)),
            (17, RelocKind::Tls, Some(8)),
            (18, RelocKind::Tls, Some(8)),
            (4, RelocKind::Other, None),
            (37, RelocKind::Other, None),
        ] {
            assert_eq!(
                relocation_kind(X86_64, r_type),
                kind,
                "x86-64 type {r_type} kind"
            );
            assert_eq!(
                relocation_width(X86_64, r_type),
                width,
                "x86-64 type {r_type} width"
            );
        }
    }

    /// The i386 table classifies the same purposes at half the width, and
    /// leaves the TLS forms unsized because their storage is model-specific.
    #[test]
    fn i386_relocations_classify_and_size() {
        for (r_type, kind, width) in [
            (1u32, RelocKind::Absolute, Some(4u8)),
            (5, RelocKind::Copy, Some(4)),
            (6, RelocKind::GlobalData, Some(4)),
            (7, RelocKind::JumpSlot, Some(4)),
            (8, RelocKind::Relative, Some(4)),
            (14, RelocKind::Tls, None),
            (15, RelocKind::Tls, None),
            (35, RelocKind::Tls, None),
            (36, RelocKind::Tls, None),
            (37, RelocKind::Tls, None),
            (2, RelocKind::Other, None),
        ] {
            assert_eq!(relocation_kind(I386, r_type), kind, "i386 type {r_type} kind");
            assert_eq!(
                relocation_width(I386, r_type),
                width,
                "i386 type {r_type} width"
            );
        }
    }

    #[test]
    fn an_unknown_machine_classifies_nothing() {
        for r_type in [1u32, 5, 6, 7, 8, 16] {
            assert_eq!(relocation_kind(Machine(0), r_type), RelocKind::Other);
            assert_eq!(relocation_width(Machine(0), r_type), None);
        }
    }

    /// `r_info` packs the symbol index above the type, but the split point
    /// differs by class: 32 bits for ELF64 and 8 bits for ELF32.
    #[test]
    fn the_r_info_split_differs_by_class() {
        let mut rela = Vec::new();
        rela.extend_from_slice(&0x1000u64.to_le_bytes());
        rela.extend_from_slice(&(((0x1234u64) << 32) | 8).to_le_bytes());
        rela.extend_from_slice(&(-8i64).to_le_bytes());
        let table = RelocationSection::parse(&rela, true, Endian::Little, ElfClass::Elf64)
            .expect("a whole RELA entry decodes");
        assert!(table.is_rela());
        let entry = table.entries()[0];
        assert_eq!(entry.offset, 0x1000);
        assert_eq!(entry.symbol, 0x1234);
        assert_eq!(entry.r_type, 8);
        assert_eq!(entry.addend, Some(-8));

        let mut rel = Vec::new();
        rel.extend_from_slice(&0x2000u32.to_le_bytes());
        rel.extend_from_slice(&(((0x5678u32) << 8) | 6).to_le_bytes());
        let table = RelocationSection::parse(&rel, false, Endian::Little, ElfClass::Elf32)
            .expect("a whole REL entry decodes");
        assert!(!table.is_rela());
        let entry = table.entries()[0];
        assert_eq!(entry.offset, 0x2000);
        assert_eq!(entry.symbol, 0x5678);
        assert_eq!(entry.r_type, 6);
        assert_eq!(entry.addend, None, "a REL entry has no explicit addend");
    }

    #[test]
    fn big_endian_entries_decode_with_the_declared_byte_order() {
        let mut rela = Vec::new();
        rela.extend_from_slice(&0x1000u64.to_be_bytes());
        rela.extend_from_slice(&(((7u64) << 32) | 6).to_be_bytes());
        rela.extend_from_slice(&0x20i64.to_be_bytes());
        let table = RelocationSection::parse(&rela, true, Endian::Big, ElfClass::Elf64)
            .expect("a big-endian RELA entry decodes");
        let entry = table.entries()[0];
        assert_eq!(entry.offset, 0x1000);
        assert_eq!(entry.symbol, 7);
        assert_eq!(entry.r_type, 6);
        assert_eq!(entry.addend, Some(0x20));
    }

    #[test]
    fn a_table_that_is_not_whole_entries_is_rejected() {
        let error = RelocationSection::parse(&[0u8; 7], false, Endian::Little, ElfClass::Elf32)
            .expect_err("seven bytes is not a whole number of REL entries");
        assert!(
            alloc::format!("{error:?}").contains("relocation table"),
            "the error should name the relocation table: {error:?}"
        );
    }

    #[test]
    fn an_empty_table_decodes_to_no_entries() {
        let table = RelocationSection::parse(&[], true, Endian::Little, ElfClass::Elf64)
            .expect("an empty table is valid");
        assert!(table.entries().is_empty());
        assert!(table.is_rela());
    }
}
