//! ELF symbol tables.
//!
//! A symbol table pairs fixed-size entries with names from a string table.
//! [`SymbolTable::parse`] decodes the entries and resolves every name.

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::ident::{ElfClass, Endian};
use crate::parse_utils::{array2, array4, array8};
use crate::strtab::StringTable;

/// The symbol binding recorded in the high nibble of `st_info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolBind {
    /// Local symbol, invisible outside the object.
    Local,
    /// Global symbol, visible to all objects.
    Global,
    /// Weak symbol, overridable without a warning.
    Weak,
    /// Another uncommon binding.
    Other(u8),
}

impl SymbolBind {
    /// Converts a raw binding value.
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Local,
            1 => Self::Global,
            2 => Self::Weak,
            other => Self::Other(other),
        }
    }

    /// Returns the raw binding value.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Local => 0,
            Self::Global => 1,
            Self::Weak => 2,
            Self::Other(value) => value,
        }
    }
}

/// The symbol type recorded in the low nibble of `st_info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolType {
    /// No type specified.
    NoType,
    /// A data object.
    Object,
    /// A function or executable code.
    Func,
    /// A section.
    Section,
    /// A source file name.
    File,
    /// A thread-local object.
    Tls,
    /// An indirect function.
    GnuIfunc,
    /// Another uncommon type.
    Other(u8),
}

impl SymbolType {
    /// Converts a raw symbol type value.
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::NoType,
            1 => Self::Object,
            2 => Self::Func,
            3 => Self::Section,
            4 => Self::File,
            6 => Self::Tls,
            10 => Self::GnuIfunc,
            other => Self::Other(other),
        }
    }

    /// Returns the raw symbol type value.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::NoType => 0,
            Self::Object => 1,
            Self::Func => 2,
            Self::Section => 3,
            Self::File => 4,
            Self::Tls => 6,
            Self::GnuIfunc => 10,
            Self::Other(value) => value,
        }
    }
}

/// The symbol visibility recorded in the low bits of `st_other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolVisibility {
    /// Default visibility rules apply.
    Default,
    /// Internal visibility, hidden from other objects.
    Internal,
    /// Not visible to other objects.
    Hidden,
    /// Visible to other objects, not preemptable.
    Protected,
}

impl SymbolVisibility {
    /// Converts the low two bits of `st_other` to a visibility.
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        match value & 0x03 {
            0 => Self::Default,
            1 => Self::Internal,
            2 => Self::Hidden,
            _ => Self::Protected,
        }
    }

    /// Returns the raw visibility value.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Default => 0,
            Self::Internal => 1,
            Self::Hidden => 2,
            Self::Protected => 3,
        }
    }
}

/// One parsed ELF symbol with its name resolved.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Symbol {
    /// The symbol name, empty for unnamed symbols.
    pub name: String,
    /// The symbol value, normally an address.
    pub value: u64,
    /// The symbol size in bytes.
    pub size: u64,
    /// The symbol binding.
    pub bind: SymbolBind,
    /// The symbol type.
    pub sym_type: SymbolType,
    /// The symbol visibility.
    pub visibility: SymbolVisibility,
    /// The related section index, zero for undefined symbols.
    pub shndx: u16,
}

/// A parsed symbol table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SymbolTable {
    /// The symbols in table order.
    pub symbols: Vec<Symbol>,
}

impl SymbolTable {
    /// Parses a symbol table from its section or segment bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the table is not a whole number of entries.
    pub fn parse(
        data: &[u8],
        strtab: StringTable<'_>,
        endian: Endian,
        class: ElfClass,
    ) -> Result<Self> {
        let entry_size = match class {
            ElfClass::Elf64 => 24usize,
            ElfClass::Elf32 => 16usize,
        };
        if !data.len().is_multiple_of(entry_size) {
            return Err(Error::invalid_section(
                "symbol table is not a whole number of entries",
            ));
        }
        let mut symbols = Vec::with_capacity(data.len() / entry_size);
        for entry in data.chunks_exact(entry_size) {
            let name_index = endian.u32(array4(entry, 0)?);
            let (value, size, info, other, shndx) = match class {
                ElfClass::Elf64 => (
                    endian.u64(array8(entry, 8)?),
                    endian.u64(array8(entry, 16)?),
                    entry[4],
                    entry[5],
                    endian.u16(array2(entry, 6)?),
                ),
                ElfClass::Elf32 => (
                    u64::from(endian.u32(array4(entry, 4)?)),
                    u64::from(endian.u32(array4(entry, 8)?)),
                    entry[12],
                    entry[13],
                    endian.u16(array2(entry, 14)?),
                ),
            };
            symbols.push(Symbol {
                name: strtab
                    .get(usize::try_from(name_index).unwrap_or(0))
                    .unwrap_or_default()
                    .to_string(),
                value,
                size,
                bind: SymbolBind::from_u8(info >> 4),
                sym_type: SymbolType::from_u8(info & 0x0f),
                visibility: SymbolVisibility::from_u8(other & 0x03),
                shndx,
            });
        }
        Ok(Self { symbols })
    }

    /// Returns the symbols in table order.
    #[must_use]
    pub fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }

    /// Returns the number of symbols.
    #[must_use]
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Tests whether the table holds no symbols.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}
