//! ELF dynamic linking metadata.
//!
//! A `PT_DYNAMIC` segment or `SHT_DYNAMIC` section holds a table of tagged
//! values. [`DynamicTable`] decodes the table, and its accessors resolve
//! string values through the dynamic string table.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::ident::{ElfClass, Endian};
use crate::parse_utils::{array4, array8};
use crate::strtab::StringTable;

/// The tag of one dynamic table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DynTag(pub u64);

impl DynTag {
    /// Marks the end of the table.
    pub const NULL: Self = Self(0);
    /// Names one needed shared object.
    pub const NEEDED: Self = Self(1);
    /// Size of the PLT relocation table.
    pub const PLTRELSZ: Self = Self(2);
    /// Address of the PLT or GOT.
    pub const PLTGOT: Self = Self(3);
    /// Address of the symbol hash table.
    pub const HASH: Self = Self(4);
    /// Address of the dynamic string table.
    pub const STRTAB: Self = Self(5);
    /// Address of the dynamic symbol table.
    pub const SYMTAB: Self = Self(6);
    /// Address of the RELA relocation table.
    pub const RELA: Self = Self(7);
    /// Total size of the RELA table.
    pub const RELASZ: Self = Self(8);
    /// Size of one RELA entry.
    pub const RELAENT: Self = Self(9);
    /// Total size of the dynamic string table.
    pub const STRSZ: Self = Self(10);
    /// Size of one dynamic symbol entry.
    pub const SYMENT: Self = Self(11);
    /// Address of the init function.
    pub const INIT: Self = Self(12);
    /// Address of the fini function.
    pub const FINI: Self = Self(13);
    /// String-table offset of the shared object name.
    pub const SONAME: Self = Self(14);
    /// String-table offset of the library search path.
    pub const RPATH: Self = Self(15);
    /// Marks a symbolic link.
    pub const SYMBOLIC: Self = Self(16);
    /// Address of the REL relocation table.
    pub const REL: Self = Self(17);
    /// Total size of the REL table.
    pub const RELSZ: Self = Self(18);
    /// Size of one REL entry.
    pub const RELENT: Self = Self(19);
    /// Relocation type of the PLT entries.
    pub const PLTREL: Self = Self(20);
    /// Slot for the dynamic linker's own use.
    pub const DEBUG: Self = Self(21);
    /// Marks relocation of a read-only segment.
    pub const TEXTREL: Self = Self(22);
    /// Address of the PLT relocation table.
    pub const JMPREL: Self = Self(23);
    /// Requires eager symbol binding.
    pub const BIND_NOW: Self = Self(24);
    /// Address of the init-function array.
    pub const INIT_ARRAY: Self = Self(25);
    /// Address of the fini-function array.
    pub const FINI_ARRAY: Self = Self(26);
    /// Size of the init-function array.
    pub const INIT_ARRAYSZ: Self = Self(27);
    /// Size of the fini-function array.
    pub const FINI_ARRAYSZ: Self = Self(28);
    /// String-table offset of the runtime search path.
    pub const RUNPATH: Self = Self(29);
    /// Generic dynamic flags.
    pub const FLAGS: Self = Self(30);
    /// Marks the start of the encoded tag range.
    pub const ENCODING: Self = Self(31);
    /// Address of the pre-init-function array.
    pub const PREINIT_ARRAY: Self = Self(32);
    /// Size of the pre-init-function array.
    pub const PREINIT_ARRAYSZ: Self = Self(33);
    /// Address of the extended section index table.
    pub const SYMTAB_SHNDX: Self = Self(34);
    /// Total size of the RELR relocation table.
    pub const RELRSZ: Self = Self(35);
    /// Address of the RELR relocation table.
    pub const RELR: Self = Self(36);
    /// Size of one RELR entry.
    pub const RELRENT: Self = Self(37);
    /// Address of the GNU-style hash table.
    pub const GNU_HASH: Self = Self(0x6fff_fef5);
    /// Address of the version symbol table.
    pub const VERSYM: Self = Self(0x6fff_fff0);
    /// Number of relative relocations in the RELA table.
    pub const RELACOUNT: Self = Self(0x6fff_fff9);
    /// Number of relative relocations in the REL table.
    pub const RELCOUNT: Self = Self(0x6fff_fffa);
    /// State flags for this object.
    pub const FLAGS_1: Self = Self(0x6fff_fffb);
    /// Address of the version definition table.
    pub const VERDEF: Self = Self(0x6fff_fffc);
    /// Number of version definitions.
    pub const VERDEFNUM: Self = Self(0x6fff_fffd);
    /// Address of the version dependency table.
    pub const VERNEED: Self = Self(0x6fff_fffe);
    /// Number of version dependencies.
    pub const VERNEEDNUM: Self = Self(0x6fff_ffff);

    /// Returns the raw tag value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// One dynamic table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DynamicEntry {
    /// The entry tag.
    pub tag: DynTag,
    /// The entry value: an address, a size, or a string-table offset.
    pub value: u64,
}

/// A parsed dynamic table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DynamicTable {
    /// The entries in table order, ending before `DT_NULL`.
    pub entries: Vec<DynamicEntry>,
}

impl DynamicTable {
    /// Parses a dynamic table from its segment or section bytes.
    ///
    /// Parsing stops at the first `DT_NULL` entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the table is not a whole number of entries.
    pub fn parse(data: &[u8], endian: Endian, class: ElfClass) -> Result<Self> {
        let entry_size = match class {
            ElfClass::Elf64 => 16usize,
            ElfClass::Elf32 => 8,
        };
        if !data.len().is_multiple_of(entry_size) {
            return Err(Error::invalid_section(
                "dynamic table is not a whole number of entries",
            ));
        }
        let mut entries = Vec::new();
        for entry in data.chunks_exact(entry_size) {
            let (tag, value) = match class {
                ElfClass::Elf64 => (
                    DynTag(endian.u64(array8(entry, 0)?)),
                    endian.u64(array8(entry, 8)?),
                ),
                ElfClass::Elf32 => (
                    DynTag(u64::from(endian.u32(array4(entry, 0)?))),
                    u64::from(endian.u32(array4(entry, 4)?)),
                ),
            };
            if tag == DynTag::NULL {
                break;
            }
            entries.push(DynamicEntry { tag, value });
        }
        Ok(Self { entries })
    }

    /// Returns the entries in table order.
    #[must_use]
    pub fn entries(&self) -> &[DynamicEntry] {
        &self.entries
    }

    /// Returns the first value stored for `tag`.
    #[must_use]
    pub fn find(&self, tag: DynTag) -> Option<u64> {
        self.entries
            .iter()
            .find(|entry| entry.tag == tag)
            .map(|entry| entry.value)
    }

    /// Returns the names of every needed shared object.
    #[must_use]
    pub fn needed(&self, strtab: StringTable<'_>) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| entry.tag == DynTag::NEEDED)
            .filter_map(|entry| string_at(strtab, entry.value))
            .collect()
    }

    /// Returns the shared object name of this object.
    #[must_use]
    pub fn soname(&self, strtab: StringTable<'_>) -> Option<String> {
        self.string_value(DynTag::SONAME, strtab)
    }

    /// Returns the runtime library search path.
    #[must_use]
    pub fn runpath(&self, strtab: StringTable<'_>) -> Option<String> {
        self.string_value(DynTag::RUNPATH, strtab)
    }

    /// Returns the link-time library search path.
    #[must_use]
    pub fn rpath(&self, strtab: StringTable<'_>) -> Option<String> {
        self.string_value(DynTag::RPATH, strtab)
    }

    fn string_value(&self, tag: DynTag, strtab: StringTable<'_>) -> Option<String> {
        string_at(strtab, self.find(tag)?)
    }
}

fn string_at(strtab: StringTable<'_>, offset: u64) -> Option<String> {
    strtab.get(usize::try_from(offset).ok()?).map(String::from)
}
