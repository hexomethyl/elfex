//! Fluent builder for constructing an [`ElfImage`] from scratch.
//!
//! [`ElfBuilder`] creates simple ELF test fixtures without touching real
//! linker output. The builder produces a valid [`ElfImage`] that round-trips
//! through [`ElfImage::parse`].

use alloc::string::String;
use alloc::vec::Vec;

use crate::elf::ElfImage;
use crate::error::Result;
use crate::header::{ElfHeader, ElfType, Machine};
use crate::ident::{ElfClass, ElfIdent, Endian, OsAbi};
use crate::program::{ProgramHeader, Segment, SegmentFlags, SegmentType};
use crate::reloc::RelocationEntry;
use crate::section::{Section, SectionFlags, SectionHeader, SectionType};

/// A fluent builder for [`ElfImage`] test fixtures.
#[derive(Debug, Clone)]
pub struct ElfBuilder {
    class: ElfClass,
    endian: Endian,
    elf_type: ElfType,
    machine: Machine,
    entry: u64,
    os_abi: OsAbi,
    flags: u32,
    loads: Vec<LoadSpec>,
    notes: Vec<NoteSpec>,
    relocations: Vec<RelocationEntry>,
}

#[derive(Debug, Clone)]
struct LoadSpec {
    vaddr: u64,
    flags: SegmentFlags,
    align: u64,
    data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct NoteSpec {
    name: String,
    note_type: u32,
    descriptor: Vec<u8>,
}

impl Default for ElfBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ElfBuilder {
    /// Creates a builder with x86-64, 64-bit little-endian defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            class: ElfClass::Elf64,
            endian: Endian::Little,
            elf_type: ElfType::Exec,
            machine: Machine::X86_64,
            entry: 0,
            os_abi: OsAbi::SYSV,
            flags: 0,
            loads: Vec::new(),
            notes: Vec::new(),
            relocations: Vec::new(),
        }
    }

    /// Sets the ELF class.
    #[must_use]
    pub const fn class(mut self, class: ElfClass) -> Self {
        self.class = class;
        self
    }

    /// Sets the byte order.
    #[must_use]
    pub const fn endian(mut self, endian: Endian) -> Self {
        self.endian = endian;
        self
    }

    /// Sets the object file type.
    #[must_use]
    pub const fn elf_type(mut self, elf_type: ElfType) -> Self {
        self.elf_type = elf_type;
        self
    }

    /// Sets the machine architecture.
    #[must_use]
    pub const fn machine(mut self, machine: Machine) -> Self {
        self.machine = machine;
        self
    }

    /// Sets the entry-point virtual address.
    #[must_use]
    pub const fn entry(mut self, entry: u64) -> Self {
        self.entry = entry;
        self
    }

    /// Sets the operating-system ABI.
    #[must_use]
    pub const fn os_abi(mut self, os_abi: OsAbi) -> Self {
        self.os_abi = os_abi;
        self
    }

    /// Sets the processor-specific flags.
    #[must_use]
    pub const fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Adds a loadable segment with the given virtual address, permissions,
    /// and bytes. The alignment defaults to `0x1000`.
    #[must_use]
    pub fn add_load(mut self, vaddr: u64, flags: SegmentFlags, data: Vec<u8>) -> Self {
        self.loads.push(LoadSpec {
            vaddr,
            flags,
            align: 0x1000,
            data,
        });
        self
    }

    /// Adds a loadable segment with explicit alignment.
    #[must_use]
    pub fn add_load_aligned(
        mut self,
        vaddr: u64,
        flags: SegmentFlags,
        align: u64,
        data: Vec<u8>,
    ) -> Self {
        self.loads.push(LoadSpec {
            vaddr,
            flags,
            align,
            data,
        });
        self
    }

    /// Embeds a note record.
    ///
    /// The builder serializes the note into its own `PT_NOTE` segment and a
    /// `SHT_NOTE` section named `.note.<name>`.
    #[must_use]
    pub fn add_note(
        mut self,
        name: impl Into<String>,
        note_type: u32,
        descriptor: impl Into<Vec<u8>>,
    ) -> Self {
        self.notes.push(NoteSpec {
            name: name.into(),
            note_type,
            descriptor: descriptor.into(),
        });
        self
    }

    /// Adds relocation entries that become a `.rela.dyn` section.
    #[must_use]
    pub fn add_relocations(mut self, entries: Vec<RelocationEntry>) -> Self {
        self.relocations = entries;
        self
    }

    /// Builds the [`ElfImage`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the layout is invalid.
    pub fn try_build(self) -> Result<ElfImage> {
        let ident = ElfIdent {
            class: self.class,
            data: self.endian,
            version: 1,
            os_abi: self.os_abi,
            abi_version: 0,
        };

        let mut segments: Vec<Segment> = Vec::new();
        let mut sections: Vec<Section> = Vec::new();

        sections.push(null_section());

        for load in &self.loads {
            let filesz = u64::try_from(load.data.len()).unwrap_or(0);
            segments.push(Segment {
                header: ProgramHeader {
                    r#type: SegmentType::LOAD,
                    flags: load.flags,
                    offset: 0,
                    vaddr: load.vaddr,
                    paddr: load.vaddr,
                    filesz,
                    memsz: filesz,
                    align: load.align,
                },
                data: load.data.clone(),
            });
        }

        add_notes(&self.notes, self.endian, &mut segments, &mut sections);
        add_rela(&self.relocations, self.endian, self.class, &mut sections);

        let header = ElfHeader {
            ident,
            r#type: self.elf_type,
            machine: self.machine,
            version: 1,
            entry: self.entry,
            phoff: 0,
            shoff: 0,
            flags: self.flags,
            ehsize: 0,
            phentsize: 0,
            phnum: 0,
            shentsize: 0,
            shnum: 0,
            shstrndx: 0,
        };

        let image = ElfImage {
            ident,
            header,
            segments,
            sections,
            runtime_base: 0,
        };

        let bytes = image.try_build()?;
        ElfImage::parse(&bytes)
    }

    /// Builds the [`ElfImage`].
    ///
    /// # Panics
    ///
    /// Panics when [`ElfBuilder::try_build`] fails.
    #[must_use]
    pub fn build(self) -> ElfImage {
        self.try_build().expect("the ELF builder layout is valid")
    }
}

fn null_section() -> Section {
    Section {
        header: SectionHeader {
            name_index: 0,
            r#type: SectionType::NULL,
            flags: SectionFlags(0),
            addr: 0,
            offset: 0,
            size: 0,
            link: 0,
            info: 0,
            addralign: 0,
            entsize: 0,
        },
        name: String::new(),
        data: Vec::new(),
    }
}

fn serialize_note(spec: &NoteSpec, endian: Endian) -> Vec<u8> {
    let name_bytes = spec.name.as_bytes();
    let namesz = u32::try_from(name_bytes.len() + 1).unwrap_or(0);
    let descsz = u32::try_from(spec.descriptor.len()).unwrap_or(0);
    let mut out = Vec::new();
    out.extend_from_slice(&endian.u32_bytes(namesz));
    out.extend_from_slice(&endian.u32_bytes(descsz));
    out.extend_from_slice(&endian.u32_bytes(spec.note_type));
    out.extend_from_slice(name_bytes);
    out.push(0);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out.extend_from_slice(&spec.descriptor);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn serialize_rela(entries: &[RelocationEntry], endian: Endian, class: ElfClass) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        match class {
            ElfClass::Elf64 => {
                out.extend_from_slice(&endian.u64_bytes(entry.offset));
                let info = (u64::from(entry.symbol) << 32) | u64::from(entry.r_type);
                out.extend_from_slice(&endian.u64_bytes(info));
                out.extend_from_slice(&endian.i64_bytes(entry.addend.unwrap_or(0)));
            }
            ElfClass::Elf32 => {
                out.extend_from_slice(&endian.u32_bytes(crate::low32(entry.offset)));
                let info = (entry.symbol << 8) | (entry.r_type & 0xff);
                out.extend_from_slice(&endian.u32_bytes(info));
                let addend = i32::try_from(entry.addend.unwrap_or(0)).unwrap_or(0);
                out.extend_from_slice(&endian.u32_bytes(addend.cast_unsigned()));
            }
        }
    }
    out
}

fn add_notes(
    notes: &[NoteSpec],
    endian: Endian,
    segments: &mut Vec<Segment>,
    sections: &mut Vec<Section>,
) {
    for note_spec in notes {
        let note_bytes = serialize_note(note_spec, endian);
        let note_len = u64::try_from(note_bytes.len()).unwrap_or(0);
        segments.push(Segment {
            header: ProgramHeader {
                r#type: SegmentType::NOTE,
                flags: SegmentFlags(SegmentFlags::READ),
                offset: 0,
                vaddr: 0,
                paddr: 0,
                filesz: note_len,
                memsz: note_len,
                align: 4,
            },
            data: note_bytes.clone(),
        });
        let section_name = alloc::format!(".note.{}", note_spec.name);
        sections.push(Section {
            header: SectionHeader {
                name_index: 0,
                r#type: SectionType::NOTE,
                flags: SectionFlags(0),
                addr: 0,
                offset: 0,
                size: note_len,
                link: 0,
                info: 0,
                addralign: 4,
                entsize: 0,
            },
            name: section_name,
            data: note_bytes,
        });
    }
}

fn add_rela(
    relocations: &[RelocationEntry],
    endian: Endian,
    class: ElfClass,
    sections: &mut Vec<Section>,
) {
    if relocations.is_empty() {
        return;
    }
    let rela_data = serialize_rela(relocations, endian, class);
    let rela_len = u64::try_from(rela_data.len()).unwrap_or(0);
    sections.push(Section {
        header: SectionHeader {
            name_index: 0,
            r#type: SectionType::RELA,
            flags: SectionFlags(0),
            addr: 0,
            offset: 0,
            size: rela_len,
            link: 0,
            info: 0,
            addralign: 8,
            entsize: match class {
                ElfClass::Elf64 => 24,
                ElfClass::Elf32 => 12,
            },
        },
        name: ".rela.dyn".into(),
        data: rela_data,
    });
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use super::*;
    use crate::notes::NT_GNU_BUILD_ID;

    fn code_flags() -> SegmentFlags {
        SegmentFlags(SegmentFlags::READ | SegmentFlags::EXECUTE)
    }

    #[test]
    fn elf64_round_trip() {
        let image = ElfBuilder::new()
            .machine(Machine::X86_64)
            .elf_type(ElfType::Exec)
            .entry(0x40_1000)
            .add_load(0x40_1000, code_flags(), vec![0xf4])
            .build();

        let bytes = image.try_build().expect("the test ELF serializes");
        let reparsed = ElfImage::parse(&bytes).expect("the serialized ELF re-parses");

        assert_eq!(reparsed.entry_point(), 0x40_1000);
        assert_eq!(reparsed.image_base(), 0x40_1000);
        assert!(reparsed.is_64bit());
        assert_eq!(reparsed.read_ioff(0, 1), Some(vec![0xf4]),);
        let segment = reparsed
            .segment_by_ioff(0)
            .expect("the code lives in a segment");
        assert!(segment.flags().is_executable());
        assert!(reparsed.validate().is_ok());
    }

    #[test]
    fn elf32_round_trip() {
        let image = ElfBuilder::new()
            .class(ElfClass::Elf32)
            .endian(Endian::Little)
            .machine(Machine::I386)
            .elf_type(ElfType::Exec)
            .entry(0x0804_8000)
            .add_load(0x0804_8000, code_flags(), vec![0xcc, 0xc3])
            .build();

        let bytes = image.try_build().expect("the ELF32 serializes");
        let reparsed = ElfImage::parse(&bytes).expect("the ELF32 re-parses");

        assert!(!reparsed.is_64bit());
        assert_eq!(reparsed.entry_point(), 0x0804_8000);
        assert_eq!(reparsed.read_ioff(0, 2), Some(vec![0xcc, 0xc3]),);
        assert!(reparsed.validate().is_ok());
    }

    #[test]
    fn note_round_trip() {
        let build_id = vec![0xde, 0xad, 0xbe, 0xef];
        let image = ElfBuilder::new()
            .entry(0x40_1000)
            .add_load(0x40_1000, code_flags(), vec![0xf4])
            .add_note("GNU", NT_GNU_BUILD_ID, build_id.clone())
            .build();

        let id = image
            .build_id()
            .expect("notes parse")
            .expect("a build-id note exists");
        assert_eq!(id, build_id);
    }
}
