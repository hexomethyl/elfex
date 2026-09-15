//! Address conversion and derived tables for an [`ElfImage`].
//!
//! ELF has no relative virtual address. This module uses the image-relative
//! offset `ioff = vaddr - image_base` as the direct analog of a PE relative
//! virtual address.

use alloc::vec::Vec;

use crate::dynamic::DynamicTable;
use crate::error::Result;
use crate::header::Machine;
use crate::notes::{NT_GNU_BUILD_ID, Note};
use crate::program::{Segment, SegmentType};
use crate::reloc::RelocationSection;
use crate::section::SectionType;
use crate::symbol::SymbolTable;
use crate::tls::TlsInfo;

use super::ElfImage;

impl ElfImage {
    /// Returns the raw `e_entry` value.
    ///
    /// The value is a preferred-base virtual address, not an offset.
    #[must_use]
    pub const fn entry_point(&self) -> u64 {
        self.header.entry
    }

    /// Tests whether the image uses the 64-bit ELF class.
    #[must_use]
    pub const fn is_64bit(&self) -> bool {
        self.ident.class.is_64bit()
    }

    /// Returns the machine architecture.
    #[must_use]
    pub const fn machine(&self) -> Machine {
        self.header.machine
    }

    /// Returns the preferred image base.
    ///
    /// The base is the minimum `PT_LOAD` virtual address rounded down to the
    /// segment page size. Position-independent objects normally report zero.
    #[must_use]
    pub fn image_base(&self) -> u64 {
        self.geometry().base
    }

    /// Returns the mapped size of the image.
    ///
    /// The span is the highest `PT_LOAD` end rounded up to the page size,
    /// relative to the preferred image base.
    #[must_use]
    pub fn image_span(&self) -> u64 {
        self.geometry().span
    }

    /// Returns the address geometry derived from the loadable segments.
    fn geometry(&self) -> super::ImageGeometry {
        super::geometry(load_records(&self.segments))
    }

    /// Returns the base address this image instance uses.
    #[must_use]
    pub const fn runtime_image_base(&self) -> u64 {
        self.runtime_base
    }

    /// Sets the base address this image instance uses.
    pub fn set_runtime_image_base(&mut self, base: u64) {
        self.runtime_base = base;
    }

    /// Converts an image-relative offset to its serialized file offset.
    ///
    /// Returns `None` when the offset has no file-backed byte.
    #[must_use]
    pub fn ioff_to_offset(&self, ioff: u64) -> Option<u64> {
        let vaddr = self.image_base().checked_add(ioff)?;
        let segment = self.segments.iter().find(|segment| {
            segment.header.r#type.0 == SegmentType::LOAD.0
                && vaddr >= segment.header.vaddr
                && vaddr < segment.header.vaddr.saturating_add(segment.header.filesz)
        })?;
        segment
            .header
            .offset
            .checked_add(vaddr - segment.header.vaddr)
    }

    /// Returns the loadable segment that covers an image-relative offset.
    #[must_use]
    pub fn segment_by_ioff(&self, ioff: u64) -> Option<&Segment> {
        let vaddr = self.image_base().checked_add(ioff)?;
        self.segments
            .iter()
            .find(|segment| segment.contains_vaddr(vaddr))
    }

    /// Reads up to `len` bytes at an image-relative offset into owned storage.
    ///
    /// Bytes beyond the segment's file data but inside its memory size read as
    /// zero, matching loader semantics.
    #[must_use]
    pub fn read_ioff(&self, ioff: u64, len: usize) -> Option<Vec<u8>> {
        let vaddr = self.image_base().checked_add(ioff)?;
        self.read_at_vaddr(vaddr, len)
    }

    /// Returns up to `len` bytes at an image-relative offset.
    ///
    /// The slice stops at the segment's file data. Zero-filled tail bytes have
    /// no slice representation; use [`ElfImage::read_ioff`] for them.
    #[must_use]
    pub fn read_at_ioff(&self, ioff: u64, len: usize) -> Option<&[u8]> {
        let segment = self.segment_by_ioff(ioff)?;
        let vaddr = self.image_base() + ioff;
        segment.data_at_vaddr(vaddr, len)
    }

    /// Tests whether an image-relative range lies inside the image.
    #[must_use]
    pub fn contains_ioff_range(&self, ioff: u64, len: u64) -> bool {
        match ioff.checked_add(len) {
            Some(end) => end <= self.image_span(),
            None => false,
        }
    }

    /// Parses the dynamic table from the `PT_DYNAMIC` segment.
    ///
    /// Returns `None` when the image declares no dynamic segment.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the dynamic segment cannot be decoded.
    pub fn dynamic(&self) -> Result<Option<DynamicTable>> {
        let Some(segment) = self
            .segments
            .iter()
            .find(|segment| segment.header.r#type.0 == SegmentType::DYNAMIC.0)
        else {
            return Ok(None);
        };
        let table = DynamicTable::parse(&segment.data, self.ident.data, self.ident.class)?;
        Ok(Some(table))
    }

    /// Parses the dynamic symbol table from `.dynsym` and `.dynstr`.
    ///
    /// Returns an empty table when the sections are absent.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when a present table cannot be decoded.
    pub fn dynamic_symbols(&self) -> Result<SymbolTable> {
        self.symbols_from(".dynsym", ".dynstr")
    }

    /// Parses the full symbol table from `.symtab` and `.strtab`.
    ///
    /// Returns an empty table when the sections are absent.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when a present table cannot be decoded.
    pub fn symbols(&self) -> Result<SymbolTable> {
        self.symbols_from(".symtab", ".strtab")
    }

    /// Parses every relocation section in the image.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when a relocation section cannot be decoded.
    pub fn relocations(&self) -> Result<Vec<RelocationSection>> {
        let mut tables = Vec::new();
        for section in &self.sections {
            let is_rela = match section.header.r#type.0 {
                value if value == SectionType::RELA.0 => true,
                value if value == SectionType::REL.0 => false,
                _ => continue,
            };
            tables.push(RelocationSection::parse(
                &section.data,
                is_rela,
                self.ident.data,
                self.ident.class,
            )?);
        }
        Ok(tables)
    }

    /// Parses every note from `PT_NOTE` segments and `SHT_NOTE` sections.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when a note cannot be decoded.
    pub fn notes(&self) -> Result<Vec<Note>> {
        let mut notes = Vec::new();
        for segment in &self.segments {
            if segment.header.r#type.0 == SegmentType::NOTE.0 {
                notes.extend(Note::parse_all(&segment.data, self.ident.data)?);
            }
        }
        for section in &self.sections {
            if section.header.r#type.0 == SectionType::NOTE.0 {
                notes.extend(Note::parse_all(&section.data, self.ident.data)?);
            }
        }
        Ok(notes)
    }

    /// Returns the GNU build identifier when a build-id note exists.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when a note cannot be decoded.
    pub fn build_id(&self) -> Result<Option<Vec<u8>>> {
        Ok(self
            .notes()?
            .into_iter()
            .find(|note| note.is_gnu(NT_GNU_BUILD_ID))
            .map(|note| note.descriptor))
    }

    /// Returns thread-local storage metadata from the `PT_TLS` segment.
    #[must_use]
    pub fn tls(&self) -> Option<TlsInfo> {
        self.segments
            .iter()
            .find(|segment| segment.header.r#type.0 == SegmentType::TLS.0)
            .map(|segment| TlsInfo::from_header(&segment.header))
    }

    fn symbols_from(&self, table: &str, strings: &str) -> Result<SymbolTable> {
        let Some(data) = self.section_by_name(table).map(|section| &section.data) else {
            return Ok(SymbolTable::default());
        };
        let strtab_bytes = self
            .section_by_name(strings)
            .map(|section| section.data.clone())
            .unwrap_or_default();
        let strtab = crate::strtab::StringTable::new(&strtab_bytes);
        SymbolTable::parse(data, strtab, self.ident.data, self.ident.class)
    }

    /// Returns up to `len` bytes at a preferred-base virtual address.
    ///
    /// Bytes beyond the covering segment's file data but inside its memory
    /// size read as zero. Returns `None` when no segment covers `vaddr`.
    #[must_use]
    pub fn read_at_vaddr(&self, vaddr: u64, len: usize) -> Option<Vec<u8>> {
        let segment = self
            .segments
            .iter()
            .find(|segment| segment.contains_vaddr(vaddr))?;
        let in_segment = usize::try_from(vaddr - segment.header.vaddr).ok()?;
        let mut out = alloc_vec(len);
        let available = segment.data.get(in_segment..).unwrap_or(&[]);
        let from_data = available.len().min(out.len());
        out[..from_data].copy_from_slice(&available[..from_data]);
        Some(out)
    }

    /// Returns the first section with `name`.
    #[must_use]
    pub fn section_by_name(&self, name: &str) -> Option<&crate::section::Section> {
        self.sections.iter().find(|section| section.name == name)
    }
}

fn load_records(segments: &[Segment]) -> impl Iterator<Item = (u64, u64, u64)> + '_ {
    segments
        .iter()
        .filter(|segment| segment.header.r#type.0 == SegmentType::LOAD.0)
        .map(|segment| {
            (
                segment.header.vaddr,
                segment.header.memsz,
                segment.header.align,
            )
        })
}

fn alloc_vec(len: usize) -> Vec<u8> {
    alloc::vec![0u8; len]
}
