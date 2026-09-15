//! Parsing an [`ElfImage`] from file or mapped byte layouts.

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::header::ElfHeaders;
use crate::program::{Segment, SegmentType};
use crate::reader::{ReadAt, SliceReader};
use crate::section::{Section, SectionHeader, SectionType};
use crate::strtab::StringTable;

use super::ElfImage;

/// The byte layout of an ELF byte source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Layout {
    /// Raw file layout addressed by file offsets.
    File,
    /// Loader-mapped layout addressed by image-relative offsets.
    Mapped,
}

impl ElfImage {
    /// Parses bytes in ELF file layout.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when a structure or its data cannot be read.
    pub fn parse(data: &[u8]) -> Result<Self> {
        Self::read_from(&SliceReader::new(data), 0, Layout::File)
    }

    /// Parses bytes from a loader-mapped image at its preferred base.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when a structure or its data cannot be read.
    pub fn parse_mapped(data: &[u8]) -> Result<Self> {
        let image = Self::read_from(&SliceReader::new(data), 0, Layout::Mapped)?;
        Ok(image)
    }

    /// Parses bytes from a loader-mapped image at `load_base`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when a structure or its data cannot be read.
    pub fn parse_mapped_at(data: &[u8], load_base: u64) -> Result<Self> {
        let mut image = Self::read_from(&SliceReader::new(data), 0, Layout::Mapped)?;
        image.runtime_base = load_base;
        Ok(image)
    }

    /// Reads an image from a positional source in the given layout.
    ///
    /// `base_offset` addresses the ELF header inside the source. Use it to
    /// parse an image embedded at a known offset.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when a structure or its data cannot be read.
    pub fn read_from<R: ReadAt>(reader: &R, base_offset: u64, layout: Layout) -> Result<Self> {
        let shifted = OffsetReader {
            inner: reader,
            base: base_offset,
        };
        let mut image = match layout {
            Layout::File => Self::read_file_layout(&shifted)?,
            Layout::Mapped => Self::read_mapped_layout(&shifted)?,
        };
        image.runtime_base = image.image_base();
        Ok(image)
    }

    /// Reads a loader-mapped image from a positional memory source.
    ///
    /// `source_address` addresses the ELF header in the source. `load_base` is
    /// the virtual address where the loader placed the image. Missing mapped
    /// pages read as zero-filled bytes, so a partially resident image still
    /// parses.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when a structural header cannot be read.
    pub fn read_mapped_from<R: ReadAt>(
        reader: &R,
        source_address: u64,
        load_base: u64,
    ) -> Result<Self> {
        let shifted = OffsetReader {
            inner: reader,
            base: source_address,
        };
        let mut image = Self::read_mapped_layout(&shifted)?;
        image.runtime_base = load_base;
        Ok(image)
    }

    fn read_file_layout<R: ReadAt>(reader: &R) -> Result<Self> {
        let headers = ElfHeaders::read_from(reader)?;
        let source_size = reader.size();
        let mut segments = Vec::with_capacity(headers.program_headers.len());
        for header in &headers.program_headers {
            let data = if header.r#type.0 == SegmentType::NULL.0 || header.filesz == 0 {
                Vec::new()
            } else {
                let len = checked_len(header.filesz, source_size)?;
                reader.read_bytes_at(header.offset, len)?
            };
            segments.push(Segment {
                header: *header,
                data,
            });
        }
        let sections = read_file_sections(reader, &headers)?;
        Ok(Self {
            ident: headers.ident,
            header: headers.header,
            segments,
            sections,
            runtime_base: 0,
        })
    }

    fn read_mapped_layout<R: ReadAt>(reader: &R) -> Result<Self> {
        let headers = ElfHeaders::read_from(reader)?;
        let source_size = reader.size();
        let image_base = compute_image_base(&headers.program_headers);
        let mut segments = Vec::with_capacity(headers.program_headers.len());
        for header in &headers.program_headers {
            let length = if header.r#type.0 == SegmentType::LOAD.0 {
                header.memsz
            } else {
                header.filesz
            };
            let data = if header.r#type.0 == SegmentType::NULL.0 || length == 0 {
                Vec::new()
            } else {
                let len = checked_len(length, source_size)?;
                let start = header.vaddr.saturating_sub(image_base);
                let mut data = alloc::vec![0u8; len];
                read_lenient(reader, start, &mut data);
                data
            };
            segments.push(Segment {
                header: *header,
                data,
            });
        }
        let sections = read_mapped_sections(reader, &headers, image_base);
        Ok(Self {
            ident: headers.ident,
            header: headers.header,
            segments,
            sections,
            runtime_base: 0,
        })
    }
}

/// Computes the preferred image base from the loadable program headers.
pub(super) fn compute_image_base(program_headers: &[crate::program::ProgramHeader]) -> u64 {
    super::geometry(
        program_headers
            .iter()
            .filter(|header| header.r#type.0 == SegmentType::LOAD.0)
            .map(|header| (header.vaddr, header.memsz, header.align)),
    )
    .base
}

fn read_file_sections<R: ReadAt>(reader: &R, headers: &ElfHeaders) -> Result<Vec<Section>> {
    if headers.header.shoff == 0 || headers.header.shnum == 0 {
        return Ok(Vec::new());
    }
    let raw = read_section_headers(reader, headers)?;
    let names = section_names(reader, headers, &raw);
    let mut sections = Vec::with_capacity(raw.len());
    for header in raw {
        let data = if header.is_nobits() || header.size == 0 {
            Vec::new()
        } else {
            let len = checked_len(header.size, reader.size())?;
            reader.read_bytes_at(header.offset, len)?
        };
        sections.push(Section {
            name: names
                .get(usize::try_from(header.name_index).unwrap_or(0))
                .cloned()
                .unwrap_or_default(),
            header,
            data,
        });
    }
    Ok(sections)
}

fn read_mapped_sections<R: ReadAt>(
    reader: &R,
    headers: &ElfHeaders,
    image_base: u64,
) -> Vec<Section> {
    let Ok(raw) = read_section_headers(reader, headers) else {
        return Vec::new();
    };
    let strtab = raw
        .get(usize::from(headers.header.shstrndx))
        .filter(|header| header.r#type.0 == SectionType::STRTAB.0)
        .and_then(|header| {
            let mut data = checked_alloc(header.size, reader.size()).ok()?;
            let start = if header.flags.is_alloc() {
                header.addr.saturating_sub(image_base)
            } else {
                header.offset
            };
            read_lenient(reader, start, &mut data);
            Some(data)
        })
        .unwrap_or_default();
    let names = StringTable::new(&strtab);
    let mut sections = Vec::with_capacity(raw.len());
    for header in raw {
        let length = if header.is_nobits() { 0 } else { header.size };
        let Ok(data) = checked_alloc(length, reader.size()) else {
            continue;
        };
        let mut data = data;
        let start = if header.flags.is_alloc() {
            header.addr.saturating_sub(image_base)
        } else {
            header.offset
        };
        read_lenient(reader, start, &mut data);
        sections.push(Section {
            name: names
                .get(usize::try_from(header.name_index).unwrap_or(0))
                .unwrap_or_default()
                .to_string(),
            header,
            data,
        });
    }
    sections
}

fn section_names<R: ReadAt>(
    reader: &R,
    headers: &ElfHeaders,
    raw: &[SectionHeader],
) -> Vec<alloc::string::String> {
    raw.get(usize::from(headers.header.shstrndx))
        .filter(|header| header.r#type.0 == SectionType::STRTAB.0)
        .and_then(|header| {
            let len = checked_len(header.size, reader.size()).ok()?;
            reader.read_bytes_at(header.offset, len).ok()
        })
        .map(|data| {
            let table = StringTable::new(&data);
            raw.iter()
                .map(|header| {
                    table
                        .get(usize::try_from(header.name_index).unwrap_or(0))
                        .unwrap_or_default()
                        .to_string()
                })
                .collect()
        })
        .unwrap_or_default()
}

fn read_section_headers<R: ReadAt>(reader: &R, headers: &ElfHeaders) -> Result<Vec<SectionHeader>> {
    let endian = headers.ident.data;
    let class = headers.ident.class;
    let entry_size = u64::from(headers.header.shentsize).max(SectionHeader::size(class));
    let mut raw = Vec::with_capacity(usize::from(headers.header.shnum));
    for index in 0..u64::from(headers.header.shnum) {
        let offset = headers
            .header
            .shoff
            .saturating_add(index.saturating_mul(entry_size));
        raw.push(SectionHeader::parse(reader, offset, endian, class)?);
    }
    Ok(raw)
}

/// Reads as many bytes as the source supplies and leaves the rest zero.
fn read_lenient<R: ReadAt>(reader: &R, offset: u64, buffer: &mut [u8]) {
    let mut filled = 0usize;
    while filled < buffer.len() {
        let Ok(count) = reader.read_at(offset + filled as u64, &mut buffer[filled..]) else {
            break;
        };
        if count == 0 {
            break;
        }
        filled += count;
    }
}

/// Maximum single allocation for untrusted size fields (256 MiB).
///
/// Prevents an absurdly large header field from triggering an OOM or an
/// address-sanitizer allocation-size error before the reader can reject it.
const MAX_ALLOC: u64 = 256 * 1024 * 1024;

/// Validates `length` against the source size and returns it as `usize`.
fn checked_len(length: u64, source_size: Option<u64>) -> Result<usize> {
    let cap = source_size.unwrap_or(MAX_ALLOC).min(MAX_ALLOC);
    if length > cap {
        return Err(Error::generic(
            "ELF structure size exceeds the source or the allocation limit",
        ));
    }
    Ok(usize::try_from(length).unwrap_or(usize::MAX))
}

/// Allocates a zero-filled vector after validating `length`.
fn checked_alloc(length: u64, source_size: Option<u64>) -> Result<Vec<u8>> {
    let len = checked_len(length, source_size)?;
    Ok(alloc::vec![0u8; len])
}

/// A reader that shifts every offset by a fixed base.
struct OffsetReader<'a, R: ReadAt> {
    inner: &'a R,
    base: u64,
}

impl<R: ReadAt> ReadAt for OffsetReader<'_, R> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let Some(shifted) = self.base.checked_add(offset) else {
            return Ok(0);
        };
        self.inner.read_at(shifted, buf)
    }

    fn size(&self) -> Option<u64> {
        self.inner.size().map(|size| size.saturating_sub(self.base))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Builds a minimal ELF64 file with one `PT_LOAD` segment whose size
    /// fields hold the fuzzer-found value `0x7863_6148_0003_1337`.
    fn elf_with_huge_segment_size() -> Vec<u8> {
        let mut data = vec![0u8; 64 + 56];
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 2; // ELFCLASS64
        data[5] = 1; // ELFDATA2LSB
        data[6] = 1; // EV_CURRENT
        data[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        data[18..20].copy_from_slice(&62u16.to_le_bytes()); // e_machine = EM_X86_64
        data[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        data[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        data[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        let phdr = &mut data[64..];
        phdr[0..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        phdr[32..40].copy_from_slice(&0x7863_6148_0003_1337u64.to_le_bytes()); // p_filesz
        phdr[40..48].copy_from_slice(&0x7863_6148_0003_1337u64.to_le_bytes()); // p_memsz
        data
    }

    #[test]
    fn huge_segment_size_is_rejected_not_allocated() {
        let data = elf_with_huge_segment_size();
        assert!(ElfImage::parse(&data).is_err());
        assert!(ElfImage::parse_mapped(&data).is_err());
    }
}
