//! Serializing an [`ElfImage`] to file and mapped layouts.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::header::ElfHeader;
use crate::program::{ProgramHeader, SegmentType};
use crate::reloc::{RelocKind, relocation_kind, relocation_width};
use crate::section::{Section, SectionFlags, SectionHeader, SectionType};

use super::ElfImage;

/// Upper bound for a serialized or mapped image, shared by every layout
/// writer. Untrusted header fields can claim spans near `u64::MAX`; this cap
/// rejects them before any allocation is attempted.
const MAX_IMAGE: usize = 256 * 1024 * 1024;

impl ElfImage {
    /// Serializes the image in ELF file layout.
    ///
    /// The operation places the ELF header, the program header table, the
    /// segment data, the section data, and the section header table. Each
    /// loadable segment keeps `p_offset` congruent to `p_vaddr` modulo
    /// `p_align`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the current model cannot be laid out.
    pub fn try_build(&self) -> Result<Vec<u8>> {
        let class = self.ident.class;
        let endian = self.ident.data;

        let ehsize = ElfHeader::size(class);
        let phentsize = ProgramHeader::size(class);
        let mut phdrs: Vec<ProgramHeader> =
            self.segments.iter().map(|segment| segment.header).collect();
        let mut sections = self.sections.clone();

        let ehsize_usize =
            usize::try_from(ehsize).map_err(|_| Error::generic("image is too large"))?;
        let mut out = alloc::vec![0u8; ehsize_usize];
        let phoff = ehsize;
        let mut cursor = phoff + phentsize * u64::try_from(phdrs.len()).unwrap_or(u64::MAX);

        for (index, segment) in self.segments.iter().enumerate() {
            let writable = usize::try_from(segment.header.filesz)
                .map_or(0, |filesz| filesz.min(segment.data.len()));
            if writable == 0 {
                phdrs[index].offset = 0;
                phdrs[index].filesz = 0;
                continue;
            }
            let alignment = if segment.header.r#type.0 == SegmentType::LOAD.0 {
                segment.header.align.max(1)
            } else {
                1
            };
            cursor = congruent(cursor, segment.header.vaddr, alignment);
            phdrs[index].offset = cursor;
            phdrs[index].filesz = u64::try_from(writable).unwrap_or(0);
            write_at(&mut out, cursor, &segment.data[..writable])?;
            cursor += u64::try_from(writable).unwrap_or(0);
        }

        let mut shstrndx = 0u16;
        if !sections.is_empty() {
            shstrndx = ensure_shstrtab(&mut sections);
            assign_name_offsets(&mut sections);
            for section in &mut sections {
                if section.header.is_nobits() {
                    continue;
                }
                if section.data.is_empty() {
                    section.header.size = 0;
                    continue;
                }
                cursor = super::align_up(cursor, section.header.addralign.max(1));
                section.header.offset = cursor;
                section.header.size = section.data.len() as u64;
                write_at(&mut out, cursor, &section.data)?;
                cursor += section.data.len() as u64;
            }
        }

        let mut table = Vec::new();
        for phdr in &phdrs {
            phdr.write(&mut table, endian, class);
        }
        write_at(&mut out, phoff, &table)?;

        let mut header = self.header;
        header.phoff = phoff;
        header.ehsize = u16::try_from(ehsize).unwrap_or(0);
        header.phentsize = u16::try_from(phentsize).unwrap_or(0);
        header.phnum = u16::try_from(phdrs.len())
            .map_err(|_| Error::generic("too many program headers for one table"))?;
        header.shnum = u16::try_from(sections.len())
            .map_err(|_| Error::generic("too many sections for one table"))?;
        header.shstrndx = shstrndx;
        header.shentsize = u16::try_from(SectionHeader::size(class)).unwrap_or(0);

        if sections.is_empty() {
            header.shoff = 0;
        } else {
            let shoff = super::align_up(cursor, 8);
            header.shoff = shoff;
            let mut table = Vec::new();
            for section in &sections {
                section.header.write(&mut table, endian, class);
            }
            write_at(&mut out, shoff, &table)?;
        }

        let mut serialized = Vec::new();
        header.write(&mut serialized);
        let header_end = usize::try_from(ehsize).unwrap_or(0);
        out[..header_end].copy_from_slice(&serialized);
        Ok(out)
    }

    /// Serializes the image in ELF file layout.
    ///
    /// # Panics
    ///
    /// Panics when [`ElfImage::try_build`] fails. Use `try_build` for
    /// recoverable serialization.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        self.try_build().expect("the ELF image serializes")
    }

    /// Serializes the image as a loader memory image at its preferred base.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the mapped layout cannot be formed.
    pub fn to_mapped_image(&self) -> Result<Vec<u8>> {
        self.to_mapped_image_at(self.image_base())
    }

    /// Serializes the image as a loader memory image at `base`.
    ///
    /// Each loadable segment is placed at `p_vaddr - image_base` and zero-filled
    /// to its memory size. When `base` differs from the preferred base, relative
    /// relocations add the base change to every stored pointer.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the mapped layout cannot be formed.
    pub fn to_mapped_image_at(&self, base: u64) -> Result<Vec<u8>> {
        let image_base = self.image_base();
        let span = usize::try_from(self.image_span())
            .map_err(|_| Error::generic("mapped image is too large"))?;
        if span > MAX_IMAGE {
            return Err(Error::generic(
                "mapped image exceeds the 256 MiB layout limit",
            ));
        }
        let mut image = alloc::vec![0u8; span];
        for segment in &self.segments {
            if segment.header.r#type.0 != SegmentType::LOAD.0 {
                continue;
            }
            let Some(start) = segment.header.vaddr.checked_sub(image_base) else {
                continue;
            };
            let Ok(start) = usize::try_from(start) else {
                continue;
            };
            let count = segment.data.len().min(image.len().saturating_sub(start));
            image[start..start + count].copy_from_slice(&segment.data[..count]);
        }
        if base != image_base {
            self.apply_relative_relocations(&mut image, base)?;
        }
        Ok(image)
    }

    fn apply_relative_relocations(&self, image: &mut [u8], base: u64) -> Result<()> {
        let delta = base.wrapping_sub(self.image_base());
        let machine = self.header.machine;
        let endian = self.ident.data;
        for table in self.relocations()? {
            for entry in table.entries() {
                if relocation_kind(machine, entry.r_type) != RelocKind::Relative {
                    continue;
                }
                let Some(width) = relocation_width(machine, entry.r_type) else {
                    continue;
                };
                let Some(offset) = entry.offset.checked_sub(self.image_base()) else {
                    continue;
                };
                let Ok(start) = usize::try_from(offset) else {
                    continue;
                };
                let end = start + usize::from(width);
                if end > image.len() {
                    continue;
                }
                let stored = match width {
                    4 => u64::from(endian.u32(read_array4(&image[start..end]))),
                    8 => endian.u64(read_array8(&image[start..end])),
                    _ => continue,
                };
                let relocated = stored.wrapping_add(delta);
                match width {
                    4 => image[start..end]
                        .copy_from_slice(&endian.u32_bytes(crate::low32(relocated))),
                    8 => image[start..end].copy_from_slice(&endian.u64_bytes(relocated)),
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

/// Finds the first file offset at or after `cursor` congruent to `vaddr`.
///
/// Saturates instead of overflowing when untrusted `p_vaddr` or `p_align`
/// values push the result past `u64::MAX`.
fn congruent(cursor: u64, vaddr: u64, alignment: u64) -> u64 {
    if alignment <= 1 {
        return cursor;
    }
    let target = vaddr % alignment;
    let current = cursor % alignment;
    match current.cmp(&target) {
        core::cmp::Ordering::Equal => cursor,
        core::cmp::Ordering::Less => cursor.saturating_add(target - current),
        core::cmp::Ordering::Greater => cursor.saturating_add(alignment - (current - target)),
    }
}

/// Ensures a `.shstrtab` section exists and returns its index.
fn ensure_shstrtab(sections: &mut Vec<Section>) -> u16 {
    if let Some(index) = sections.iter().position(|section| {
        section.name == ".shstrtab" && section.header.r#type.0 == SectionType::STRTAB.0
    }) {
        return u16::try_from(index).unwrap_or(0);
    }
    sections.push(Section {
        header: SectionHeader {
            name_index: 0,
            r#type: SectionType::STRTAB,
            flags: SectionFlags(0),
            addr: 0,
            offset: 0,
            size: 0,
            link: 0,
            info: 0,
            addralign: 1,
            entsize: 0,
        },
        name: ".shstrtab".into(),
        data: Vec::new(),
    });
    u16::try_from(sections.len() - 1).unwrap_or(0)
}

/// Builds the section-name blob and patches every `sh_name`.
fn assign_name_offsets(sections: &mut [Section]) {
    let mut blob: Vec<u8> = Vec::new();
    blob.push(0);
    let mut offsets = Vec::with_capacity(sections.len());
    for section in sections.iter() {
        offsets.push(crate::low32(u64::try_from(blob.len()).unwrap_or(0)));
        blob.extend_from_slice(section.name.as_bytes());
        blob.push(0);
    }
    for (section, offset) in sections.iter_mut().zip(offsets) {
        section.header.name_index = offset;
        if section.header.r#type.0 == SectionType::STRTAB.0 && section.name == ".shstrtab" {
            section.data.clone_from(&blob);
            section.header.size = blob.len() as u64;
        }
    }
}

fn write_at(out: &mut Vec<u8>, offset: u64, bytes: &[u8]) -> Result<()> {
    let start = usize::try_from(offset).map_err(|_| Error::generic("image is too large"))?;
    let end = start
        .checked_add(bytes.len())
        .ok_or_else(|| Error::generic("image is too large"))?;
    if end > MAX_IMAGE {
        return Err(Error::generic(
            "serialized image exceeds the 256 MiB layout limit",
        ));
    }
    if out.len() < end {
        out.resize(end, 0);
    }
    out[start..end].copy_from_slice(bytes);
    Ok(())
}

fn read_array4(bytes: &[u8]) -> [u8; 4] {
    [bytes[0], bytes[1], bytes[2], bytes[3]]
}

fn read_array8(bytes: &[u8]) -> [u8; 8] {
    [
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]
}
