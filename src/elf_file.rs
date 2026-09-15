//! Lossless ELF file container.
//!
//! [`ElfFile`] wraps an [`ElfImage`] and preserves any trailing bytes that
//! follow the last structural element in the original file. The round-trip
//! `parse → try_build` reproduces the trailing bytes verbatim.

use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use crate::elf::ElfImage;
use crate::error::Result;
use crate::reader::{ReadAt, SliceReader};

/// An [`ElfImage`] paired with trailing file bytes.
///
/// Some tools append data after the section header table. This container
/// preserves those bytes so a file dump keeps them intact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfFile {
    image: ElfImage,
    trailing: Vec<u8>,
}

impl ElfFile {
    /// Parses a file from raw bytes.
    ///
    /// The image structures are parsed and the bytes after the last structure
    /// are stored as trailing data.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the ELF structures cannot be read.
    pub fn parse(data: &[u8]) -> Result<Self> {
        Self::read_from(&SliceReader::new(data))
    }

    /// Reads a file from a positional source.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the ELF structures cannot be read.
    pub fn read_from<R: ReadAt>(reader: &R) -> Result<Self> {
        let image = ElfImage::read_from(reader, 0, crate::elf::Layout::File)?;
        let file_end = last_structure_end(&image);
        let trailing = reader
            .size()
            .and_then(|size| {
                let remaining = size.checked_sub(file_end)?;
                let len = usize::try_from(remaining).ok()?;
                reader.read_bytes_at(file_end, len).ok()
            })
            .unwrap_or_default();
        Ok(Self { image, trailing })
    }

    /// Wraps an image with no trailing data.
    #[must_use]
    pub const fn new(image: ElfImage) -> Self {
        Self {
            image,
            trailing: Vec::new(),
        }
    }

    /// Opens a file from a filesystem path.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the file cannot be opened or the ELF
    /// structures cannot be read.
    #[cfg(feature = "std")]
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        Self::read_from(&crate::reader::FileReader::open(path)?)
    }

    /// Returns the underlying image.
    #[must_use]
    pub const fn image(&self) -> &ElfImage {
        &self.image
    }

    /// Returns the underlying image for editing.
    pub fn image_mut(&mut self) -> &mut ElfImage {
        &mut self.image
    }

    /// Consumes the container and returns the image.
    #[must_use]
    pub fn into_image(self) -> ElfImage {
        self.image
    }

    /// Returns the trailing bytes.
    #[must_use]
    pub fn trailing(&self) -> &[u8] {
        &self.trailing
    }

    /// Serializes the file: the image in file layout followed by trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the image cannot be serialized.
    pub fn try_build(&self) -> Result<Vec<u8>> {
        let mut bytes = self.image.try_build()?;
        bytes.extend_from_slice(&self.trailing);
        Ok(bytes)
    }
}

impl Deref for ElfFile {
    type Target = ElfImage;

    fn deref(&self) -> &Self::Target {
        &self.image
    }
}

impl DerefMut for ElfFile {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.image
    }
}

/// Returns the file offset one past the last structural byte.
fn last_structure_end(image: &ElfImage) -> u64 {
    let mut end: u64 = 0;
    let class = image.ident().class;

    let ehsize = crate::header::ElfHeader::size(class);
    end = end.max(ehsize);

    let phentsize = crate::program::ProgramHeader::size(class);
    let phdr_end = image
        .header()
        .phoff
        .checked_add(u64::from(image.header().phnum) * phentsize)
        .unwrap_or(end);
    end = end.max(phdr_end);

    for segment in image.segments() {
        if segment.header.filesz > 0 {
            let seg_end = segment
                .header
                .offset
                .checked_add(segment.header.filesz)
                .unwrap_or(end);
            end = end.max(seg_end);
        }
    }

    for section in image.sections() {
        if !section.header.is_nobits() && section.header.size > 0 {
            let sec_end = section
                .header
                .offset
                .checked_add(section.header.size)
                .unwrap_or(end);
            end = end.max(sec_end);
        }
    }

    let shentsize = crate::section::SectionHeader::size(class);
    let shdr_end = image
        .header()
        .shoff
        .checked_add(u64::from(image.header().shnum) * shentsize)
        .unwrap_or(end);
    end = end.max(shdr_end);

    end
}
