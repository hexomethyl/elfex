//! ELF note records.
//!
//! Notes carry auxiliary metadata such as the GNU build identifier. Each note
//! stores a name, a numeric type, and a descriptor. [`Note::parse_all`] walks a
//! note sequence from a `PT_NOTE` segment or `SHT_NOTE` section.

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::ident::Endian;
use crate::parse_utils::array4;

/// The note name for GNU extensions.
pub const NAME_GNU: &str = "GNU";

/// The GNU build-identifier note type.
pub const NT_GNU_BUILD_ID: u32 = 3;

/// One parsed note record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Note {
    /// The note name, normally `"GNU"` or `"Linux"`.
    pub name: String,
    /// The owner-defined note type.
    pub note_type: u32,
    /// The note payload.
    pub descriptor: Vec<u8>,
}

impl Note {
    /// Returns the note name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the owner-defined note type.
    #[must_use]
    pub const fn note_type(&self) -> u32 {
        self.note_type
    }

    /// Returns the note payload.
    #[must_use]
    pub fn descriptor(&self) -> &[u8] {
        &self.descriptor
    }

    /// Tests whether this note is a GNU note of `note_type`.
    #[must_use]
    pub fn is_gnu(&self, note_type: u32) -> bool {
        self.name == NAME_GNU && self.note_type == note_type
    }

    /// Parses every complete note in `data`.
    ///
    /// Each note header stores a name size, a descriptor size, and a type. The
    /// name and descriptor are padded to four-byte boundaries. Parsing stops at
    /// the first record that does not fit the remaining bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when a complete note header or payload is not valid
    /// UTF-8 or the header sizes are not representable.
    pub fn parse_all(data: &[u8], endian: Endian) -> Result<Vec<Note>> {
        let mut notes = Vec::new();
        let mut offset = 0usize;
        while data.len() - offset >= 12 {
            let namesz = endian.u32(array4(data, offset)?);
            let descsz = endian.u32(array4(data, offset + 4)?);
            let note_type = endian.u32(array4(data, offset + 8)?);
            let name_len = usize::try_from(namesz)
                .map_err(|_| Error::invalid_section("note name size is out of range"))?;
            let desc_len = usize::try_from(descsz)
                .map_err(|_| Error::invalid_section("note descriptor size is out of range"))?;
            let name_end = offset + 12 + name_len;
            let desc_start = name_end + padding4(name_len);
            let desc_end = desc_start + desc_len;
            if desc_end > data.len() {
                break;
            }
            let mut name = &data[name_end - name_len..name_end];
            if name.last() == Some(&0) {
                name = &name[..name.len() - 1];
            }
            notes.push(Note {
                name: core::str::from_utf8(name)
                    .map_err(|_| Error::invalid_utf8())?
                    .to_string(),
                note_type,
                descriptor: data[desc_start..desc_end].to_vec(),
            });
            offset = desc_end + padding4(desc_len);
        }
        Ok(notes)
    }
}

const fn padding4(length: usize) -> usize {
    (4 - (length % 4)) % 4
}
