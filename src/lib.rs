//! A bespoke ELF reader, editor, and builder.
//!
//! `elfex` parses, edits, and rebuilds 32-bit and 64-bit ELF objects. It has no
//! third-party dependencies. It is `no_std` with `extern crate alloc`; the
//! default `std` feature adds file entry points and `std::io` error support.
//!
//! The crate mirrors the parse, edit, rebuild, and mapped-image capabilities of
//! a Portable Executable reader. ELF has no relative virtual address, so `elfex`
//! uses an image-relative offset `ioff = vaddr - image_base` as the direct
//! analog of a PE relative virtual address.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub mod builder;
pub mod dynamic;
pub mod elf;
pub mod elf_file;
pub mod error;
pub mod header;
pub mod ident;
pub mod notes;
mod parse_utils;
pub mod program;
pub mod reader;
pub mod reloc;
pub mod section;
pub mod strtab;
pub mod symbol;
pub mod tls;
pub mod validation;

pub use builder::ElfBuilder;
pub use dynamic::{DynTag, DynamicEntry, DynamicTable};
pub use elf::ElfImage;
pub use elf_file::ElfFile;
pub use error::{Error, ErrorKind, Result};
pub use header::{ElfHeader, ElfHeaders, ElfType, Machine};
pub use ident::{ElfClass, ElfIdent, Endian, OsAbi};
pub use notes::Note;
pub use program::{ProgramHeader, Segment, SegmentFlags, SegmentType};
pub use reader::{ReadAt, SliceReader, VecReader};
pub use reloc::{RelocKind, RelocationEntry, RelocationSection};
pub use section::{Section, SectionFlags, SectionHeader, SectionType};
pub use strtab::StringTable;
pub use symbol::{Symbol, SymbolBind, SymbolTable, SymbolType, SymbolVisibility};
pub use tls::TlsInfo;

#[cfg(feature = "std")]
pub use reader::FileReader;

/// Truncates a 64-bit field to its 32-bit on-disk width for an ELF32 object.
///
/// The 32-bit ELF classes define these header fields as 32 bits wide, so a
/// well-formed ELF32 value always fits. The builder and parser keep the values
/// in range.
#[expect(
    clippy::cast_possible_truncation,
    reason = "ELF32 header fields are defined as 32 bits wide"
)]
pub(crate) const fn low32(value: u64) -> u32 {
    value as u32
}
