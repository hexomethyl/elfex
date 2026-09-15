//! The ELF image container.
//!
//! [`ElfImage`] owns the parsed headers, segments, and sections of one ELF
//! object. Its submodules split the container's behavior:
//!
//! - `parse` reads the container from file or mapped layouts.
//! - `inspect` exposes addresses, image-relative offsets, and derived tables.
//! - `build` serializes the container to file and mapped layouts.
//! - `edit` writes bytes through image-relative offsets.
//! - `validate` checks structural invariants.

mod build;
mod edit;
mod inspect;
mod parse;
mod validate;

pub use parse::Layout;

use alloc::vec::Vec;

use crate::header::ElfHeader;
use crate::ident::ElfIdent;
use crate::program::Segment;
use crate::section::Section;

/// A parsed ELF object with its segments and sections.
///
/// The runtime map unit is the `PT_LOAD` segment. Sections are a secondary
/// link-time view used for symbol, relocation, and note parsing. Both views are
/// optional at run time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfImage {
    pub(crate) ident: ElfIdent,
    pub(crate) header: ElfHeader,
    pub(crate) segments: Vec<Segment>,
    pub(crate) sections: Vec<Section>,
    pub(crate) runtime_base: u64,
}

impl ElfImage {
    /// Returns the ELF identification.
    #[must_use]
    pub const fn ident(&self) -> ElfIdent {
        self.ident
    }

    /// Returns the ELF file header.
    #[must_use]
    pub const fn header(&self) -> &ElfHeader {
        &self.header
    }

    /// Returns the mutable ELF file header.
    pub fn header_mut(&mut self) -> &mut ElfHeader {
        &mut self.header
    }

    /// Returns the parsed segments in program-header order.
    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Returns the mutable segments in program-header order.
    pub fn segments_mut(&mut self) -> &mut Vec<Segment> {
        &mut self.segments
    }

    /// Returns the parsed sections in section-header order.
    #[must_use]
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// Returns the mutable sections in section-header order.
    pub fn sections_mut(&mut self) -> &mut Vec<Section> {
        &mut self.sections
    }
}

/// The address geometry derived from the loadable segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ImageGeometry {
    /// The preferred image base.
    pub base: u64,
    /// The page size used for rounding.
    pub page: u64,
    /// The mapped image size relative to the base.
    pub span: u64,
}

/// Computes the image geometry from `(vaddr, memsz, align)` load records.
pub(crate) fn geometry(loads: impl Iterator<Item = (u64, u64, u64)>) -> ImageGeometry {
    let mut page: u64 = 0x1000;
    let mut min_vaddr: Option<u64> = None;
    let mut max_end: u64 = 0;
    for (vaddr, memsz, align) in loads {
        if memsz == 0 {
            continue;
        }
        min_vaddr = Some(min_vaddr.map_or(vaddr, |current| current.min(vaddr)));
        max_end = max_end.max(vaddr.saturating_add(memsz));
        if align > 1 {
            page = page.max(align);
        }
    }
    let Some(min_vaddr) = min_vaddr else {
        return ImageGeometry {
            base: 0,
            page,
            span: 0,
        };
    };
    let base = min_vaddr - (min_vaddr % page);
    let span = align_up(max_end, page).saturating_sub(base);
    ImageGeometry { base, page, span }
}

/// Computes the smallest multiple of `alignment` that is at least `value`.
///
/// Saturates instead of overflowing when `value` sits near `u64::MAX`, as
/// untrusted `p_vaddr + p_memsz` combinations can produce.
pub(crate) const fn align_up(value: u64, alignment: u64) -> u64 {
    if alignment <= 1 {
        return value;
    }
    let remainder = value % alignment;
    if remainder == 0 {
        value
    } else {
        value.saturating_add(alignment - remainder)
    }
}
