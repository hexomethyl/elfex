//! Byte-level editing of an [`ElfImage`] through image-relative offsets.

use super::ElfImage;

impl ElfImage {
    /// Replaces bytes at an image-relative offset.
    ///
    /// The write updates the covering loadable segment. It also updates every
    /// allocated section that covers the same virtual address, so a later
    /// serialization of either view sees the change.
    ///
    /// Returns `None` when the offset or the replacement range has no file
    /// bytes in the covering segment.
    pub fn write_at_ioff(&mut self, ioff: u64, data: &[u8]) -> Option<()> {
        let vaddr = self.image_base().checked_add(ioff)?;
        {
            let segment = self.segments.iter_mut().find(|segment| {
                segment.header.r#type.0 == crate::program::SegmentType::LOAD.0
                    && segment.contains_vaddr(vaddr)
            })?;
            let start = usize::try_from(vaddr - segment.header.vaddr).ok()?;
            let end = start.checked_add(data.len())?;
            segment.data.get_mut(start..end)?.copy_from_slice(data);
        }
        for section in &mut self.sections {
            if !section.contains_vaddr(vaddr) || section.header.is_nobits() {
                continue;
            }
            let Some(start) = usize::try_from(vaddr - section.header.addr).ok() else {
                continue;
            };
            let Some(end) = start.checked_add(data.len()) else {
                continue;
            };
            if let Some(target) = section.data.get_mut(start..end) {
                target.copy_from_slice(data);
            }
        }
        Some(())
    }
}
