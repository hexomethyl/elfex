//! Structural validation of an [`ElfImage`].

use alloc::format;
use alloc::vec::Vec;

use crate::program::SegmentType;
use crate::section::SectionType;
use crate::validation::{ValidationCode, ValidationIssue, ValidationResult};

use super::ElfImage;

impl ElfImage {
    /// Checks the structural invariants of the current model.
    ///
    /// Parsing already rejects unreadable structures. This method reports the
    /// suspicious or invalid states that a parsed or edited model can still
    /// hold, such as overlapping loadable segments or an entry point outside
    /// the mapped image.
    #[must_use]
    pub fn validate(&self) -> ValidationResult {
        let mut issues = Vec::new();
        let base = self.image_base();
        let span = self.image_span();

        let loads: Vec<_> = self
            .segments
            .iter()
            .filter(|segment| segment.header.r#type.0 == SegmentType::LOAD.0)
            .collect();
        if loads.is_empty() {
            issues.push(ValidationIssue::warning(
                ValidationCode::NoLoadSegments,
                "the object declares no loadable segment",
            ));
        }

        if self.header.entry != 0 {
            let entry = self.header.entry;
            let outside = match base.checked_add(span) {
                Some(image_end) => entry < base || entry >= image_end,
                None => true,
            };
            if outside {
                issues.push(
                    ValidationIssue::warning(
                        ValidationCode::EntryPointOutOfImage,
                        "the entry point lies outside the mapped image",
                    )
                    .with_context(format!("{entry:#x}")),
                );
            }
        }

        let mut ranges: Vec<(u64, u64, usize)> = loads
            .iter()
            .enumerate()
            .map(|(index, segment)| {
                (
                    segment.header.vaddr,
                    segment.header.vaddr.saturating_add(segment.header.memsz),
                    index,
                )
            })
            .collect();
        ranges.sort_unstable();
        for pair in ranges.windows(2) {
            let (_, first_end, first_index) = pair[0];
            let (second_start, _, second_index) = pair[1];
            if first_end > second_start {
                issues.push(
                    ValidationIssue::error(
                        ValidationCode::OverlappingSegments,
                        "two loadable segments overlap in memory",
                    )
                    .with_context(format!("segments {first_index} and {second_index}")),
                );
            }
        }

        for (index, segment) in loads.iter().enumerate() {
            let header = &segment.header;
            if header.filesz > header.memsz {
                issues.push(
                    ValidationIssue::error(
                        ValidationCode::SegmentFileRangeOutOfBounds,
                        "a segment declares more file bytes than memory bytes",
                    )
                    .with_context(format!("segment {index}")),
                );
            }
            let alignment = header.align;
            if alignment > 1
                && header.offset % alignment != header.vaddr % alignment
                && header.filesz > 0
            {
                issues.push(
                    ValidationIssue::warning(
                        ValidationCode::SegmentVaddrMisaligned,
                        "a segment file offset is not congruent with its virtual address",
                    )
                    .with_context(format!("segment {index}")),
                );
            }
        }

        if self.header.shnum != 0 {
            let index = usize::from(self.header.shstrndx);
            let valid = self
                .sections
                .get(index)
                .is_some_and(|section| section.header.r#type.0 == SectionType::STRTAB.0);
            if !valid {
                issues.push(ValidationIssue::warning(
                    ValidationCode::InvalidStringTableIndex,
                    "the section-name string table index names no string table",
                ));
            }
        }

        ValidationResult::new(issues)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::builder::ElfBuilder;
    use crate::header::{ElfType, Machine};
    use crate::program::{SegmentFlags, SegmentType};
    use crate::validation::{ValidationCode, ValidationLevel};

    use super::ElfImage;

    fn code_flags() -> SegmentFlags {
        SegmentFlags(SegmentFlags::READ | SegmentFlags::EXECUTE)
    }

    /// Two abutting loadable segments, an entry point inside the second, and a
    /// section-name string table the header names correctly.
    fn well_formed() -> ElfImage {
        ElfBuilder::new()
            .machine(Machine::X86_64)
            .elf_type(ElfType::Exec)
            .entry(0x40_1000)
            .add_load(
                0x40_0000,
                SegmentFlags(SegmentFlags::READ),
                vec![0u8; 0x1000],
            )
            .add_load(0x40_1000, code_flags(), vec![0xf4, 0xc3])
            .build()
    }

    fn codes(image: &ElfImage) -> Vec<ValidationCode> {
        image
            .validate()
            .issues
            .iter()
            .map(|issue| issue.code)
            .collect()
    }

    #[test]
    fn a_well_formed_image_reports_no_issues() {
        let result = well_formed().validate();
        assert!(result.is_ok(), "unexpected issues: {:?}", result.issues);
    }

    #[test]
    fn an_object_with_no_loadable_segment_is_flagged() {
        let mut image = well_formed();
        image
            .segments_mut()
            .retain(|segment| segment.header.r#type.0 != SegmentType::LOAD.0);
        assert!(codes(&image).contains(&ValidationCode::NoLoadSegments));
    }

    #[test]
    fn an_entry_point_outside_the_mapped_image_is_flagged() {
        let mut image = well_formed();
        image.header_mut().entry = 0xdead_beef;
        let issues = image.validate().issues;
        let issue = issues
            .iter()
            .find(|issue| issue.code == ValidationCode::EntryPointOutOfImage)
            .expect("an out-of-image entry point is reported");
        assert_eq!(issue.level, ValidationLevel::Warning);
        assert_eq!(issue.context.as_deref(), Some("0xdeadbeef"));
    }

    /// A zero entry point means "no entry", not "address zero", so it must not
    /// be reported as lying outside the image.
    #[test]
    fn a_zero_entry_point_is_not_flagged() {
        let mut image = well_formed();
        image.header_mut().entry = 0;
        assert!(!codes(&image).contains(&ValidationCode::EntryPointOutOfImage));
    }

    #[test]
    fn overlapping_loadable_segments_are_an_error() {
        let mut image = well_formed();
        image.segments_mut()[0].header.memsz = 0x2000;
        let issues = image.validate().issues;
        let issue = issues
            .iter()
            .find(|issue| issue.code == ValidationCode::OverlappingSegments)
            .expect("an overlap is reported");
        assert_eq!(issue.level, ValidationLevel::Error);
        assert!(
            issue.context.is_some(),
            "the issue should name the overlapping segments"
        );
        assert!(!image.validate().is_ok(), "an error fails validation");
    }

    #[test]
    fn a_segment_claiming_more_file_than_memory_bytes_is_an_error() {
        let mut image = well_formed();
        image.segments_mut()[1].header.filesz = 0x4000;
        image.segments_mut()[1].header.memsz = 0x10;
        let issues = image.validate().issues;
        let issue = issues
            .iter()
            .find(|issue| issue.code == ValidationCode::SegmentFileRangeOutOfBounds)
            .expect("filesz beyond memsz is reported");
        assert_eq!(issue.level, ValidationLevel::Error);
    }

    /// A loader maps whole pages, so `p_offset` and `p_vaddr` must agree
    /// modulo `p_align`.
    #[test]
    fn a_segment_offset_not_congruent_with_its_address_is_flagged() {
        let mut image = well_formed();
        let segment = &mut image.segments_mut()[1];
        segment.header.align = 0x1000;
        segment.header.filesz = 2;
        segment.header.offset = segment.header.vaddr % 0x1000 + 1;
        assert!(codes(&image).contains(&ValidationCode::SegmentVaddrMisaligned));
    }

    /// The congruence check only applies to segments with file bytes; a
    /// `.bss`-only segment has no file range to be congruent with.
    #[test]
    fn an_empty_file_range_is_not_checked_for_congruence() {
        let mut image = well_formed();
        let segment = &mut image.segments_mut()[1];
        segment.header.align = 0x1000;
        segment.header.filesz = 0;
        segment.header.offset = 1;
        assert!(!codes(&image).contains(&ValidationCode::SegmentVaddrMisaligned));
    }

    #[test]
    fn a_section_name_index_naming_no_string_table_is_flagged() {
        let mut image = well_formed();
        image.header_mut().shnum = 1;
        image.header_mut().shstrndx = u16::MAX;
        assert!(codes(&image).contains(&ValidationCode::InvalidStringTableIndex));
    }

    /// With no section headers at all there is no string-table index to check.
    #[test]
    fn no_section_headers_means_no_string_table_check() {
        let mut image = well_formed();
        image.header_mut().shnum = 0;
        image.header_mut().shstrndx = u16::MAX;
        assert!(!codes(&image).contains(&ValidationCode::InvalidStringTableIndex));
    }
}
