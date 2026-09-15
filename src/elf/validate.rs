//! Structural validation of an [`ElfImage`].

use alloc::format;
use alloc::vec::Vec;

use crate::program::SegmentType;
use crate::section::SectionType;
use crate::validation::{ValidationCode, ValidationIssue, ValidationLevel, ValidationResult};

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

        let _ = ValidationLevel::Error;
        ValidationResult::new(issues)
    }
}
