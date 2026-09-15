//! ELF structural validation issues.
//!
//! [`crate::ElfImage::validate`] produces a [`ValidationResult`]. This module
//! defines the issue types that make up that result.

use alloc::string::String;
use alloc::vec::Vec;

/// The severity of one validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValidationLevel {
    /// Suspicious state that can still be accepted.
    Warning,
    /// Invalid state that can prevent correct processing.
    Error,
}

/// The structural check that produced one validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ValidationCode {
    /// The ELF magic number was invalid.
    InvalidMagic,
    /// The ELF class was unsupported.
    UnsupportedClass,
    /// The ELF data encoding was unsupported.
    UnsupportedDataEncoding,
    /// The object type was invalid.
    InvalidType,
    /// The entry point fell outside the mapped image.
    EntryPointOutOfImage,
    /// Two loadable segments overlapped.
    OverlappingSegments,
    /// A segment file range fell outside the file.
    SegmentFileRangeOutOfBounds,
    /// A segment virtual address was not congruent with its file offset.
    SegmentVaddrMisaligned,
    /// The program header count exceeded the file size.
    InvalidProgramHeaderCount,
    /// A section file range fell outside the file.
    SectionFileRangeOutOfBounds,
    /// The section-name string table index was invalid.
    InvalidStringTableIndex,
    /// The object declared no loadable segment.
    NoLoadSegments,
}

/// One structural validation finding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValidationIssue {
    /// The issue severity.
    pub level: ValidationLevel,
    /// The check that produced the issue.
    pub code: ValidationCode,
    /// A human-readable description.
    pub message: String,
    /// Optional location context.
    pub context: Option<String>,
}

impl ValidationIssue {
    /// Creates a warning-severity issue.
    #[must_use]
    pub fn warning(code: ValidationCode, message: impl Into<String>) -> Self {
        Self {
            level: ValidationLevel::Warning,
            code,
            message: message.into(),
            context: None,
        }
    }

    /// Creates an error-severity issue.
    #[must_use]
    pub fn error(code: ValidationCode, message: impl Into<String>) -> Self {
        Self {
            level: ValidationLevel::Error,
            code,
            message: message.into(),
            context: None,
        }
    }

    /// Attaches location context.
    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }
}

/// The complete set of structural validation findings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationResult {
    /// Every finding, in check order.
    pub issues: Vec<ValidationIssue>,
}

impl ValidationResult {
    /// Creates a result from a list of findings.
    #[must_use]
    pub const fn new(issues: Vec<ValidationIssue>) -> Self {
        Self { issues }
    }

    /// Returns every finding.
    #[must_use]
    pub fn issues(&self) -> &[ValidationIssue] {
        &self.issues
    }

    /// Tests whether the object has no findings.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.issues.is_empty()
    }

    /// Tests whether the object has at least one error-severity finding.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.issues
            .iter()
            .any(|issue| issue.level == ValidationLevel::Error)
    }

    /// Returns the error-severity findings.
    #[must_use = "inspecting the errors does not consume them"]
    pub fn errors(&self) -> impl Iterator<Item = &ValidationIssue> {
        self.issues
            .iter()
            .filter(|issue| issue.level == ValidationLevel::Error)
    }

    /// Returns the warning-severity findings.
    #[must_use = "inspecting the warnings does not consume them"]
    pub fn warnings(&self) -> impl Iterator<Item = &ValidationIssue> {
        self.issues
            .iter()
            .filter(|issue| issue.level == ValidationLevel::Warning)
    }
}
