//! ELF identification bytes and the enums derived from them.
//!
//! The first sixteen bytes of an ELF file form the identification array. This
//! module parses that array into an [`ElfIdent`] and defines the [`ElfClass`],
//! [`Endian`], and [`OsAbi`] values that the rest of the crate uses.

use crate::error::{Error, Result};

/// The ELF magic number: `0x7f`, `E`, `L`, `F`.
pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// The size of the ELF identification array in bytes.
pub const EI_NIDENT: usize = 16;

/// The address width class of an ELF object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfClass {
    /// 32-bit object with 32-bit address fields.
    Elf32,
    /// 64-bit object with 64-bit address fields.
    Elf64,
}

impl ElfClass {
    /// Parses the `EI_CLASS` byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the byte is not a known class.
    pub const fn from_byte(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Elf32),
            2 => Ok(Self::Elf64),
            other => Err(Error::invalid_class(other)),
        }
    }

    /// Returns the `EI_CLASS` byte for this class.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Elf32 => 1,
            Self::Elf64 => 2,
        }
    }

    /// Tests whether the class uses 64-bit address fields.
    #[must_use]
    pub const fn is_64bit(self) -> bool {
        matches!(self, Self::Elf64)
    }
}

/// The byte order of an ELF object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endian {
    /// Least significant byte first.
    Little,
    /// Most significant byte first.
    Big,
}

impl Endian {
    /// Parses the `EI_DATA` byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the byte is not a known data encoding.
    pub const fn from_byte(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Little),
            2 => Ok(Self::Big),
            other => Err(Error::invalid_data_encoding(other)),
        }
    }

    /// Returns the `EI_DATA` byte for this encoding.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Little => 1,
            Self::Big => 2,
        }
    }

    /// Decodes a `u16` in this byte order.
    #[must_use]
    pub const fn u16(self, bytes: [u8; 2]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        }
    }

    /// Decodes a `u32` in this byte order.
    #[must_use]
    pub const fn u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }

    /// Decodes a `u64` in this byte order.
    #[must_use]
    pub const fn u64(self, bytes: [u8; 8]) -> u64 {
        match self {
            Self::Little => u64::from_le_bytes(bytes),
            Self::Big => u64::from_be_bytes(bytes),
        }
    }

    /// Decodes an `i32` in this byte order.
    #[must_use]
    pub const fn i32(self, bytes: [u8; 4]) -> i32 {
        match self {
            Self::Little => i32::from_le_bytes(bytes),
            Self::Big => i32::from_be_bytes(bytes),
        }
    }

    /// Decodes an `i64` in this byte order.
    #[must_use]
    pub const fn i64(self, bytes: [u8; 8]) -> i64 {
        match self {
            Self::Little => i64::from_le_bytes(bytes),
            Self::Big => i64::from_be_bytes(bytes),
        }
    }

    /// Encodes a `u16` in this byte order.
    #[must_use]
    pub const fn u16_bytes(self, value: u16) -> [u8; 2] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }

    /// Encodes a `u32` in this byte order.
    #[must_use]
    pub const fn u32_bytes(self, value: u32) -> [u8; 4] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }

    /// Encodes a `u64` in this byte order.
    #[must_use]
    pub const fn u64_bytes(self, value: u64) -> [u8; 8] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }

    /// Encodes an `i64` in this byte order.
    #[must_use]
    pub const fn i64_bytes(self, value: i64) -> [u8; 8] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }
}

/// The operating-system application binary interface named in the identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OsAbi(pub u8);

impl OsAbi {
    /// UNIX System V ABI.
    pub const SYSV: Self = Self(0);
    /// HP-UX ABI.
    pub const HPUX: Self = Self(1);
    /// NetBSD ABI.
    pub const NETBSD: Self = Self(2);
    /// GNU or Linux ABI.
    pub const GNU: Self = Self(3);
    /// Sun Solaris ABI.
    pub const SOLARIS: Self = Self(6);
    /// FreeBSD ABI.
    pub const FREEBSD: Self = Self(9);

    /// Returns the raw `EI_OSABI` byte.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

/// The parsed ELF identification array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ElfIdent {
    /// The address width class.
    pub class: ElfClass,
    /// The byte order.
    pub data: Endian,
    /// The ELF header version, normally `1`.
    pub version: u8,
    /// The operating-system ABI.
    pub os_abi: OsAbi,
    /// The ABI version.
    pub abi_version: u8,
}

impl ElfIdent {
    /// Parses the sixteen-byte identification array.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the magic number, class, or data encoding is
    /// invalid.
    pub fn parse(bytes: &[u8; EI_NIDENT]) -> Result<Self> {
        if bytes[0..4] != ELF_MAGIC {
            return Err(Error::invalid_magic());
        }
        Ok(Self {
            class: ElfClass::from_byte(bytes[4])?,
            data: Endian::from_byte(bytes[5])?,
            version: bytes[6],
            os_abi: OsAbi(bytes[7]),
            abi_version: bytes[8],
        })
    }

    /// Serializes the identification array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; EI_NIDENT] {
        let mut bytes = [0u8; EI_NIDENT];
        bytes[0..4].copy_from_slice(&ELF_MAGIC);
        bytes[4] = self.class.to_byte();
        bytes[5] = self.data.to_byte();
        bytes[6] = self.version;
        bytes[7] = self.os_abi.0;
        bytes[8] = self.abi_version;
        bytes
    }
}
