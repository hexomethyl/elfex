//! Shared byte-extraction helpers for fixed-size field decoding.
//!
//! The table parsers slice fixed-size arrays out of section bytes before they
//! decode them with an [`crate::ident::Endian`]. These helpers keep the bounds
//! checks in one place.

use crate::error::{Error, Result};

/// Extracts two bytes at `offset`.
pub(crate) const fn array2(data: &[u8], offset: usize) -> Result<[u8; 2]> {
    if offset + 2 > data.len() {
        return Err(Error::buffer_too_small(
            2,
            data.len().saturating_sub(offset),
        ));
    }
    Ok([data[offset], data[offset + 1]])
}

/// Extracts four bytes at `offset`.
pub(crate) const fn array4(data: &[u8], offset: usize) -> Result<[u8; 4]> {
    if offset + 4 > data.len() {
        return Err(Error::buffer_too_small(
            4,
            data.len().saturating_sub(offset),
        ));
    }
    Ok([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Extracts eight bytes at `offset`.
pub(crate) const fn array8(data: &[u8], offset: usize) -> Result<[u8; 8]> {
    if offset + 8 > data.len() {
        return Err(Error::buffer_too_small(
            8,
            data.len().saturating_sub(offset),
        ));
    }
    Ok([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}
