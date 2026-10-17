use super::invalid;
use std::{io, mem, slice};

/// Initialized storage aligned for all pointer-bearing Windows structures used
/// by this module. The logical byte length is separate from rounded capacity.
pub(super) struct Buffer {
    words: Vec<usize>,
    len: usize,
}

impl Buffer {
    pub(super) fn new(len: usize) -> io::Result<Self> {
        if len == 0 || len > 65_536 {
            return Err(invalid());
        }
        let word = mem::size_of::<usize>();
        let count = len.checked_add(word - 1).ok_or_else(invalid)? / word;
        Ok(Self {
            words: vec![0; count],
            len,
        })
    }

    pub(super) fn bytes(&self) -> &[u8] {
        // SAFETY: all words are initialized, u8 has alignment one, and len is
        // bounded by this allocation's byte capacity in new().
        unsafe { slice::from_raw_parts(self.words.as_ptr().cast(), self.len) }
    }

    pub(super) fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as above, with exclusive access to the allocation.
        unsafe { slice::from_raw_parts_mut(self.words.as_mut_ptr().cast(), self.len) }
    }

    pub(super) fn as_ptr(&self) -> *const std::ffi::c_void {
        self.words.as_ptr().cast()
    }

    pub(super) fn as_mut_ptr(&mut self) -> *mut std::ffi::c_void {
        self.words.as_mut_ptr().cast()
    }
}

pub(super) fn u16_at(bytes: &[u8], at: usize) -> io::Result<u16> {
    let end = at.checked_add(2).ok_or_else(invalid)?;
    Ok(u16::from_le_bytes(
        bytes
            .get(at..end)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}

pub(super) fn u32_at(bytes: &[u8], at: usize) -> io::Result<u32> {
    let end = at.checked_add(4).ok_or_else(invalid)?;
    Ok(u32::from_le_bytes(
        bytes
            .get(at..end)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
