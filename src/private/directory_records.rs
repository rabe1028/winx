//! Bounds-checked decoding of one native directory record, without filesystem IO.
use std::io;

#[derive(Clone, Copy)]
pub(super) struct Layout {
    pub(super) length: usize,
    pub(super) name: usize,
}

pub(super) struct Record {
    pub(super) name: Vec<u16>,
    pub(super) next: Option<usize>,
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid Windows directory record",
    )
}

fn u32_at(bytes: &[u8], at: usize) -> io::Result<usize> {
    let end = at.checked_add(4).ok_or_else(invalid)?;
    let value = bytes.get(at..end).ok_or_else(invalid)?;
    usize::try_from(u32::from_le_bytes(value.try_into().map_err(|_| invalid())?))
        .map_err(|_| invalid())
}

pub(super) fn decode(bytes: &[u8], layout: Layout) -> io::Result<Record> {
    let next = u32_at(bytes, 0)?;
    let length = u32_at(bytes, layout.length)?;
    if length == 0 || length > 510 || length % 2 != 0 {
        return Err(invalid());
    }
    let end = layout.name.checked_add(length).ok_or_else(invalid)?;
    let raw_name = bytes.get(layout.name..end).ok_or_else(invalid)?;
    if next != 0
        && (next % 8 != 0
            || next < end
            || bytes.get(next..).map_or(true, |remaining| {
                remaining.len() < layout.name.saturating_add(2)
            }))
    {
        return Err(invalid());
    }
    let name: Vec<u16> = raw_name
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    // Preserve arbitrary Windows names (including unpaired UTF-16 and names
    // which a later managed writer rejects). Never return a path or NUL.
    if name.iter().any(|unit| matches!(unit, 0 | 47 | 92)) {
        return Err(invalid());
    }
    Ok(Record {
        name,
        next: if next == 0 { None } else { Some(next) },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAYOUT: Layout = Layout {
        length: 60,
        name: 104,
    };

    fn record(name: &[u16], next: u32, total: usize) -> Vec<u8> {
        let mut bytes = vec![0; total];
        bytes[..4].copy_from_slice(&next.to_le_bytes());
        bytes[60..64].copy_from_slice(&((name.len() * 2) as u32).to_le_bytes());
        for (slot, unit) in bytes[104..].chunks_exact_mut(2).zip(name) {
            slot.copy_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn names_preserve_unicode_surrogates_and_nonmanaged_spelling() {
        for name in [
            vec![0x65e5, 32, 0xd800],
            vec![46],
            vec![46, 46],
            vec![65, 46],
        ] {
            let decoded = decode(&record(&name, 0, 104 + name.len() * 2), LAYOUT).unwrap();
            assert_eq!(decoded.name, name);
            assert_eq!(decoded.next, None);
        }
    }

    #[test]
    fn next_record_is_forward_aligned_and_has_room_for_its_header() {
        assert_eq!(
            decode(&record(&[65], 112, 218), LAYOUT).unwrap().next,
            Some(112)
        );
        for next in [8, 104, 108, 216, u32::MAX] {
            assert!(decode(&record(&[65], next, 218), LAYOUT).is_err());
        }
    }

    #[test]
    fn rejects_truncated_odd_oversized_and_empty_names() {
        for length in [0_u32, 1, 3, 512, u32::MAX] {
            let mut bytes = record(&[65], 0, 616);
            bytes[60..64].copy_from_slice(&length.to_le_bytes());
            assert!(decode(&bytes, LAYOUT).is_err());
        }
        for length in [0, 3, 63, 104, 105] {
            assert!(decode(&record(&[65], 0, 106)[..length], LAYOUT).is_err());
        }
        let name = vec![65; 255];
        assert_eq!(decode(&record(&name, 0, 614), LAYOUT).unwrap().name, name);
    }

    #[test]
    fn rejects_names_containing_path_separators_or_nul() {
        for unit in [0, 47, 92] {
            assert!(decode(&record(&[65, unit, 66], 0, 110), LAYOUT).is_err());
        }
    }
}
