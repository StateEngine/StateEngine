//! LEB128 varints and the delta-coded lists stored in BLOB columns.
//!
//! A pair list holds `(key, value)` rows sorted by strictly increasing key,
//! with `value >= 1`. Each row is `varint((key - previous) << 1 | (value > 1))`
//! followed by `varint(value)` only when the flag is set, so the common
//! `tf = 1` costs no value byte. Postings (`file`, `tf`) and per-file token
//! lists (`tok`, `tf`) share it. An id list is plain delta varints. Keys and
//! ids start at 1, so every stored delta is at least 1; decoding refuses a
//! zero delta, a zero value and a varint wider than 64 bits.
use crate::{IndexError, Result};

pub fn put(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

pub fn get(bytes: &[u8], pos: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *bytes
            .get(*pos)
            .ok_or(IndexError::Corrupt("truncated varint"))?;
        *pos += 1;
        // The tenth byte carries bit 63 only.
        if shift == 63 && byte > 1 {
            return Err(IndexError::Corrupt("overlong varint"));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(IndexError::Corrupt("overlong varint"))
}

/// Encode pairs that are already sorted by strictly increasing key.
pub fn encode_pairs(pairs: &[(i64, u32)]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(pairs.len() * 3);
    let mut previous = 0i64;
    for (index, (key, value)) in pairs.iter().enumerate() {
        if *key <= 0 || (index > 0 && *key <= previous) || *value == 0 {
            return Err(IndexError::Invalid(
                "pair keys must be positive and increasing with nonzero values",
            ));
        }
        let delta = (*key - previous) as u64;
        if delta > u64::MAX >> 1 {
            return Err(IndexError::Invalid("pair key gap too large"));
        }
        put(&mut out, (delta << 1) | u64::from(*value > 1));
        if *value > 1 {
            put(&mut out, u64::from(*value));
        }
        previous = *key;
    }
    Ok(out)
}

pub fn decode_pairs(bytes: &[u8]) -> Result<Vec<(i64, u32)>> {
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut pos = 0;
    let mut key = 0i64;
    while pos < bytes.len() {
        let head = get(bytes, &mut pos)?;
        if head >> 1 == 0 {
            return Err(IndexError::Corrupt("pair keys must increase"));
        }
        key = key
            .checked_add(
                i64::try_from(head >> 1).map_err(|_| IndexError::Corrupt("pair key overflow"))?,
            )
            .ok_or(IndexError::Corrupt("pair key overflow"))?;
        let value = if head & 1 == 1 {
            let value = u32::try_from(get(bytes, &mut pos)?)
                .map_err(|_| IndexError::Corrupt("pair value overflow"))?;
            if value <= 1 {
                return Err(IndexError::Corrupt("flagged pair value must exceed 1"));
            }
            value
        } else {
            1
        };
        out.push((key, value));
    }
    Ok(out)
}

/// Encode ids that are already sorted and distinct.
pub fn encode_ids(ids: &[i64]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(ids.len() * 2);
    let mut previous = 0i64;
    for (index, id) in ids.iter().enumerate() {
        if *id <= 0 || (index > 0 && *id <= previous) {
            return Err(IndexError::Invalid("ids must be positive and increasing"));
        }
        put(&mut out, (*id - previous) as u64);
        previous = *id;
    }
    Ok(out)
}

pub fn decode_ids(bytes: &[u8]) -> Result<Vec<i64>> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut pos = 0;
    let mut id = 0i64;
    while pos < bytes.len() {
        let delta = get(bytes, &mut pos)?;
        if delta == 0 {
            return Err(IndexError::Corrupt("ids must increase"));
        }
        id = id
            .checked_add(i64::try_from(delta).map_err(|_| IndexError::Corrupt("id overflow"))?)
            .ok_or(IndexError::Corrupt("id overflow"))?;
        out.push(id);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_round_trip_at_boundaries() -> Result<()> {
        for value in [
            0,
            1,
            127,
            128,
            16_383,
            16_384,
            u64::from(u32::MAX),
            u64::MAX,
        ] {
            let mut bytes = Vec::new();
            put(&mut bytes, value);
            let mut pos = 0;
            assert_eq!(get(&bytes, &mut pos)?, value);
            assert_eq!(pos, bytes.len());
        }
        assert!(get(&[0x80], &mut 0).is_err());
        Ok(())
    }

    #[test]
    fn pair_and_id_lists_round_trip_and_refuse_disorder() -> Result<()> {
        let pairs = [(1, 3), (2, 1), (300, 70_000), (1 << 40, 1)];
        assert_eq!(decode_pairs(&encode_pairs(&pairs)?)?, pairs);
        assert_eq!(encode_pairs(&[(1, 1), (2, 1)])?, [2, 2]);
        assert!(encode_pairs(&[(5, 1), (5, 2)]).is_err());
        assert!(encode_pairs(&[(5, 0)]).is_err());
        let ids = [3, 4, 1000, 1 << 33];
        assert_eq!(decode_ids(&encode_ids(&ids)?)?, ids);
        assert!(encode_ids(&[2, 1]).is_err());
        assert_eq!(decode_pairs(&[])?, []);
        Ok(())
    }
}
