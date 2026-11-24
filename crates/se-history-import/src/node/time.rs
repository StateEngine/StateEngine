//! Node's persisted Date.toISOString form, decoded without a locale or clock.
use super::{StoreResult, invalid};
pub(super) fn micros(value: &str) -> StoreResult<i64> {
    let b = value.as_bytes();
    if !value.is_ascii()
        || b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b.last() != Some(&b'Z')
    {
        return Err(invalid(
            "Node timestamp requires its recorded UTC ISO format",
        ));
    }
    let n = |start: usize, end: usize| value[start..end].parse::<i64>().map_err(invalid);
    let (y, m, d, h, min, s) = (
        n(0, 4)?,
        n(5, 7)?,
        n(8, 10)?,
        n(11, 13)?,
        n(14, 16)?,
        n(17, 19)?,
    );
    let leap = |y: i64| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let months = [
        31,
        if leap(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1970..=9999).contains(&y)
        || !(1..=12).contains(&m)
        || d < 1
        || d > months[(m - 1) as usize]
        || !(0..24).contains(&h)
        || !(0..60).contains(&min)
        || !(0..60).contains(&s)
    {
        return Err(invalid("Node timestamp has an invalid calendar component"));
    }
    let fraction = if b.len() == 20 {
        0
    } else {
        if b[19] != b'.' || !(22..=27).contains(&b.len()) {
            return Err(invalid("Node timestamp fraction requires 1..6 digits"));
        }
        n(20, b.len() - 1)? * 10i64.pow((27 - b.len()) as u32)
    };
    let leaps = |y: i64| y / 4 - y / 100 + y / 400;
    let days = (y - 1970) * 365 + leaps(y - 1) - leaps(1969)
        + months[..(m - 1) as usize].iter().sum::<i64>()
        + d
        - 1;
    Ok(((days * 24 + h) * 3600 + min * 60 + s) * 1_000_000 + fraction)
}
