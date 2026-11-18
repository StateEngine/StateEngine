/// Lowercase hexadecimal in byte order, with two digits per byte and no prefix.
pub fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}

/// Whether text contains only lowercase ASCII hexadecimal digits.
pub fn is_lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Decode complete ASCII hexadecimal byte pairs, accepting either letter case.
pub fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = char::from(pair[0]).to_digit(16)?;
            let lo = char::from(pair[1]).to_digit(16)?;
            Some(((hi << 4) | lo) as u8)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::hex_lower;

    #[test]
    fn lowercase_hex_preserves_leading_zeroes_and_byte_order() {
        assert_eq!(hex_lower(&[]), "");
        assert_eq!(
            hex_lower(&[0, 1, 15, 16, 127, 128, 171, 255]),
            "00010f107f80abff"
        );
    }
}
