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
