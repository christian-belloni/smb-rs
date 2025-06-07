pub const fn parse_hex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("Invalid hex character"),
    }
}

pub const fn parse_byte(b: &[u8], i: usize) -> u8 {
    (parse_hex(b[i]) << 4) | parse_hex(b[i + 1])
}
