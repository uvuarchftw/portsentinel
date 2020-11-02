pub(crate) fn to_dotline(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len());

    for byte in bytes.iter() {
        if *byte > 31 && *byte < 127 {
            result.push(*byte as char)
        } else if *byte == 0 {
            result.push('-');
        } else {
            result.push('.');
        }
    }
    result
}
