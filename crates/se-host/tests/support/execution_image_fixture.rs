use std::io::Write;
fn main() {
    let mut output = std::io::stdout().lock();
    output.write_all(b"QUALIFIED_IMAGE_ORIGINAL\n").unwrap();
    writeln!(
        output,
        "{}",
        std::env::args_os().next().unwrap().to_string_lossy()
    )
    .unwrap();
}
