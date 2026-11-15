//! Native transport double: successful platform probes, explicit cache refusal.
use std::{env, fs::OpenOptions, io::Write, path::PathBuf, process};

fn decode(command: &str) -> String {
    let Some((_, encoded)) = command.split_once("-EncodedCommand ") else {
        return command.to_owned();
    };
    let mut bytes = Vec::new();
    let (mut bits, mut count) = (0u32, 0u32);
    for byte in encoded.trim().bytes().take_while(|b| *b != b'=') {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => process::exit(91),
        };
        bits = (bits << 6) | u32::from(digit);
        count += 6;
        if count >= 8 {
            count -= 8;
            bytes.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    if bytes.len() % 2 != 0 {
        process::exit(92);
    }
    let words: Vec<_> = bytes
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    String::from_utf16(&words).expect("valid encoded fixture command")
}

fn main() {
    let args: Vec<_> = env::args().collect();
    assert_eq!(args.len(), 6, "unexpected SSH arguments");
    assert_eq!(&args[1..5], ["-T", "-o", "BatchMode=yes", "127.0.0.1"]);
    let command = &args[5];
    assert!(command.len() <= 65536);
    let root = PathBuf::from(env::var_os("SE_PLATFORM_ROOT").expect("private root"));
    let mut recorded = false;
    for index in 0..8 {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(format!("command-{index}")))
        {
            Ok(mut file) => {
                file.write_all(command.as_bytes()).expect("record command");
                recorded = true;
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("trace creation failed: {error}"),
        }
    }
    assert!(recorded, "unexpected excess SSH calls");
    let key = if command == "uname -sm" {
        "UNAME"
    } else if decode(command).contains("OSArchitecture") {
        "ARCH"
    } else {
        process::exit(42)
    };
    let response = env::var(format!("SE_PLATFORM_{key}")).expect("probe response");
    std::io::stdout()
        .write_all(response.as_bytes())
        .expect("probe stdout");
    process::exit(
        if env::var(format!("SE_PLATFORM_{key}_OK")).as_deref() == Ok("true") {
            0
        } else {
            1
        },
    );
}
