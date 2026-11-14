//! Controlled SSH fault transport. Receive uses an owned native file; other
//! Windows commands execute the production encoded PowerShell unchanged.
use std::{fs::OpenOptions, io::{Read, Write}, process::{Command, Stdio}, time::Duration};

fn decoded(command: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = command.split("-EncodedCommand ").nth(1).ok_or("encoded command absent")?;
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut count = 0;
    let mut bytes = Vec::new();
    for byte in value.bytes().take_while(|b| *b != b'=') {
        let digit = alphabet.iter().position(|b| *b == byte).ok_or("invalid encoding")?;
        bits = (bits << 6) | u32::try_from(digit)?;
        count += 6;
        if count >= 8 { count -= 8; bytes.push(u8::try_from((bits >> count) & 255)?); }
    }
    let units: Vec<_> = bytes.chunks_exact(2).map(|b| u16::from_le_bytes([b[0],b[1]])).collect();
    Ok(String::from_utf16(&units)?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args().collect();
    let command = arguments.last().ok_or("command absent")?;
    let root = std::path::PathBuf::from(std::env::var_os("SE_STAGING_ROOT").ok_or("root absent")?);
    let mut log = OpenOptions::new().create(true).append(true).open(root.join("commands.log"))?;
    writeln!(log, "{command}")?;
    drop(log);
    if command == "uname -sm" {
        if std::env::var("SE_STAGING_CASE")? != "cancel" { println!("Linux x86_64"); return Ok(()); }
        std::process::exit(1);
    }
    let script = decoded(command)?;
    if script.contains("OpenStandardInput().CopyTo") {
        let relative = script.split("Join-Path $HOME '").nth(1).and_then(|s|s.split('\'').next()).ok_or("generated upload path absent")?;
        let profile = std::path::PathBuf::from(std::env::var_os("USERPROFILE").ok_or("native profile absent")?);
        let path = profile.join(relative);
        let mut file = OpenOptions::new().write(true).create_new(true).open(&path)?;
        std::fs::write(root.join("upload-path.txt"), path.to_str().ok_or("upload path UTF-8")?)?;
        let mut input = std::io::stdin().lock();
        let mut bytes = [0; 4096];
        loop {
            let n = input.read(&mut bytes)?;
            if n == 0 {break;}
            file.write_all(&bytes[..n])?;
            file.flush()?;
            std::thread::sleep(Duration::from_millis(50));
        }
        file.sync_all()?;
        return Ok(());
    }
    let args: Vec<_> = command.split_ascii_whitespace().collect();
    let status = Command::new(args[0]).args(&args[1..]).stdin(Stdio::null()).status()?;
    std::process::exit(status.code().unwrap_or(1));
}
