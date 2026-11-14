#![cfg(target_os = "macos")]

use serde_json::{Value, json};
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    time::Duration,
};

fn result<T: std::fmt::Debug>(value: io::Result<T>) -> Value {
    match value {
        Ok(value) => json!({"ok":format!("{value:?}")}),
        Err(error) => json!({"errno":error.raw_os_error(),"error":error.to_string()}),
    }
}

// Observation only: retain the native result before and after peer closure.
#[test]
fn record_timeout_after_peer_close() -> Result<(), Box<dyn std::error::Error>> {
    let (mut reader, mut writer) = UnixStream::pair()?;
    let before_close = result(reader.set_read_timeout(Some(Duration::from_millis(10))));
    writer.write_all(b"reply")?;
    drop(writer);
    let with_buffered_reply = result(reader.set_read_timeout(Some(Duration::from_millis(10))));
    let read = result(reader.read(&mut [0; 5]));
    let after_drain = result(reader.set_read_timeout(Some(Duration::from_millis(10))));
    let eof = result(reader.read(&mut [0; 1]));
    let document = json!({"before_close":before_close,"with_buffered_reply":with_buffered_reply,"read":read,"after_drain":after_drain,"eof":eof});
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/judge-diagnostics/macos-closed-socket");
    std::fs::create_dir_all(&root)?;
    std::fs::write(
        root.join("socket.json"),
        serde_json::to_vec_pretty(&document)?,
    )?;
    println!("{document}");
    Ok(())
}
