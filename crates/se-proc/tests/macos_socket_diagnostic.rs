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

// Observation only. The native consumer cases judge the product separately.
#[test]
fn record_native_socket_reads() -> Result<(), Box<dyn std::error::Error>> {
    let mut observations = Vec::new();
    for timeout in [
        None,
        Some(Duration::from_millis(10)),
        Some(Duration::from_secs(1)),
    ] {
        let (mut reader, mut writer) = UnixStream::pair()?;
        let configured = result(reader.set_read_timeout(timeout));
        writer.write_all(b"x")?;
        let read = result(reader.read(&mut [0; 1]));
        drop(writer);
        let eof = result(reader.read(&mut [0; 1]));
        observations.push(json!({"timeout_ms":timeout.map(|d|d.as_millis()),"configured":configured,"read":read,"eof":eof}));
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/judge-diagnostics/macos-socket");
    std::fs::create_dir_all(&root)?;
    let document = json!({"observations":observations});
    std::fs::write(
        root.join("socket.json"),
        serde_json::to_vec_pretty(&document)?,
    )?;
    println!("{document}");
    Ok(())
}
