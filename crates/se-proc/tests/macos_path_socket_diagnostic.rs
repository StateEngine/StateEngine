#![cfg(target_os = "macos")]

use se_proc::native_ipc::{IpcIoBound, NativeUnixStream};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

fn result<T: std::fmt::Debug>(value: io::Result<T>) -> Value {
    match value {
        Ok(value) => json!({"ok":format!("{value:?}")}),
        Err(error) => json!({"errno":error.raw_os_error(),"error":error.to_string()}),
    }
}

fn exchange(mut client: impl Read + Write, mut server: UnixStream) -> Value {
    let timeout = server.set_read_timeout(Some(Duration::from_millis(100)));
    if timeout.is_err() {
        return json!({"stage":"server timeout","result":result(timeout)});
    }
    let sent = client.write_all(b"x");
    if sent.is_err() {
        return json!({"stage":"client write","result":result(sent)});
    }
    let server_read = result(server.read(&mut [0; 1]));
    let sent = server.write_all(b"y");
    if sent.is_err() {
        return json!({"stage":"server write","result":result(sent),"server_read":server_read});
    }
    let client_read = result(client.read(&mut [0; 1]));
    drop(client);
    let server_eof = result(server.read(&mut [0; 1]));
    json!({"server_read":server_read,"client_read":client_read,"server_eof":server_eof})
}

// Observation only: compare real pathname connections without asserting acceptance.
#[test]
fn record_pathname_socket_reads() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir()
        .canonicalize()?
        .join(format!("io-{}", std::process::id()));
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let mut observations = Vec::new();
    for native in [false, true] {
        let path = root.join("s");
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let observed = if native {
            let bound = IpcIoBound {
                deadline: Instant::now() + Duration::from_secs(2),
                cancelled: Arc::new(AtomicBool::new(false)),
            };
            match NativeUnixStream::connect(&path, bound) {
                Ok(client) => exchange(client, listener.accept()?.0),
                Err(error) => json!({"stage":"native connect","error":format!("{error:?}")}),
            }
        } else {
            let client = UnixStream::connect(&path)?;
            client.set_read_timeout(Some(Duration::from_secs(1)))?;
            exchange(client, listener.accept()?.0)
        };
        observations.push(json!({"native":native,"observed":observed}));
        drop(listener);
        fs::remove_file(&path)?;
    }
    fs::remove_dir(&root)?;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/judge-diagnostics/macos-path-socket");
    fs::create_dir_all(&root)?;
    let document = json!({"observations":observations});
    fs::write(
        root.join("socket.json"),
        serde_json::to_vec_pretty(&document)?,
    )?;
    println!("{document}");
    Ok(())
}
