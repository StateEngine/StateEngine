//! Real loopback consumers protect credential routing and complete response reads.
#![cfg(feature = "listener")]
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;
#[cfg(unix)]
use se_host::secode_process::Images;
use se_host::{
    client::{ClientOptions, lease::Deadline},
    secode_process::Control,
};
#[cfg(unix)]
use std::fs;
use std::{
    error::Error,
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
type Check = Result<(), Box<dyn Error + Send + Sync>>;
struct Profile(cleanup_directory::PrivateDirectory);
impl Profile {
    fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let p = cleanup_directory::private_case_directory().map_err(|error| error.to_string())?;
        let files = se_proc::NativeStateFiles::create(&p)?;
        let mut stage = files.create_staging(&p)?;
        stage.file.write_all(b"review:synthetic-secret\n")?;
        drop(stage.file);
        files.publish_no_replace(&stage.path, &p.join("basic.credential"))?;
        Ok(Self(p.cleanup_on_drop()))
    }
    fn control(&self, endpoint: &str) -> se_types::Result<Control> {
        Control::open(&self.0, endpoint)
    }
}
fn deadline(ms: u64) -> se_types::Result<Deadline> {
    Deadline::from_options(&ClientOptions {
        expected_generation: None,
        timeout: Duration::from_millis(ms),
        cancelled: Arc::new(AtomicBool::new(false)),
    })
}
type Server = (
    String,
    std::thread::JoinHandle<Result<String, std::io::Error>>,
);
fn serve(response: Vec<u8>) -> Result<Server, std::io::Error> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    let origin = format!("http://{}/", l.local_addr()?);
    let t = std::thread::spawn(move || {
        let (mut s, _) = l.accept()?;
        s.set_read_timeout(Some(Duration::from_secs(3)))?;
        let mut request = Vec::new();
        let mut b = [0; 1];
        while !request.ends_with(b"\r\n\r\n") {
            if s.read(&mut b)? == 0 {
                break;
            }
            request.push(b[0]);
            if request.len() > 16384 {
                return Err(std::io::Error::other("request bound"));
            }
        }
        let _ = s.write_all(&response);
        Ok(String::from_utf8_lossy(&request).into_owned())
    });
    Ok((origin, t))
}
#[test]
fn refuse_credential_routing_suffixes_and_non_loopback_origins() -> Check {
    let p = Profile::new()?;
    for url in [
        "https://127.0.0.1:9/",
        "http://192.0.2.1:9/",
        "http://localhost:9/",
        "http://review:secret@127.0.0.1:9/",
        "http://127.0.0.1:9/api/",
        "http://127.0.0.1:9/?route=x",
        "http://127.0.0.1:9/#x",
    ] {
        assert!(p.control(url).is_err(), "accepted {url}");
    }
    Ok(())
}
#[tokio::test]
async fn exact_loopback_request_uses_private_basic_credential() -> Check {
    let p = Profile::new()?;
    let (origin, t) = serve(
        b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}".to_vec(),
    )?;
    let result = p
        .control(&origin)?
        .read(&["api", "health"], &deadline(3000)?)
        .await;
    let request = t.join().map_err(|_| "server panicked")??;
    assert!(result?["ok"].as_bool() == Some(true));
    assert!(request.starts_with("GET /api/health HTTP/1.1\r\n"));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: basic cmv2awv3onn5bnrozxrpyy1zzwnyzxq=")
    );
    Ok(())
}
#[tokio::test]
async fn redirect_never_forwards_private_credential() -> Check {
    let p = Profile::new()?;
    let target = TcpListener::bind("127.0.0.1:0")?;
    target.set_nonblocking(true)?;
    let response = format!(
        "HTTP/1.1 302 Found\r\nLocation: http://{}/steal\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}",
        target.local_addr()?
    );
    let (origin, t) = serve(response.into_bytes())?;
    let result = p
        .control(&origin)?
        .read(&["api", "health"], &deadline(3000)?)
        .await;
    t.join().map_err(|_| "server panicked")??;
    assert!(result.is_err(), "redirect became success");
    assert!(
        matches!(target.accept(),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock),
        "credential route followed redirect"
    );
    Ok(())
}
#[tokio::test]
async fn truncated_and_oversized_success_responses_refuse() -> Check {
    let p = Profile::new()?;
    let oversized = 8 * 1024 * 1024 + 1;
    let mut large =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {oversized}\r\nConnection: close\r\n\r\n")
            .into_bytes();
    large.push(b'"');
    large.extend(std::iter::repeat_n(b'a', oversized - 2));
    large.push(b'"');
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\nConnection: close\r\n\r\n{\"ok\":true}".to_vec(),
        large,
    ] {
        let (origin, t) = serve(response)?;
        let result = p
            .control(&origin)?
            .read(&["api", "health"], &deadline(3000)?)
            .await;
        t.join().map_err(|_| "server panicked")??;
        assert!(result.is_err(), "incomplete response accepted");
    }
    Ok(())
}
#[tokio::test]
async fn authenticated_error_redacts_secret_from_public_reason() -> Check {
    let p = Profile::new()?;
    let body = r#"{"message":"synthetic-secret denied"}"#;
    let response = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let (origin, t) = serve(response.into_bytes())?;
    let result = p
        .control(&origin)?
        .read(&["api", "health"], &deadline(3000)?)
        .await;
    t.join().map_err(|_| "server panicked")??;
    let error = match result {
        Err(error) => format!("{error:?}"),
        Ok(_) => panic!("refusal became success"),
    };
    assert!(
        !error.contains("synthetic-secret"),
        "secret in public error"
    );
    assert!(error.contains("[credential]"));
    Ok(())
}
#[cfg(unix)]
#[test]
fn selected_native_image_replacement_is_refused_before_reuse() -> Check {
    let p = Profile::new()?;
    let cli = p.0.join("secode");
    let server = p.0.join("secode-server");
    fs::copy("/bin/true", &cli)?;
    fs::copy("/bin/true", &server)?;
    let mut selected = Images::open(&cli)?;
    selected.validate()?;
    let replacement = p.0.join("replacement");
    fs::copy("/bin/false", &replacement)?;
    fs::rename(replacement, &server)?;
    assert!(selected.validate().is_err(), "replaced server image reused");
    Ok(())
}
