//! Protects: 70 §4.2 / T19 — browser and DNS-rebinding requests cannot enter even
//! the anonymous HTTP route; an initialized owner's local process gets no TCP authority.
#[path = "../../test-support/home_reaper.rs"]
mod home_reaper;
#[path = "../../test-support/provider_home.rs"]
mod provider_home;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::Path,
    process::{Command, Output},
    time::Duration,
};
type Check = Result<(), Box<dyn std::error::Error>>;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
#[path = "support/runtime_host.rs"]
mod runtime_host;

fn command(image: &Path, home: &Path, json: bool) -> Command {
    let mut command = Command::new(image);
    command.arg("--home").arg(home);
    if json {
        command.arg("--json");
    }
    for (name, _) in std::env::vars_os() {
        let text = name.to_string_lossy();
        if text.starts_with("SE_")
            || text.starts_with("STATEENGINE_")
            || text.starts_with("SECODE_")
            || matches!(text.as_ref(), "CLAUDECODE" | "CODEX_THREAD_ID" | "CODEX_CI")
        {
            command.env_remove(name);
        }
    }
    provider_home::for_state(&mut command, home);
    command
}
fn checked(output: Output) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    if !output.status.success() {
        return Err(format!(
            "public CLI failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}
struct Response {
    status: u16,
    body: String,
}
fn request(
    port: u16,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let body = if method == "POST" {
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"stateengine_status","arguments":{}}}"#
    } else {
        ""
    };
    write!(
        stream,
        "{method} {target} HTTP/1.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    )?;
    for (key, value) in headers {
        write!(stream, "{key}: {value}\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(body.as_bytes())?;
    let mut bytes = Vec::new();
    stream.take(1_048_577).read_to_end(&mut bytes)?;
    assert!(bytes.len() <= 1_048_576, "unbounded HTTP response");
    let response = String::from_utf8(bytes)?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or("HTTP response headers absent")?;
    assert!(
        !head
            .lines()
            .any(|line| line.to_ascii_lowercase().starts_with("access-control-")),
        "listener emitted browser permission: {head}"
    );
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("HTTP status absent")?
        .parse()?;
    let body = if head
        .lines()
        .any(|line| line.eq_ignore_ascii_case("transfer-encoding: chunked"))
    {
        let mut rest = body.as_bytes();
        let mut decoded = Vec::new();
        loop {
            let end = rest
                .windows(2)
                .position(|pair| pair == b"\r\n")
                .ok_or("chunk size absent")?;
            let size = usize::from_str_radix(
                std::str::from_utf8(&rest[..end])?
                    .split(';')
                    .next()
                    .ok_or("chunk size absent")?,
                16,
            )?;
            rest = &rest[end + 2..];
            if size == 0 {
                break;
            }
            if rest.len() < size + 2 || &rest[size..size + 2] != b"\r\n" {
                return Err("incomplete HTTP chunk".into());
            }
            decoded.extend_from_slice(&rest[..size]);
            rest = &rest[size + 2..];
        }
        String::from_utf8(decoded)?
    } else {
        body.to_owned()
    };
    Ok(Response { status, body })
}

struct AdmissionCase<'a> {
    name: &'static str,
    method: &'static str,
    target: String,
    headers: Vec<(&'static str, &'a str)>,
}

fn admission_cases<'a>(authority: &'a str, origin: &str) -> Vec<AdmissionCase<'a>> {
    vec![
        AdmissionCase {
            name: "foreign host",
            method: "GET",
            target: "/stateengine/livez".to_owned(),
            headers: vec![("Host", "attacker.invalid")],
        },
        AdmissionCase {
            name: "null origin",
            method: "GET",
            target: "/stateengine/livez".to_owned(),
            headers: vec![("Host", authority), ("Origin", "null")],
        },
        AdmissionCase {
            name: "foreign origin",
            method: "GET",
            target: "/stateengine/livez".to_owned(),
            headers: vec![("Host", authority), ("Origin", "https://attacker.invalid")],
        },
        AdmissionCase {
            name: "cross-site fetch",
            method: "GET",
            target: "/stateengine/livez".to_owned(),
            headers: vec![("Host", authority), ("Sec-Fetch-Site", "cross-site")],
        },
        AdmissionCase {
            name: "same-site fetch",
            method: "GET",
            target: "/stateengine/livez".to_owned(),
            headers: vec![("Host", authority), ("Sec-Fetch-Site", "same-site")],
        },
        AdmissionCase {
            name: "absolute target",
            method: "GET",
            target: format!("{origin}/stateengine/livez"),
            headers: vec![("Host", authority)],
        },
        AdmissionCase {
            name: "private route without bearer",
            method: "POST",
            target: "/mcp".to_owned(),
            headers: vec![("Host", authority), ("Content-Type", "application/json")],
        },
        AdmissionCase {
            name: "query bearer",
            method: "POST",
            target: "/mcp?access_token=sels-invalid".to_owned(),
            headers: vec![("Host", authority), ("Content-Type", "application/json")],
        },
        AdmissionCase {
            name: "form post",
            method: "POST",
            target: "/mcp".to_owned(),
            headers: vec![("Host", authority), ("Content-Type", "text/plain")],
        },
        AdmissionCase {
            name: "preflight",
            method: "OPTIONS",
            target: "/mcp".to_owned(),
            headers: vec![("Host", authority)],
        },
    ]
}

fn assert_admission_refusal(name: &str, response: &Response) -> Check {
    if name == "private route without bearer" && response.status == 200 {
        let body: serde_json::Value = serde_json::from_str(&response.body)?;
        assert_eq!(
            body["jsonrpc"], "2.0",
            "missing-session reply lost RPC envelope"
        );
        assert_eq!(
            body["id"], 1,
            "missing-session reply changed the actual request id"
        );
        if body.get("error").is_some() {
            assert!(
                body.get("result").is_none(),
                "refusal also carried a success result: {body}"
            );
            assert_eq!(
                body["error"]["code"], -32001,
                "wrong missing-session RPC refusal: {body}"
            );
            assert!(
                body["error"]["message"]
                    .as_str()
                    .is_some_and(|text| text.starts_with("session-required:")),
                "missing-session RPC refusal lost its reason: {body}"
            );
        } else {
            assert_eq!(
                body["result"]["isError"], true,
                "anonymous private call succeeded: {body}"
            );
            assert_eq!(
                body["result"]["structuredContent"]["code"], "session-required",
                "anonymous private call lacked the session-required refusal: {body}"
            );
        }
    } else {
        assert!(
            (400..500).contains(&response.status),
            "{name} was not refused: {}",
            response.status
        );
    }
    if name == "preflight" {
        assert_eq!(
            response.status, 405,
            "preflight did not name method refusal"
        );
    }
    println!("HTTP admission: {name}: {}", response.status);
    Ok(())
}

/// Protects: T19 — actual loopback HTTP admission, not a private router or fake server.
#[test]
fn public_http_admission_precedes_anonymous_and_private_routes() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let f = std::mem::ManuallyDrop::new(fixture::Fixture::new()?);
    println!(
        "HTTP judge private home (retained on failure): {}",
        f.home.display()
    );
    let home = &f.options.state_directory;
    let repository = f.home.join("repository");
    std::fs::create_dir(&repository)?;
    let image = f.home.join(if cfg!(windows) {
        "judge-se.exe"
    } else {
        "judge-se"
    });
    std::fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
    checked(
        command(&image, home, true)
            .args(["init", "--repo"])
            .arg(&repository)
            .output_executable()?,
    )?;
    let configuration: toml::Value =
        toml::from_str(&std::fs::read_to_string(home.join("config.toml"))?)?;
    let port = u16::try_from(
        configuration["runtime"]["listen_port"]
            .as_integer()
            .ok_or("persisted listen port absent")?,
    )?;
    let host = runtime_host::RunningHost::start(&image, home)?;
    let authority = format!("127.0.0.1:{port}");
    let localhost = format!("localhost:{port}");
    let origin = format!("http://{authority}");
    for authority in [&authority, &localhost] {
        let response = request(port, "GET", "/stateengine/livez", &[("Host", authority)])?;
        assert_eq!(response.status, 200, "anonymous control failed");
        let body: serde_json::Value = serde_json::from_str(&response.body)?;
        let object = body.as_object().ok_or("livez is not an object")?;
        assert_eq!(object.len(), 2, "anonymous route disclosed private fields");
        assert_eq!(body["ok"], true);
        assert!(object.contains_key("api"));
    }
    for case in admission_cases(&authority, &origin) {
        let response = request(port, case.method, &case.target, &case.headers)?;
        assert_admission_refusal(case.name, &response)?;
    }
    assert_eq!(
        request(
            port,
            "GET",
            "/stateengine/livez",
            &[
                ("Host", &authority),
                ("Origin", &origin),
                ("Sec-Fetch-Site", "same-origin")
            ]
        )?
        .status,
        200
    );
    host.stop()?;
    drop(host);
    drop(std::mem::ManuallyDrop::into_inner(f));
    Ok(())
}

#[path = "../../test-support/executable.rs"]
mod executable;
use executable::ExecutableCommand;
