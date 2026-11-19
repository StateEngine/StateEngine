//! Bounded local protocol fixture; no account or external provider is used.
use super::Check;
use se_host::client::{BlockingIpcClient, ClientOptions, endpoint};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::Duration,
};

const AUTH: &str = "Basic Zml4dHVyZTpzeW50aGV0aWMtc2VjcmV0";
struct State {
    profile: PathBuf,
    endpoint: String,
    saved: Value,
    capability: Option<Vec<u8>>,
    restart_key: Option<String>,
    ready: bool,
    held: bool,
}
fn identity() -> Value {
    json!({"incarnation":"fixture-incarnation","serviceInstance":"fixture-instance","generation":1,"registrationVersion":"fixture-v1"})
}
fn read_file(path: &Path) -> Check<Value> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn save(state: &State) -> Check {
    fs::write(
        state.profile.join("fixture-state.json"),
        serde_json::to_vec(&state.saved)?,
    )?;
    Ok(())
}
fn read_request(
    reader: &mut BufReader<TcpStream>,
) -> Check<Option<(String, String, BTreeMap<String, String>, Value)>> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let mut words = line.split_whitespace();
    let method = words.next().ok_or("method absent")?.to_owned();
    let path = words
        .next()
        .ok_or("path absent")?
        .split('?')
        .next()
        .ok_or("path absent")?
        .to_owned();
    let mut headers = BTreeMap::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err("incomplete headers".into());
        }
        if line == "\r\n" {
            break;
        }
        let (key, value) = line.split_once(':').ok_or("invalid header")?;
        headers.insert(key.to_ascii_lowercase(), value.trim().to_owned());
    }
    let length = headers
        .get("content-length")
        .map(|s| s.parse::<usize>())
        .transpose()?
        .unwrap_or(0);
    if length > 1_048_576 {
        return Err("request too large".into());
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok(Some((method, path, headers, body)))
}
fn respond(reader: &mut BufReader<TcpStream>, status: u16, body: &Value) -> Check {
    let bytes = serde_json::to_vec(body)?;
    let reason = match status {
        200 => "OK",
        409 => "NotReady",
        403 => "Forbidden",
        _ => "Not Found",
    };
    write!(
        reader.get_mut(),
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        bytes.len()
    )?;
    reader.get_mut().write_all(&bytes)?;
    Ok(())
}
fn decode(value: &str) -> Check<Vec<u8>> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("invalid hex".into());
    }
    (0..32)
        .map(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|e| e.into()))
        .collect()
}
fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut padded = [0u8; 64];
    if key.len() > 64 {
        padded[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0u8; 64];
    let mut outer = [0u8; 64];
    for i in 0..64 {
        inner[i] = padded[i] ^ 0x36;
        outer[i] = padded[i] ^ 0x5c;
    }
    let mut first = Sha256::new();
    first.update(inner);
    for part in parts {
        first.update(part);
    }
    let mut second = Sha256::new();
    second.update(outer);
    second.update(first.finalize());
    second.finalize().into()
}
fn text<'a>(body: &'a Value, key: &str) -> Check<&'a str> {
    body[key]
        .as_str()
        .ok_or_else(|| format!("missing {key}").into())
}
fn signature(state: &State, domain: &[u8], body: &Value, release: bool) -> Check<String> {
    let key = state.capability.as_deref().ok_or("capability not ready")?;
    let restart = decode(text(body, "restart_key")?)?;
    let nonce = decode(text(body, if release { "nonce" } else { "challenge" })?)?;
    let hash = if release {
        let project = text(body, "project_id")?;
        let agent = text(body, "agent_id")?;
        hmac(
            key,
            &[
                domain,
                &restart,
                &nonce,
                project.as_bytes(),
                &[0],
                agent.as_bytes(),
            ],
        )
    } else {
        hmac(key, &[domain, &restart, &nonce])
    };
    Ok(se_types::hex_lower(&hash))
}
fn notice(state: &State, session: &str) -> Value {
    json!({"service":identity(),"sessionID":session,"targetID":"fixture-target","binding":"11".repeat(32),"holdID":if state.held {Some("fixture-hold")} else {None},"status":if state.held {"held"} else {"ready"}})
}
fn route(
    method: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
    body: &Value,
    state: &mut State,
) -> Check<(u16, Value)> {
    if path == "/api/stateengine/rebind/challenge" {
        if !state.ready {
            state.saved["not_ready_count"] =
                json!(state.saved["not_ready_count"].as_u64().unwrap_or(0) + 1);
            save(state)?;
            return Ok((409, json!({"error":"NotReady"})));
        }
        if state.restart_key.as_deref() != Some(text(body, "restart_key")?) {
            return Ok((403, json!({"error":"unknown restart"})));
        }
        return Ok((
            200,
            json!({"mac":signature(state,b"stateengine.rebind.control/v1",body,false)?}),
        ));
    }
    if headers.get("authorization").map(String::as_str) != Some(AUTH) {
        return Ok((403, json!({"error":"authorization"})));
    }
    if path == "/api/stateengine/rebind/release" {
        if !state.ready {
            return Ok((409, json!({"error":"NotReady"})));
        }
        let coords = state.saved.get("coordinates").ok_or("coordinates absent")?;
        if body["project_id"] != coords["project_id"]
            || body["agent_id"] != coords["agent_id"]
            || state.restart_key.as_deref() != Some(text(body, "restart_key")?)
            || signature(state, b"stateengine.rebind.release/v1", body, true)? != text(body, "mac")?
        {
            return Ok((403, json!({"error":"release proof"})));
        }
        let restart = decode(text(body, "restart_key")?)?;
        let nonce = decode(text(body, "nonce")?)?;
        let reply = hmac(
            state.capability.as_deref().ok_or("capability absent")?,
            &[b"stateengine.rebind.released/v1", &restart, &nonce],
        );
        state.saved["released"] = json!(true);
        save(state)?;
        return Ok((
            200,
            json!({"released":true,"mac":se_types::hex_lower(&reply)}),
        ));
    }
    if path == "/api/health" {
        return Ok((200, json!({"ok":true})));
    }
    if path == "/api/session/active" {
        return Ok((200, json!({"data":{}})));
    }
    if path == "/fixture/input" {
        state.saved["input"] = body.clone();
        save(state)?;
        return Ok((200, json!({"accepted":true})));
    }
    if path == "/fixture/ready" {
        state.ready = true;
        state.saved["ready"] = json!(true);
        save(state)?;
        return Ok((200, json!({"ready":true})));
    }
    if path == "/fixture/uncertain" {
        state.saved["uncertain_next"] = json!(true);
        save(state)?;
        return Ok((200, json!({"armed":true})));
    }
    if path == "/fixture/exit" {
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(250));
            std::process::exit(0);
        });
        return Ok((200, json!({"exiting":true})));
    }
    if path == "/fixture/restart" {
        state.saved["coordinates"] = body.clone();
        state.saved["restart_started"] = json!(true);
        save(state)?;
        let executable = env::current_exe()?;
        Command::new(executable)
            .arg("fixture-restart")
            .arg("--service")
            .arg(&state.profile)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(250));
            std::process::exit(0);
        });
        return Ok((200, json!({"started":true})));
    }
    if path == "/api/session" && method == "POST" {
        state.saved["session"] = body.clone();
        save(state)?;
        return Ok((200, json!({"data":body})));
    }
    let parts: Vec<_> = path.trim_start_matches('/').split('/').collect();
    if parts.len() < 3 || parts[..2] != ["api", "session"] {
        return Ok((404, json!({"error":"unknown route"})));
    }
    let session = parts[2];
    let tail = &parts[3..];
    if tail.is_empty() {
        return Ok((200, json!({"data":state.saved["session"]})));
    }
    if tail == ["preset"] {
        if method == "POST" {
            state.saved["preset"] = body["preset"].clone();
            save(state)?;
        }
        return Ok((200, json!({"data":{"effective":state.saved["preset"]}})));
    }
    if tail == ["instructions", "entries", "stateengine-identity"] && method == "PUT" {
        state.saved["instruction"] = body["value"].clone();
        save(state)?;
        return Ok((200, json!({"ok":true})));
    }
    if tail == ["instructions", "entries"] {
        return Ok((
            200,
            json!({"data":[{"key":"stateengine-identity","value":state.saved["instruction"]}]}),
        ));
    }
    if tail == ["stateengine", "capability"] && method == "PUT" {
        return Ok((200, json!({"ok":true})));
    }
    if tail == ["stateengine", "notice"] && method == "GET" {
        return Ok((200, notice(state, session)));
    }
    if tail == ["stateengine", "notice"] && method == "POST" {
        let ids = body["messages"].as_array().ok_or("notice ids absent")?;
        let ids: Vec<String> = ids
            .iter()
            .map(|id| id.as_str().map(str::to_owned).ok_or("invalid notice id"))
            .collect::<Result<_, _>>()?;
        let text = se_host::secode_process::notice_text(&ids)?;
        let metadata = json!({"native_mail_wake":1,"hostNotice":true,"targetID":"fixture-target","binding":"11".repeat(32),"messages":ids.iter().map(|id| json!({"source_message":id})).collect::<Vec<_>>()});
        let accepted = json!({"id":body["id"],"sessionID":session,"admittedSeq":2,"timeCreated":2,"kind":"synthetic","text":text,"delivery":"steer","metadata":metadata});
        if !state.saved["notices"].is_array() {
            state.saved["notices"] = json!([]);
        }
        state.saved["notices"]
            .as_array_mut()
            .ok_or("notice history absent")?
            .push(accepted.clone());
        state.saved["notice"] = accepted.clone();
        let uncertain = state.saved["uncertain_next"] == true;
        state.saved["uncertain_open"] = json!(uncertain);
        state.saved["uncertain_next"] = json!(false);
        save(state)?;
        if uncertain {
            return Ok((599, Value::Null));
        }
        return Ok((200, json!({"service":identity(),"data":accepted})));
    }
    if tail.first() == Some(&"input") && tail.len() == 2 {
        let input = &state.saved["input"];
        if state.saved["notice"]["id"] == tail[1] && state.saved["uncertain_open"] == true {
            return Ok((409, json!({"error":"NotReady"})));
        }
        let data = if state.saved["notice"]["id"] == tail[1] {
            state.saved["notice"].clone()
        } else if input["id"] == tail[1] {
            json!({"id":input["id"],"sessionID":session,"admittedSeq":1,"timeCreated":1,"kind":"user","text":input["text"],"delivery":"queue","metadata":{"origin":"seat-startup"}})
        } else {
            Value::Null
        };
        return Ok((200, json!({"service":identity(),"data":data})));
    }
    if tail == ["message"] {
        let input = &state.saved["input"];
        let mut rows = if input.is_object() {
            vec![json!({"type":"user","id":input["id"],"text":input["text"]})]
        } else {
            vec![]
        };
        if state.saved["notice"].is_object() && state.saved["uncertain_open"] != true {
            rows.push(json!({"type":"synthetic","id":state.saved["notice"]["id"],"text":state.saved["notice"]["text"]}));
        }
        return Ok((200, json!({"data":rows,"cursor":{}})));
    }
    if tail == ["interrupt"] && method == "POST" {
        state.held = true;
        return Ok((200, json!({"ok":true})));
    }
    if tail == ["reconcile"] && method == "POST" {
        return Ok((200, json!({"ok":true})));
    }
    Ok((404, json!({"error":"unknown session route"})))
}
fn connection(stream: TcpStream, shared: Arc<Mutex<State>>) -> Check {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut reader = BufReader::new(stream);
    while let Some((method, path, headers, body)) = read_request(&mut reader)? {
        let (status, value) = {
            let mut state = shared.lock().map_err(|_| "fixture state poisoned")?;
            route(&method, &path, &headers, &body, &mut state)?
        };
        if status == 599 {
            return Ok(());
        }
        respond(&mut reader, status, &value)?;
    }
    Ok(())
}
fn restart(shared: &Arc<Mutex<State>>) -> Check {
    let (profile, address, coords) = {
        let state = shared.lock().map_err(|_| "fixture state poisoned")?;
        (
            state.profile.clone(),
            state.endpoint.clone(),
            state.saved["coordinates"].clone(),
        )
    };
    let home = PathBuf::from(text(&coords, "home")?);
    let endpoint = endpoint::decode_endpoint(&fs::read(home.join("endpoint.json"))?)?;
    let project = text(&coords, "project_id")?.parse()?;
    let agent = text(&coords, "agent_id")?.parse()?;
    let options = ClientOptions {
        expected_generation: None,
        timeout: Duration::from_secs(30),
        cancelled: Arc::new(AtomicBool::new(false)),
    };
    let reply = BlockingIpcClient::rebind(&endpoint, &options, project, agent, address)?;
    {
        let mut state = shared.lock().map_err(|_| "fixture state poisoned")?;
        state.capability = Some(reply.capability.expose().to_vec());
        state.restart_key = Some(reply.restart_key);
    }
    {
        let mut state = shared.lock().map_err(|_| "fixture state poisoned")?;
        state.saved["rebound"] = json!(true);
        save(&state)?;
    }
    let _ = profile;
    Ok(())
}
pub fn serve(profile: PathBuf, is_restart: bool) -> Check {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = format!("http://{}/", listener.local_addr()?);
    let saved = if profile.join("fixture-state.json").exists() {
        read_file(&profile.join("fixture-state.json"))?
    } else {
        json!({})
    };
    let state = State {
        profile: profile.clone(),
        endpoint: endpoint.clone(),
        saved,
        capability: None,
        restart_key: None,
        ready: !is_restart,
        held: false,
    };
    if !is_restart {
        let pid = std::process::id();
        fs::write(
            profile.join("registration"),
            format!(
                "secode-service/registration/1\nslot=fixture-slot\ninstance=fixture-instance\nenvironment=fixture-env\ngeneration=1\npid={pid}\nendpoint={endpoint}\nversion=fixture-v1\nregistered_at=1\n"
            ),
        )?;
        fs::write(
            profile.join("fixture-registration.json"),
            serde_json::to_vec(
                &json!({"schema":"secode.cli.service-status.v1","outcome":"ready","serviceSlot":"fixture-slot","serviceInstance":"fixture-instance","environment":"fixture-env","registrationVersion":"fixture-v1","generation":1,"pid":pid,"endpoint":endpoint}),
            )?,
        )?;
        fs::write(
            profile.join("serve-ready.json"),
            serde_json::to_vec(
                &json!({"schema":"secode.product.ready.v2","operation":"serve","pid":pid,"observed_endpoint":endpoint}),
            )?,
        )?;
    }
    let shared = Arc::new(Mutex::new(state));
    if is_restart {
        fs::write(
            profile.join("fixture-replacement.json"),
            serde_json::to_vec(&json!({"pid":std::process::id(),"endpoint":endpoint}))?,
        )?;
        let state = shared.clone();
        std::thread::spawn(move || {
            if let Err(error) = restart(&state) {
                eprintln!("fixture rebind failed: {error}");
            }
        });
    }
    for stream in listener.incoming() {
        let stream = stream?;
        let state = shared.clone();
        std::thread::spawn(move || {
            let _ = connection(stream, state);
        });
    }
    Ok(())
}
pub fn post(endpoint: &str, path: &str, body: &Value) -> Check<Value> {
    let url = endpoint
        .strip_prefix("http://")
        .ok_or("non-http fixture endpoint")?
        .trim_end_matches('/');
    let mut stream = TcpStream::connect(url)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let bytes = serde_json::to_vec(body)?;
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {url}\r\nAuthorization: {AUTH}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    )?;
    stream.write_all(&bytes)?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if !line.starts_with("HTTP/1.1 200") {
        return Err("fixture POST refused".into());
    }
    let mut length = 0usize;
    loop {
        line.clear();
        reader.read_line(&mut line)?;
        if line == "\r\n" {
            break;
        }
        if let Some((key, value)) = line.split_once(':')
            && key.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse()?;
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(serde_json::from_slice(&body)?)
}

pub fn initialize_mcp(policy: &Value) -> Check {
    let mcp = &policy["mcp"]["stateengine"];
    let url = text(mcp, "url")?
        .strip_prefix("http://")
        .ok_or("fixture MCP URL")?;
    let (address, path) = url.split_once('/').ok_or("fixture MCP path")?;
    let bearer = text(&mcp["headers"], "Authorization")?;
    let proof = text(&mcp["headers"], "X-StateEngine-Session-Proof")?;
    let body = serde_json::to_vec(
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"contract-fixture","version":"1"}}}),
    )?;
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    write!(
        stream,
        "POST /{path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: {bearer}\r\nX-StateEngine-Session-Proof: {proof}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if !line.starts_with("HTTP/1.1 200") {
        return Err("fixture MCP initialization refused".into());
    }
    let mut length = 0usize;
    loop {
        line.clear();
        reader.read_line(&mut line)?;
        if line == "\r\n" {
            break;
        }
        if let Some((key, value)) = line.split_once(':')
            && key.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse()?;
        }
    }
    if length > 1_048_576 {
        return Err("fixture MCP response too large".into());
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    let response: Value = serde_json::from_slice(&bytes)?;
    if response.get("error").is_some() {
        return Err("fixture MCP initialization failed".into());
    }
    Ok(())
}
