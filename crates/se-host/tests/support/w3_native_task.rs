//! The actual SE Code boundary: no judge-constructed CapturedTurn supplies this proof.
use super::*;

fn required_file(name: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(std::env::var_os(name).ok_or_else(|| format!("missing {name}"))?);
    if !path.is_absolute() || !path.is_file() {
        return Err(format!(
            "{name} must name an absolute regular file: {}",
            path.display()
        ));
    }
    Ok(path)
}
fn read_json(path: &Path) -> Result<serde_json::Value, String> {
    serde_json::from_slice(&std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?)
        .map_err(|e| format!("{}: {e}", path.display()))
}
fn field<'a>(value: &'a serde_json::Value, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing string {name}"))
}
fn file_digest(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(se_types::hex_lower(&Sha256::digest(bytes)))
}

/// Protects W3: an unpredictable judge nonce crosses link/bind, a native task,
/// real write/read tool effects and both durable public history events. Missing
/// inputs or any driver/product failure fails, retaining the isolated fixture.
#[test]
fn native_secode_task_captures_the_judge_nonce_through_public_surfaces() -> Result<(), String> {
    let driver = required_file("SE_W3_NATIVE_DRIVER")?;
    let server = required_file("SE_W3_SECODE_SERVER")?;
    let product = std::env::var("SE_W3_PRODUCT_COMMIT").map_err(|e| e.to_string())?;
    if product.len() != 40 || !product.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("SE_W3_PRODUCT_COMMIT must be the exact candidate commit".into());
    }
    let mut judge = Judge::new("native")?;
    judge.retain = true;
    let secret = se_proc::random_secret().map_err(|e| format!("judge nonce: {e:?}"))?;
    let nonce = se_types::hex_lower(&secret.expose()[..16]);
    let repo = judge.root.join("repo");
    let output = judge.root.join("native-witness");
    let server_hash = file_digest(&server)?;
    let helper_hash = file_digest(&judge.helper)?;
    std::fs::write(judge.root.join("judge-nonce.txt"), &nonce).map_err(|e| e.to_string())?;
    let python = std::env::var_os("SE_W3_PYTHON").unwrap_or_else(|| "python3".into());
    let result = Command::new(python)
        .arg(&driver)
        .args(["--secode-server"])
        .arg(&server)
        .args(["--se"])
        .arg(&judge.helper)
        .args(["--root"])
        .arg(&output)
        .args(["--state-home"])
        .arg(&judge.home)
        .args(["--repo"])
        .arg(&repo)
        .args([
            "--project",
            &judge.project,
            "--agent",
            &judge.agent,
            "--nonce",
            &nonce,
        ])
        .env_clear()
        .envs(owner_env(&judge.home))
        .current_dir(&repo)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("native driver launch: {e}"))?;
    std::fs::write(judge.root.join("driver.stdout"), &result.stdout).map_err(|e| e.to_string())?;
    std::fs::write(judge.root.join("driver.stderr"), &result.stderr).map_err(|e| e.to_string())?;
    if !result.status.success() {
        return Err(format!(
            "native driver exited {}; retained {}: {}",
            result.status,
            judge.root.display(),
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    let witness = read_json(&output.join("witness.json"))?;
    assert_eq!(witness["outcome"], "captured");
    assert_eq!(witness["nonce"], nonce);
    assert_eq!(witness["branch_tip"], product);
    assert_eq!(witness["project"], judge.project);
    assert_eq!(witness["agent"], judge.agent);
    assert_eq!(witness["state_home"], judge.home.to_string_lossy().as_ref());
    let inputs = read_json(&output.join("inputs.json"))?;
    assert_eq!(inputs["server_sha256"], server_hash);
    assert_eq!(inputs["se_sha256"], helper_hash);
    assert_eq!(file_digest(&server)?, server_hash);
    assert_eq!(file_digest(&judge.helper)?, helper_hash);
    let conversation = field(&witness, "conversation")?;
    assert!(
        conversation.starts_with("ses_"),
        "native conversation absent"
    );
    let task = field(&witness, "task_text")?;
    assert!(task.contains(&nonce) && task.contains('π') && task.contains("café"));
    let effect = witness
        .get("file_effect")
        .ok_or("missing native file effect")?;
    let effect_path = PathBuf::from(field(effect, "path")?);
    assert_eq!(effect_path.parent(), Some(repo.as_path()));
    assert!(
        effect_path
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.contains(&nonce))
    );
    let expected_file = format!("W3 native task {nonce}: π and café\n");
    assert_eq!(
        std::fs::read_to_string(&effect_path).map_err(|e| e.to_string())?,
        expected_file
    );
    assert_eq!(effect["text"], expected_file);

    // Read the retained native HTTP response, then independently read the
    // durable events through fresh CLI processes, rather than trusting the
    // driver's expected_text or cached public CLI stdout.
    let history = read_json(&output.join("native-history.json"))?;
    let messages = history["data"]
        .as_array()
        .ok_or("native history is not a list")?;
    assert!(
        !messages
            .iter()
            .any(|m| m.get("error").is_some_and(|e| !e.is_null()) || m["finish"] == "error")
    );
    let users: Vec<_> = messages.iter().filter(|m| m["type"] == "user").collect();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["text"], task);
    let finals: Vec<_> = messages
        .iter()
        .filter(|m| m["type"] == "assistant" && m["finish"] == "stop")
        .collect();
    assert_eq!(finals.len(), 1);
    let content = finals[0]["content"]
        .as_array()
        .ok_or("native answer lacks content")?;
    let assistant: String = content
        .iter()
        .filter(|v| v["type"] == "text")
        .map(|v| field(v, "text"))
        .collect::<Result<Vec<_>, _>>()?
        .concat();
    assert!(!assistant.is_empty(), "native final answer is empty");
    let tools: Vec<_> = messages
        .iter()
        .filter_map(|m| m["content"].as_array())
        .flatten()
        .filter(|v| v["type"] == "tool")
        .collect();
    let names: Vec<_> = tools
        .iter()
        .map(|v| field(v, "name"))
        .collect::<Result<_, _>>()?;
    assert_eq!(names, ["write", "read"]);
    assert!(tools.iter().all(|v| v["state"]["status"] == "completed"));
    let records = witness["public_history"]
        .as_array()
        .ok_or("public history coordinates absent")?;
    assert_eq!(records.len(), 2);
    let mut seen = std::collections::BTreeSet::new();
    for record in records {
        let role = field(record, "role")?;
        assert!(seen.insert(role), "duplicate native captured role");
        let text = match role {
            "user" => task,
            "assistant" => &assistant,
            _ => return Err("unexpected native capture role".into()),
        };
        assert_public_turn(
            &judge,
            field(record, "event_id")?,
            conversation,
            role,
            field(record, "native_event")?,
            text,
        )?;
    }
    assert_eq!(
        seen,
        std::collections::BTreeSet::from(["assistant", "user"])
    );
    let exited = read_json(&output.join("exit.json"))?;
    assert_eq!(exited["exit"], 0);
    assert_eq!(exited["ready_retired"], true);
    println!(
        "W3 native task PASS: fresh nonce, native write/read, exact provider conversation, UTF-8 bytes and two public durable captures; fixture {}",
        judge.root.display()
    );
    Ok(())
}
