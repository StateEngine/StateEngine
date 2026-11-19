//! Native contract fixture used only by the managed restart tests.
mod server;
use std::{
    env,
    error::Error,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
type Check<T = ()> = Result<T, Box<dyn Error>>;

fn value(args: &[String], key: &str) -> Check<String> {
    let i = args
        .iter()
        .position(|arg| arg == key)
        .ok_or_else(|| format!("missing {key}"))?;
    args.get(i + 1)
        .cloned()
        .ok_or_else(|| format!("missing value for {key}").into())
}
fn profile(args: &[String]) -> Check<PathBuf> {
    Ok(PathBuf::from(value(args, "--service")?))
}
fn version() {
    println!("secode contract-fixture");
}
fn initialize(path: &Path) -> Check {
    let mut dir = fs::DirBuilder::new();
    dir.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        dir.mode(0o700);
    }
    dir.create(path)?;
    let files = se_proc::NativeProfileFiles::open(path)?;
    let mut stage = files.create_staging(path)?;
    stage.file.write_all(b"fixture:synthetic-secret\n")?;
    drop(stage.file);
    files.publish_no_replace(&stage.path, &path.join("basic.credential"))?;
    // The driver releases initialization only after observing native custody.
    let executable = env::current_exe()?;
    let directory = executable
        .parent()
        .ok_or("fixture executable has no directory")?;
    fs::write(
        directory.join("bootstrap-pid"),
        std::process::id().to_string(),
    )?;
    let until = std::time::Instant::now() + Duration::from_secs(30);
    while !directory.join("bootstrap-release").exists() {
        if std::time::Instant::now() >= until {
            return Err("bootstrap observation timed out".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}
fn registration(path: &Path) -> Check<serde_json::Value> {
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("fixture-registration.json"))?)?;
    Ok(value)
}
fn run_client(args: &[String]) -> Check {
    let profile = profile(args)?;
    let session = value(args, "--session")?;
    let input = value(args, "--input-id")?;
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text)?;
    let policy: serde_json::Value =
        serde_json::from_slice(&fs::read(profile.join("host-policy.json"))?)?;
    server::initialize_mcp(&policy)?;
    let saved = registration(&profile)?;
    let endpoint = saved["endpoint"]
        .as_str()
        .ok_or("fixture endpoint absent")?;
    server::post(
        endpoint,
        "/fixture/input",
        &serde_json::json!({"session":session,"id":input,"text":text}),
    )?;
    loop {
        std::thread::park_timeout(Duration::from_secs(60));
    }
}
fn main_impl() -> Check {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") => {
            version();
            Ok(())
        }
        Some("--external-host-capabilities") => {
            let mut value: serde_json::Value = serde_json::from_str(include_str!(
                "../../judges/secode_headless_capabilities.json"
            ))?;
            value["service"]["shutdown"] = serde_json::json!(["SIGINT", "Ctrl+C"]);
            println!("{value}");
            Ok(())
        }
        Some("init-profile") => initialize(&profile(&args)?),
        Some("status") => {
            println!("{}", registration(&profile(&args)?)?);
            Ok(())
        }
        Some("serve-service") => server::serve(profile(&args)?, false),
        Some("fixture-restart") => server::serve(profile(&args)?, true),
        Some("run") => run_client(&args),
        _ => Err("unsupported fixture command".into()),
    }
}
fn main() {
    if let Err(error) = main_impl() {
        eprintln!("fixture failed: {error}");
        std::process::exit(1);
    }
}
