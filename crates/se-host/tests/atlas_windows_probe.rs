//! Native Atlas component observations on an otherwise unchanged checkout.
#[path = "../../test-support/directory_owner.rs"]
mod directory_owner;
#[path = "atlas_windows_probe/native.rs"]
mod native;
#[path = "atlas_windows_probe/parser.rs"]
mod parser;
#[allow(dead_code)]
#[path = "../src/atlas_runtime/project_work.rs"]
mod project_work;
#[path = "atlas_windows_probe/sql.rs"]
mod sql;

use se_atlas::{lifecycle::CaseMode, model::*, source::RegisteredSource};
use se_host::atlas_source::NativeAtlasSource;
use serde_json::{Value, json};
use std::{
    error::Error,
    fs,
    path::PathBuf,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

type Observed<T> = Result<T, Box<dyn Error>>;
type Source = RegisteredSource<NativeAtlasSource>;

struct Fixture {
    source: Source,
    home: PathBuf,
    directory: directory_owner::PrivateDirectory,
}

impl Fixture {
    fn new() -> Observed<Self> {
        se_proc::initialize_file_creation_owner()?;
        let directory = std::env::temp_dir().join(format!(
            "atlas-components-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        ));
        fs::create_dir(&directory)?;
        let directory = directory_owner::PrivateDirectory::for_case(directory.canonicalize()?);
        let source_path = directory.join("source");
        fs::create_dir(&source_path)?;
        let home = directory.join("atlas");
        let project = se_types::ProjectId::from_parts(1, [1; 10])?;
        let root = RootId::from_parts(1, [2; 10])?;
        let source = NativeAtlasSource::open(
            RootRegistration {
                cache: CacheLocation {
                    directory: home.join(project.as_str()).join(root.as_str()),
                },
                project,
                root,
                canonical_source_root: source_path,
                git_metadata: None,
            },
            if cfg!(windows) {
                CaseMode::InsensitivePreserving
            } else {
                CaseMode::Sensitive
            },
        )?;
        Ok(Self {
            source,
            home,
            directory,
        })
    }
}

fn timed<T>(work: impl FnOnce() -> Observed<T>) -> Observed<(T, u64)> {
    let started = Instant::now();
    let value = work()?;
    Ok((value, started.elapsed().as_nanos().try_into()?))
}

fn output(section: &str, report: &Value) -> Observed<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/judge-diagnostics");
    fs::create_dir_all(&root)?;
    fs::write(
        root.join(format!("atlas-components-{section}.json")),
        serde_json::to_vec_pretty(report)?,
    )?;
    Ok(())
}

#[test]
fn atlas_components_native() -> Observed<()> {
    if let Ok(case) = std::env::var("ATLAS_COMPONENT_CASE") {
        println!("ATLAS_CASE {}", parser::observe(&case)?);
        return Ok(());
    }
    let environment = json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "debug_assertions": cfg!(debug_assertions),
        "logical_processors": std::thread::available_parallelism()?.get(),
        "runner_image": std::env::var("ImageOS").ok(),
        "runner_image_version": std::env::var("ImageVersion").ok(),
        "run_id": std::env::var("GITHUB_RUN_ID").ok(),
        "run_attempt": std::env::var("GITHUB_RUN_ATTEMPT").ok(),
    });
    output("environment", &environment)?;
    let fixture = Fixture::new()?;
    output("status", &sql::status(&fixture)?)?;
    output("sql", &sql::observe(&fixture)?)?;
    fixture.directory.finish(Ok::<(), Box<dyn Error>>(()))?;
    parser::run()
}
