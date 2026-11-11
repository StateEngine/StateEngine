//! A per-file ceiling cannot see a module that grows sideways into hundreds of
//! files. Each crate's `src/` and each `src/` directory at depth one and two
//! has a line budget and a file-count budget; nested files count toward every
//! ancestor at depth one and two. Growth past a budget is refused, and a
//! budget entry for a crate or directory that no longer exists is refused too:
//! a dead number is a budget nobody is maintaining.
use super::*;

const BUDGETS: &str = include_str!("../module-budgets.json");
const BUDGETS_PATH: &str = "crates/se-types/tests/module-budgets.json";
const FILES: &str = include_str!("../files-per-dir.json");
const FILES_PATH: &str = "crates/se-types/tests/files-per-dir.json";

struct LineBudgets {
    default_crate: usize,
    default_directory: usize,
    crates: BTreeMap<String, usize>,
    directories: BTreeMap<String, usize>,
}

struct FileBudgets {
    default_directory: usize,
    directories: BTreeMap<String, usize>,
}

fn sizes(value: &Value, label: &str, path: &str) -> Result<BTreeMap<String, usize>, String> {
    required_object(value, label)?
        .iter()
        .map(|(name, lines)| {
            let lines = lines
                .as_u64()
                .and_then(|lines| usize::try_from(lines).ok())
                .ok_or_else(|| format!("{path}: {label}.{name} must be a line count"))?;
            Ok((name.clone(), lines))
        })
        .collect()
}

fn line_budgets(source: &str) -> Result<LineBudgets, String> {
    let document: Value =
        serde_json::from_str(source).map_err(|error| format!("{BUDGETS_PATH}: {error}"))?;
    Ok(LineBudgets {
        default_crate: required_usize(&document["default_crate_lines"], "default_crate_lines")?,
        default_directory: required_usize(
            &document["default_directory_lines"],
            "default_directory_lines",
        )?,
        crates: sizes(&document["crates"], "crates", BUDGETS_PATH)?,
        directories: sizes(&document["directories"], "directories", BUDGETS_PATH)?,
    })
}

fn file_budgets(source: &str) -> Result<FileBudgets, String> {
    let document: Value =
        serde_json::from_str(source).map_err(|error| format!("{FILES_PATH}: {error}"))?;
    Ok(FileBudgets {
        default_directory: required_usize(
            &document["default_directory_files"],
            "default_directory_files",
        )?,
        directories: sizes(&document["directories"], "directories", FILES_PATH)?,
    })
}

/// Lines and file counts per crate `src/` and per `src/` directory at depth
/// one and two.
fn measured(
    inventory: &BTreeMap<String, Vec<u8>>,
) -> (
    BTreeMap<String, usize>,
    BTreeMap<String, usize>,
    BTreeMap<String, usize>,
) {
    let mut crates = BTreeMap::new();
    let mut directories = BTreeMap::new();
    let mut files = BTreeMap::new();
    for (path, source) in inventory {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() < 4 || parts[0] != "crates" || parts[2] != "src" {
            continue;
        }
        let lines = physical_line_count(source);
        *crates.entry(parts[1].to_owned()).or_insert(0) += lines;
        let nested = &parts[3..parts.len() - 1];
        for depth in 1..=nested.len().min(2) {
            let directory = [&parts[..3], &nested[..depth]].concat().join("/");
            *directories.entry(directory.clone()).or_insert(0) += lines;
            *files.entry(directory).or_insert(0) += 1;
        }
    }
    (crates, directories, files)
}

fn over_budget(
    kind: &str,
    now: &BTreeMap<String, usize>,
    limits: &BTreeMap<String, usize>,
    default: usize,
    path: &str,
) -> Vec<String> {
    let mut problems = Vec::new();
    for (name, lines) in now {
        let limit = limits.get(name).copied().unwrap_or(default);
        if *lines > limit {
            problems.push(format!(
                "{kind} {name} has {lines} lines, over its budget of {limit}; split it by responsibility into its own module or crate"
            ));
        }
    }
    for name in limits.keys().filter(|name| !now.contains_key(*name)) {
        problems.push(format!(
            "{kind} {name} no longer exists; delete it from {path}"
        ));
    }
    problems
}

fn over_file_budget(
    now: &BTreeMap<String, usize>,
    limits: &BTreeMap<String, usize>,
    default: usize,
) -> Vec<String> {
    let mut problems = Vec::new();
    for (name, count) in now {
        let limit = limits.get(name).copied().unwrap_or(default);
        if *count > limit {
            problems.push(format!(
                "directory {name} has {count} Rust files, over its budget of {limit}; split the folder along a real responsibility boundary"
            ));
        }
    }
    for name in limits.keys().filter(|name| !now.contains_key(*name)) {
        problems.push(format!(
            "directory {name} no longer exists; delete it from {FILES_PATH}"
        ));
    }
    problems
}

#[test]
fn crates_and_source_directories_stay_within_their_budgets() -> Result<(), Box<dyn Error>> {
    let budgets = line_budgets(BUDGETS)?;
    let files = file_budgets(FILES)?;
    let inventory = rust_source_inventory(&workspace_root())?;
    let (crates, directories, file_counts) = measured(&inventory);
    let mut problems = over_budget(
        "crate",
        &crates,
        &budgets.crates,
        budgets.default_crate,
        BUDGETS_PATH,
    );
    problems.extend(over_budget(
        "directory",
        &directories,
        &budgets.directories,
        budgets.default_directory,
        BUDGETS_PATH,
    ));
    problems.extend(over_file_budget(
        &file_counts,
        &files.directories,
        files.default_directory,
    ));
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n").into())
    }
}

#[test]
fn growth_past_a_budget_and_a_stale_entry_are_refused() {
    let inventory = BTreeMap::from([
        ("crates/demo/src/area/part.rs".to_owned(), vec![b'\n'; 30]),
        ("crates/demo/src/lib.rs".to_owned(), vec![b'\n'; 5]),
    ]);
    let (crates, directories, file_counts) = measured(&inventory);
    assert_eq!(crates.get("demo"), Some(&35));
    assert_eq!(directories.get("crates/demo/src/area"), Some(&30));
    assert_eq!(file_counts.get("crates/demo/src/area"), Some(&1));

    let line_limits = BTreeMap::from([
        ("crates/demo/src/area".to_owned(), 29),
        ("crates/demo/src/gone".to_owned(), 10),
    ]);
    let line_problems = over_budget(
        "directory",
        &directories,
        &line_limits,
        10_000,
        BUDGETS_PATH,
    );
    assert_eq!(line_problems.len(), 2);
    assert!(line_problems[0].contains("over its budget of 29"));
    assert!(line_problems[1].contains("no longer exists"));

    let file_limits = BTreeMap::from([
        ("crates/demo/src/area".to_owned(), 1),
        ("crates/demo/src/gone".to_owned(), 4),
    ]);
    let file_problems = over_file_budget(&file_counts, &file_limits, 12);
    assert_eq!(file_problems.len(), 1);
    assert!(file_problems[0].contains("no longer exists"));

    let file_limits = BTreeMap::from([("crates/demo/src/area".to_owned(), 0)]);
    let file_problems = over_file_budget(&file_counts, &file_limits, 12);
    assert_eq!(file_problems.len(), 1);
    assert!(file_problems[0].contains("over its budget of 0"));
}
