//! Extractor edge cases and store invariants, exercised through the public API.
use se_atlas_index::{
    IndexError,
    custody::{GuardedRead, IndexSourceRoot},
    extract::{Extracted, ImportKind, SymbolKind, extract, flags, imports::Resolver},
    store::{BuildOptions, CompactPolicy, Reader, RebuildReason, Store, StoreIdentity},
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU32, Ordering},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> std::io::Result<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "se-atlas-index-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    fn write(&self, relative: &str, text: &str) -> std::io::Result<()> {
        let path = self.0.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, text)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn outline(extracted: &Extracted) -> Vec<(SymbolKind, &str, Option<&str>)> {
    extracted
        .symbols
        .iter()
        .map(|symbol| {
            let parent = symbol
                .parent
                .and_then(|index| extracted.symbols.get(index))
                .map(|parent| parent.name.as_str());
            (symbol.kind, symbol.name.as_str(), parent)
        })
        .collect()
}

fn spellings(extracted: &Extracted) -> Vec<&str> {
    extracted
        .imports
        .iter()
        .map(|spec| spec.spelling.as_str())
        .collect()
}

#[test]
fn rust_outline_handles_multiline_headers_and_use_trees() {
    let source = "use crate::{\n    cache::connection,\n    query::{find, Reader as R},\n};\npub use self::inner::Thing;\nmod tests;\n\n/// \"{ not a block\"\n#[derive(Debug)]\npub struct Holder<'a> { name: &'a str }\n\nimpl<'a>\n    Display for\n    Holder<'a>\n{\n    fn fmt(&self) -> String {\n        let brace = '{';\n        format!(\"}}\")\n    }\n}\n\npub(crate) async fn run() {}\n";
    let extracted = extract("crates/demo/src/lib.rs", source.as_bytes(), false);
    assert_eq!(
        outline(&extracted),
        [
            (SymbolKind::Module, "tests", None),
            (SymbolKind::Struct, "Holder", None),
            (SymbolKind::Impl, "Holder", None),
            (SymbolKind::Method, "fmt", Some("Holder")),
            (SymbolKind::Function, "run", None),
        ]
    );
    let holder = &extracted.symbols[1];
    assert!(holder.exported && holder.sig.starts_with("pub struct Holder"));
    let fmt = &extracted.symbols[3];
    assert_eq!((fmt.line, fmt.end_line), (16, 19));
    assert_eq!(extracted.symbols[2].end_line, 20);
    assert_eq!(
        spellings(&extracted),
        [
            "crate::cache::connection",
            "crate::query::find",
            "crate::query",
            "self::inner",
            "mod tests"
        ]
    );
    assert!(extracted.imports[3].reexport);
    assert_eq!(extracted.imports[4].kind, ImportKind::Module);
}

#[test]
fn typescript_go_and_python_outlines_and_imports() {
    let ts = "import {\n  a,\n  b,\n} from './util';\nexport { c } from \"./barrel\";\nconst re = /[{'\"]/g;\nexport const handler = async (x: number) => {\n  return x;\n};\nexport class Service extends Base {\n  constructor() { super(); }\n  async load<T>(id: string): Promise<T> { return fetch(id); }\n  if (x) {}\n}\n";
    let extracted = extract("web/src/service.ts", ts.as_bytes(), false);
    assert_eq!(
        outline(&extracted),
        [
            (SymbolKind::Const, "re", None),
            (SymbolKind::Function, "handler", None),
            (SymbolKind::Class, "Service", None),
            (SymbolKind::Method, "constructor", Some("Service")),
            (SymbolKind::Method, "load", Some("Service")),
        ]
    );
    assert_eq!(spellings(&extracted), ["./util", "./barrel"]);
    assert!(extracted.imports[1].reexport);

    let go = "package demo\n\nimport (\n\t\"fmt\"\n\tlog \"github.com/acme/repo/pkg/log\"\n)\n\ntype Server struct {\n\tName string\n}\n\nfunc (s *Server) Start() error {\n\treturn nil\n}\n\nfunc helper() {}\n";
    let extracted = extract("cmd/server.go", go.as_bytes(), false);
    assert_eq!(
        outline(&extracted),
        [
            (SymbolKind::Struct, "Server", None),
            (SymbolKind::Method, "Start", Some("Server")),
            (SymbolKind::Function, "helper", None),
        ]
    );
    assert_eq!(
        spellings(&extracted),
        ["fmt", "github.com/acme/repo/pkg/log"]
    );

    let py = "from . import (\n    sibling,\n)\nimport os.path as p\nMAX = 3\n\nclass Store:\n    def get(self):\n        return '''\n    def not_code():\n'''\n\n    async def put(self):\n        pass\n\ndef test_store():\n    pass\n";
    let extracted = extract("pkg/test_store.py", py.as_bytes(), false);
    assert_eq!(
        outline(&extracted),
        [
            (SymbolKind::Const, "MAX", None),
            (SymbolKind::Class, "Store", None),
            (SymbolKind::Method, "get", Some("Store")),
            (SymbolKind::Method, "put", Some("Store")),
            (SymbolKind::Function, "test_store", None),
        ]
    );
    assert_eq!(extracted.symbols[2].end_line, 11);
    assert_eq!(spellings(&extracted), [".sibling", "os.path"]);
    assert_ne!(extracted.flags & flags::TEST, 0);
}

#[test]
fn structured_text_outlines_are_syntactic() {
    let yaml = "name: CI\non:\n  push:\njobs:\n  build:\n    steps:\n      - name: Check out\n        run: |\n          key: not a key\n      - name: Test\n";
    let extracted = extract(".github/workflows/ci.yml", yaml.as_bytes(), false);
    let names: Vec<_> = outline(&extracted);
    assert!(names.contains(&(SymbolKind::Key, "build", Some("jobs"))));
    assert!(names.contains(&(SymbolKind::Item, "Check out", Some("steps"))));
    assert!(names.contains(&(SymbolKind::Item, "Test", Some("steps"))));
    assert!(!names.iter().any(|(_, name, _)| *name == "key"));

    let markdown = "# Guide\n\n```\n# not a heading\n```\n## Install\n### Linux\n## Use\n";
    let extracted = extract("docs/guide.md", markdown.as_bytes(), false);
    assert_eq!(
        outline(&extracted),
        [
            (SymbolKind::Section, "Guide", None),
            (SymbolKind::Section, "Install", Some("Guide")),
            (SymbolKind::Section, "Linux", Some("Install")),
            (SymbolKind::Section, "Use", Some("Guide")),
        ]
    );

    let sql = "-- CREATE TABLE ignored (x);\nCREATE TABLE IF NOT EXISTS users (\n id INTEGER\n);\nCREATE UNIQUE INDEX users_id ON users(id);\n";
    let extracted = extract("db/schema.sql", sql.as_bytes(), false);
    assert_eq!(
        outline(&extracted),
        [
            (SymbolKind::Table, "users", None),
            (SymbolKind::Key, "users_id", None)
        ]
    );
    assert_eq!(
        (extracted.symbols[0].line, extracted.symbols[0].end_line),
        (2, 4)
    );
}

#[test]
fn binary_bom_minified_and_lock_files_are_classified() {
    let binary = extract("assets/blob.bin", b"abc\0def", false);
    assert_eq!(binary.flags & flags::BINARY, flags::BINARY);
    assert!(binary.tokens.iter().any(|(token, _)| token == "blob"));
    assert!(!binary.tokens.iter().any(|(token, _)| token == "def"));

    let bom = extract("src/main.rs", "\u{feff}fn main() {}\n".as_bytes(), false);
    assert_eq!(bom.symbols[0].name, "main");
    assert!(
        !bom.tokens
            .iter()
            .any(|(token, _)| token.contains('\u{feff}'))
    );

    let long_line = format!("var x = \"{}\";\n", "a".repeat(5000));
    let minified = extract("dist/app.js", long_line.as_bytes(), false);
    assert_eq!(minified.flags & flags::MINIFIED, flags::MINIFIED);
    assert!(minified.symbols.is_empty());

    let lock = extract("Cargo.lock", b"[[package]]\nname = \"serde\"\n", false);
    assert_ne!(lock.flags & flags::GENERATED, 0);
    assert!(lock.symbols.is_empty() && lock.tokens.iter().any(|(t, _)| t == "cargo"));
    assert!(!lock.tokens.iter().any(|(t, _)| t == "serde"));
}

fn postings(reader: &Reader, token: &str) -> Result<Vec<(i64, u32)>, IndexError> {
    match reader.token_id(token)? {
        Some(id) => reader.read_postings(id),
        None => Ok(Vec::new()),
    }
}

fn count(store: &Store, sql: &str) -> Result<i64, Box<dyn std::error::Error>> {
    Ok(store.connection().query_row(sql, [], |row| row.get(0))?)
}

#[test]
fn incremental_saves_write_only_deltas_and_compaction_folds_them() -> TestResult {
    let repo = TempDir::new("repo")?;
    repo.write("src/lib.rs", "mod alpha;\npub fn shared_name() {}\n")?;
    repo.write("src/alpha.rs", "pub fn alpha_only() { shared_name(); }\n")?;
    repo.write(".env", "TOKEN=synthetic\n")?;
    repo.write("tests/alpha.rs", "use demo::alpha;\n#[test]\nfn t() {}\n")?;
    let state = TempDir::new("state")?;
    let db = state.0.join("atlas.db");
    let root = IndexSourceRoot::open(&repo.0)?;
    let (mut store, reason) = Store::open(&db, &StoreIdentity::default())?;
    assert_eq!(reason, Some(RebuildReason::Missing));
    let report = store.cold_build(&root, &BuildOptions::default())?;
    assert!(report.discovery_complete);
    assert_eq!(report.indexed, 3);
    let reader = Reader::open(&db)?;
    assert_eq!(postings(&reader, "shared_name")?.len(), 2);
    assert_eq!(postings(&reader, "synthetic")?.len(), 0);

    let base_df: i64 = store.connection().query_row(
        "SELECT df FROM vocab WHERE tok='shared_name'",
        [],
        |row| row.get(0),
    )?;
    let base_blob: Vec<u8> = store.connection().query_row(
        "SELECT postings FROM vocab_post p JOIN vocab v ON v.id=p.tok WHERE v.tok='shared_name'",
        [],
        |row| row.get(0),
    )?;
    repo.write(
        "src/alpha.rs",
        "pub fn alpha_only() { brand_new_word(); }\n",
    )?;
    let GuardedRead::Source(source) = root.read_guarded_file("src/alpha.rs")? else {
        return Err("alpha.rs must be readable".into());
    };
    let resolver = Resolver::new(["src/lib.rs", "src/alpha.rs", "tests/alpha.rs"]);
    let update = store.update_file(&resolver, "src/alpha.rs", &source)?;
    assert_eq!(update.symbols.body_changed.len(), 1);
    assert_eq!(
        update.delta_rows,
        count(&store, "SELECT count(*) FROM post_delta")? as usize
    );
    let df_after: i64 = store.connection().query_row(
        "SELECT df FROM vocab WHERE tok='shared_name'",
        [],
        |row| row.get(0),
    )?;
    let blob_after: Vec<u8> = store.connection().query_row(
        "SELECT postings FROM vocab_post p JOIN vocab v ON v.id=p.tok WHERE v.tok='shared_name'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!((df_after, &blob_after), (base_df, &base_blob));
    let shared = reader.token_id("shared_name")?.ok_or("token")?;
    assert_eq!(reader.effective_df(shared)?, 1);
    assert_eq!(postings(&reader, "brand_new_word")?.len(), 1);
    let live_before = postings(&reader, "brand_new_word")?;

    let compacted = store.compact_deltas(&CompactPolicy::default(), true)?;
    assert!(compacted.tokens > 0);
    assert_eq!(count(&store, "SELECT count(*) FROM post_delta")?, 0);
    assert_eq!(count(&store, "SELECT count(*) FROM gram_delta")?, 0);
    assert_eq!(postings(&reader, "brand_new_word")?, live_before);
    assert_eq!(reader.effective_df(shared)?, 1);

    assert!(store.remove_file("src/alpha.rs")?);
    assert_eq!(postings(&reader, "brand_new_word")?.len(), 0);
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM sym s JOIN files f ON f.id=s.file WHERE f.path='src/alpha.rs'"
        )?,
        0
    );
    Ok(())
}

#[test]
fn damaged_or_foreign_store_files_are_rebuilt_empty() -> TestResult {
    let state = TempDir::new("damaged")?;
    let db = state.0.join("atlas.db");
    let (store, _) = Store::open(&db, &StoreIdentity::default())?;
    let damaged = store.path().to_path_buf();
    drop(store);
    fs::write(
        &damaged,
        b"this is not a database file, padded well past one header page",
    )?;
    let (store, reason) = Store::open(&db, &StoreIdentity::default())?;
    assert_eq!(reason, Some(RebuildReason::Corrupt));
    assert_eq!(count(&store, "SELECT count(*) FROM files")?, 0);
    let journal: String = store
        .connection()
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    assert_eq!(journal, "wal");
    drop(store);
    let (_, reason) = Store::open(&db, &StoreIdentity::default())?;
    assert_eq!(reason, None);
    assert!(!damaged.exists());
    Ok(())
}
