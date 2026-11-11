//! A14's process adapter reads prebuilt native caches; it never indexes on query.
//! Its contained-cold SQL profile is a retrieval experiment, not a host RAM witness.
#[path = "atlas_retrieval_adapter/scope.rs"]
mod scope;
use se_atlas::{
    cache::{connection::*, pointer},
    errors::AtlasResult,
    lifecycle::CaseMode,
    model::*,
    query::{QueryReader, ReaderContext, RecordReader},
};
use se_host::{atlas_cache::NativeAtlasCache, atlas_source::NativeAtlasSource};
use se_types::{Read, code::*};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{self, Read as _},
    path::PathBuf,
    time::{Duration, Instant},
};
#[derive(Deserialize)]
struct Request {
    id: String,
    root: PathBuf,
    query: String,
    query_kind: String,
    limit: u16,
    #[serde(default)]
    corpus_revision: String,
    #[serde(default)]
    source_scope: Option<scope::SourceScope>,
}
struct NoRecords;
impl RecordReader for NoRecords {
    fn read(
        &self,
        _: &se_types::ProjectId,
        _: &AtlasPrincipal,
        _: &RecordPointer,
        _: Option<&QueryText>,
    ) -> AtlasResult<Read<RecordHit>> {
        Err(unavailable())
    }
    fn literal_read(
        &self,
        _: &se_types::ProjectId,
        _: &AtlasPrincipal,
        _: &RecordPointer,
        _: &QueryText,
    ) -> AtlasResult<Read<RecordHit>> {
        Err(unavailable())
    }
    fn body(
        &self,
        _: &se_types::ProjectId,
        _: &AtlasPrincipal,
        _: &RecordPointer,
        _: Option<&QueryText>,
    ) -> AtlasResult<Read<HitBody>> {
        Err(unavailable())
    }
}
fn unavailable() -> se_types::SeError {
    se_types::SeError::invalid(
        "retrieval corpus",
        "code-only frozen corpus; authoritative records are not supplied",
    )
}
fn run(request: &Request) -> Result<(Vec<String>, bool, Value), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments.len() != 2 {
        return Err("usage: atlas_retrieval_adapter ROOT_TO_CACHE_HOME_JSON".into());
    }
    let mut mappings: BTreeMap<PathBuf, scope::Mapping> =
        serde_json::from_slice(&std::fs::read(&arguments[1])?)?;
    let root = request.root.canonicalize()?;
    let prepared = mappings
        .remove(&root)
        .ok_or("no prepared native cache for this corpus root")?
        .prepare(request.source_scope.as_ref(), &request.corpus_revision)?;
    let home = &prepared.home;
    let project = se_types::ProjectId::from_parts(1, [42; 10])?;
    let id = RootId::from_parts(1, [43; 10])?;
    let source = NativeAtlasSource::open(
        RootRegistration {
            project: project.clone(),
            root: id.clone(),
            canonical_source_root: root,
            cache: CacheLocation {
                directory: home.join(project.as_str()).join(id.as_str()),
            },
            git_metadata: None,
        },
        CaseMode::Sensitive,
    )?;
    let files = NativeAtlasCache::open(home, source.scope.clone())?
        .ok_or("prepared cache absent; queries do not build it")?;
    let open_started = Instant::now();
    // NativeRuntime::with_reader uses atlas_cold::sql_deadline (five seconds).
    // Opening is separate from the unchanged one-second live-source query.
    let opened = pointer::open_current(
        &files,
        &source.scope,
        ConnectionRole::ExternalReader,
        &SqlProfile::contained_cold(),
        open_started + Duration::from_secs(5),
    );
    eprintln!(
        "{}",
        json!({
            "id": request.id,
            "cache_open_ms": open_started.elapsed().as_secs_f64() * 1000.0,
            "cache_open_state": match &opened {
                Ok(Some(_)) => "present",
                Ok(None) => "absent",
                Err(_) => "unreadable",
            },
        })
    );
    let mut cache = opened?.ok_or("prepared pointer absent; queries do not build it")?;
    prepared.validate_cache(&mut cache.connection)?;
    let mut reader = QueryReader::new(
        &mut cache.connection,
        ReaderContext {
            memory: None,
            viewer: AtlasPrincipal::Human(se_types::HumanId::from_parts(1, [44; 10])?),
            records: &NoRecords,
            source: Some(&source),
            hostless: true,
            epoch_retired: cache.epoch_retired,
            now_unix_ms: None,
            record_feed_current: false,
        },
    );
    let regex = match request.query_kind.as_str() {
        "literal" => false,
        "regex" => true,
        _ => return Err("unsupported query_kind".into()),
    };
    // Use the same compact request budget and exact renderer as the public host.
    let request = se_core::ops::atlas::AtlasFind {
        query: QueryText::new(&request.query)?,
        kind: SearchKind::Code,
        paths: prepared.query.paths,
        languages: prepared.query.languages,
        mode: Some(SearchMode::Literal),
        order: SearchOrder::Relevance,
        full: false,
        regex,
        options: serde_json::from_value(json!({"limit": request.limit, "byte_budget":4096}))?,
    };
    let result = reader.find_compact(&request.query()?, 4096, false)?;
    let rendered = se_atlas::render::search(&result, 4096, false)?;
    if rendered.len() > 4096 {
        return Err("compact consumer exceeded its byte budget".into());
    }
    let Read::Present { value } = result.data else {
        return Err("prepared cache did not return a readable query page".into());
    };
    let paths = value
        .page
        .items()
        .iter()
        .map(|hit| match &hit.target {
            HitTarget::Code(code) => Ok(code.pointer.path.as_str().to_owned()),
            _ => Err("non-code target in code corpus"),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let diagnostics = json!({"text": &value.text, "has_next": value.page.next().is_some()});
    Ok((paths, value.page.window().complete(), diagnostics))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    io::stdin().take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("request exceeds 65536 bytes".into());
    }
    let request: Request = serde_json::from_slice(&bytes)?;
    let mut response = json!({"id":request.id,"rank_version":se_atlas::rank::VERSION,"targets":[],"complete":false,"error":Value::Null});
    match run(&request) {
        Ok((paths, complete, diagnostics)) => {
            response["targets"] = serde_json::to_value(paths)?;
            response["complete"] = complete.into();
            response["diagnostics"] = diagnostics;
            // Acknowledged only after the pinned manifest and native SQL scope
            // have both been accepted, never after postfiltering returned hits.
            response["source_scope"] = serde_json::to_value(&request.source_scope)?;
        }
        Err(error) => response["error"] = error.to_string().into(),
    }
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}
