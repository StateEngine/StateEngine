//! Impact pages show a defining file's inline tests at zero hops, never an
//! empty byte range or a hop back to the dependent itself, and an unmeasured
//! extent reads as unavailable rather than zero bytes.
use se_atlas::render;
use se_types::{ProjectId, Read, code::*};

type Check = Result<(), Box<dyn std::error::Error>>;

fn answer(value: Impact) -> Result<Answer<Read<Impact>>, Box<dyn std::error::Error>> {
    Ok(Answer {
        index: IndexSummary {
            project: ProjectId::from_parts(1, [1; 10])?,
            root: RootId::from_parts(1, [2; 10])?,
            epoch: None,
            generation: None,
            state: IndexState::Current,
            coverage: serde_json::from_value(serde_json::json!({
                "discovered_files":2,"indexed_files":2,"partial_files":0,
                "deferred_files":0,"failed_files":0,"discovery_complete":true,
                "stale_files":0,"resolved_references":0,"name_only_references":0,
                "watched_directories":0,"unwatched_directories":0,
                "watch_discovery_complete":true,"watch_stats_started":null,
                "watch_activation_attempts":0,"watch_limited_activations":0,"reasons":[]
            }))?,
            memory: None,
        },
        snapshot_advanced: false,
        epoch_retired: false,
        data: Read::Present { value },
    })
}

fn span(line: u32, start_byte: u64, end_byte: u64) -> Span {
    Span {
        start: Position {
            line,
            byte_column: 0,
        },
        end: Position {
            line,
            byte_column: 4,
        },
        start_byte,
        end_byte,
    }
}

fn at(file: u8, path: &str, span: Option<Span>) -> Result<CodePointer, Box<dyn std::error::Error>> {
    Ok(CodePointer {
        file: FileId([file; 16]),
        path: RelativePath::new(path)?,
        span,
        content_hash: None,
        freshness: SnapshotFreshness::Current,
    })
}

fn dependent(pointer: CodePointer, file_hops: Vec<FileImpactHop>) -> Dependent {
    Dependent {
        pointer,
        symbol: None,
        hops: Vec::new(),
        file_hops,
    }
}

fn page(
    dependents: Vec<Dependent>,
    tests: Vec<Dependent>,
) -> Result<String, Box<dyn std::error::Error>> {
    let value = Impact {
        dependents,
        tests,
        records: Vec::new(),
        omitted_frontier: 0,
        frontier_count_complete: true,
        next: None,
        complete: true,
    };
    Ok(render::impact(&answer(value)?, 65_536)?)
}

#[test]
fn inline_tests_render_at_zero_hops() -> Check {
    let output = page(
        Vec::new(),
        vec![dependent(at(1, "src/lib.rs", None)?, Vec::new())],
    )?;
    assert!(
        output.contains("src/lib.rs · 0 hops · possible test\n"),
        "{output}"
    );
    assert!(!output.contains('→'), "{output}");
    Ok(())
}

#[test]
fn file_hops_skip_self_sites_and_empty_ranges() -> Check {
    let caller = at(2, "src/caller.rs", None)?;
    let self_hop = FileImpactHop {
        from: FileId([2; 16]),
        to: FileId([1; 16]),
        site: caller.clone(),
        start_byte: 0,
        end_byte: 0,
        accuracy: Accuracy::ImportedFile,
    };
    let output = page(vec![dependent(caller, vec![self_hop])], Vec::new())?;
    let line = output.lines().next().ok_or("empty page")?;
    assert_eq!(line, "src/caller.rs · 1 hop (ImportedFile)");
    assert!(!output.contains("bytes 0..0"), "{output}");

    let elsewhere = FileImpactHop {
        from: FileId([2; 16]),
        to: FileId([1; 16]),
        site: at(3, "src/site.rs", Some(span(4, 10, 20)))?,
        start_byte: 10,
        end_byte: 20,
        accuracy: Accuracy::ExplicitImport,
    };
    let output = page(
        vec![dependent(at(2, "src/caller.rs", None)?, vec![elsewhere])],
        Vec::new(),
    )?;
    assert!(
        output.contains(" → src/site.rs:4 (10 B) bytes 10..20 (ExplicitImport)"),
        "{output}"
    );
    Ok(())
}

#[test]
fn empty_byte_span_shows_no_size_not_zero_bytes() -> Check {
    let output = page(
        vec![
            dependent(at(1, "src/empty.rs", Some(span(7, 5, 5)))?, Vec::new()),
            dependent(at(2, "src/sized.rs", Some(span(3, 5, 17)))?, Vec::new()),
        ],
        Vec::new(),
    )?;
    assert!(output.contains("src/empty.rs:7 · "), "{output}");
    assert!(!output.contains("(0 B)"), "{output}");
    assert!(output.contains("src/sized.rs:3 (12 B)"), "{output}");
    Ok(())
}
