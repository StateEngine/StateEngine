use crate::{errors::AtlasResult, lifecycle::*, model::*};
use se_types::code::AtlasText;
/// Finite candidates, including nonexistent paths. Persist them to repair an
/// importer when a formerly missing target appears, without editing the importer.
pub fn candidates(
    importer: &RelativePath,
    import: &ImportRecord,
) -> AtlasResult<Vec<RelativePath>> {
    let mut paths = binding_candidates(importer, import)?;
    for path in namespace_candidates(importer, import)? {
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    Ok(paths)
}
pub(super) fn namespace_candidates(
    importer: &RelativePath,
    import: &ImportRecord,
) -> AtlasResult<Vec<RelativePath>> {
    if import.kind == ImportKind::Rust {
        return rust_paths(importer, &import.spelling, false, import.lexical_scope);
    }
    if import.kind == ImportKind::Python
        && let Some(name) = import.imported_name.as_deref()
    {
        let mut paths = Vec::new();
        for candidate in binding_candidates(importer, import)? {
            let value = candidate.as_str();
            let Some(package) = value
                .strip_suffix("/__init__.py")
                .or_else(|| value.strip_suffix(".py"))
            else {
                continue;
            };
            for suffix in [".py", "/__init__.py"] {
                let path = RelativePath::new(format!("{package}/{name}{suffix}"))?;
                if !paths.contains(&path) {
                    paths.push(path);
                }
            }
        }
        return Ok(paths);
    }
    Ok(Vec::new())
}
pub(super) fn binding_candidates(
    importer: &RelativePath,
    import: &ImportRecord,
) -> AtlasResult<Vec<RelativePath>> {
    let source = importer.as_str();
    let parent = source.rsplit_once('/').map_or("", |(p, _)| p);
    let spelling = import.spelling.as_str();
    let (base, suffixes): (Option<String>, &[&str]) = match import.kind {
        ImportKind::Esm | ImportKind::CommonJs => {
            if !spelling.starts_with('.') {
                return Ok(Vec::new());
            }
            let path = normalize(parent, spelling);
            let explicit = spelling.rsplit('/').next().is_some_and(|s| s.contains('.'));
            (
                path,
                if explicit {
                    &[""]
                } else {
                    &[
                        ".ts",
                        ".tsx",
                        ".js",
                        ".jsx",
                        ".mjs",
                        ".cjs",
                        "/index.ts",
                        "/index.tsx",
                        "/index.js",
                        "/index.jsx",
                        "/index.mjs",
                        "/index.cjs",
                    ]
                },
            )
        }
        ImportKind::Python => {
            let dots = spelling.bytes().take_while(|b| *b == b'.').count();
            let mut prefix = if dots == 0 { "" } else { parent };
            for _ in 1..dots {
                let Some((up, _)) = prefix.rsplit_once('/') else {
                    if prefix.is_empty() {
                        return Ok(Vec::new());
                    }
                    prefix = "";
                    continue;
                };
                prefix = up;
            }
            (
                normalize(prefix, &spelling[dots..].replace('.', "/")),
                if dots > 0 && dots == spelling.len() {
                    &["/__init__.py"]
                } else {
                    &[".py", "/__init__.py"]
                },
            )
        }
        ImportKind::Rust => {
            return rust_paths(
                importer,
                spelling,
                import.imported_name.is_some(),
                import.lexical_scope,
            );
        }
    };
    let Some(base) = base else {
        return Ok(Vec::new());
    };
    let mut result = Vec::new();
    for suffix in suffixes {
        if let Ok(path) = RelativePath::new(format!("{base}{suffix}"))
            && !result.contains(&path)
        {
            result.push(path);
        }
    }
    Ok(result)
}
pub(super) fn rust_paths(
    importer: &RelativePath,
    spelling: &str,
    symbol: bool,
    lexical_scope: u32,
) -> AtlasResult<Vec<RelativePath>> {
    let source = importer.as_str();
    let crate_root = if source.starts_with("src/") {
        "src".to_owned()
    } else if let Some((prefix, _)) = source.rsplit_once("/src/") {
        format!("{prefix}/src")
    } else {
        String::new()
    };
    let parent = source.rsplit_once('/').map_or("", |(p, _)| p);
    let name = source.rsplit('/').next().unwrap_or(source);
    let module = if matches!(name, "lib.rs" | "main.rs" | "mod.rs") {
        parent
    } else {
        source.strip_suffix(".rs").unwrap_or(parent)
    };
    let mut parts = spelling.split("::");
    let first = parts.next().unwrap_or("");
    // Relative paths inside inline modules require their actual module context;
    // a lexical scope number alone is not permission to guess a filesystem path.
    if first != "crate" && lexical_scope != 0 {
        return Ok(Vec::new());
    }
    let mut prefix = match first {
        "crate" => crate_root.clone(),
        "self" | "super" => module.to_owned(),
        _ => return Ok(Vec::new()),
    };
    let mut tail = parts.collect::<Vec<_>>();
    if first == "super" {
        tail.insert(0, "super");
    }
    if symbol {
        tail.pop();
    }
    while tail.first() == Some(&"super") {
        if prefix == crate_root {
            return Ok(Vec::new());
        }
        prefix = prefix.rsplit_once('/').map_or("", |(p, _)| p).to_owned();
        tail.remove(0);
    }
    if tail.last() == Some(&"self") {
        tail.pop();
    }
    if tail
        .iter()
        .any(|p| matches!(*p, "crate" | "super" | "self" | ""))
    {
        return Ok(Vec::new());
    }
    let Some(base) = normalize(&prefix, &tail.join("/")) else {
        return Ok(Vec::new());
    };
    let endings: &[&str] = if base == crate_root {
        match name {
            "lib.rs" => &["/lib.rs"],
            "main.rs" => &["/main.rs"],
            _ => &["/lib.rs", "/main.rs"],
        }
    } else {
        &[".rs", "/mod.rs"]
    };
    endings
        .iter()
        .map(|ending| RelativePath::new(format!("{base}{ending}")))
        .collect()
}
fn normalize(base: &str, value: &str) -> Option<String> {
    if value.starts_with('/') || value.contains(['\\', '\0', ':']) {
        return None;
    }
    let mut parts = base
        .split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    for part in value.split('/') {
        match part {
            "" | "." => (),
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(part),
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}
