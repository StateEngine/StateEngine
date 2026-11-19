//! Streaming no-follow DFS; only ignore metadata and active ancestor cursors stay resident.
use super::*;
#[cfg(not(all(windows, feature = "listener")))]
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use se_atlas::source::{SourceDirectory, SourceEntryKind};
#[cfg(not(all(windows, feature = "listener")))]
use std::io::Read;
struct Directory<'a> {
    path: Option<RelativePath>,
    cursor: Box<dyn SourceDirectory + 'a>,
    #[cfg(not(all(windows, feature = "listener")))]
    rules: Gitignore,
    #[cfg(all(windows, feature = "listener"))]
    rules: crate::atlas_renewal::ignore::Rules,
}
pub(super) enum Entry {
    Directory {
        path: Option<RelativePath>,
        #[cfg(all(windows, feature = "listener"))]
        identity: [u8; 32],
    },
    File(RelativePath),
}
fn directory_entry(path: Option<RelativePath>, cursor: &dyn SourceDirectory) -> AtlasResult<Entry> {
    #[cfg(not(all(windows, feature = "listener")))]
    let _ = cursor;
    Ok(Entry::Directory {
        path,
        #[cfg(all(windows, feature = "listener"))]
        identity: cursor.physical_identity()?,
    })
}
#[cfg(not(all(windows, feature = "listener")))]
fn global_rules(root: &std::path::Path, request: &protocol::Request) -> AtlasResult<Gitignore> {
    let mut global = GitignoreBuilder::new(root);
    for pattern in &request.global_patterns {
        global.add_line(None, pattern).map_err(failure)?;
    }
    global.build().map_err(failure)
}
#[cfg(all(windows, feature = "listener"))]
fn ignore_policy(request: &protocol::Request) -> IgnorePolicy {
    IgnorePolicy {
        global_patterns: request.global_patterns.clone(),
        generated_prefixes: request.generated_prefixes.clone(),
        digest: request.ignore_digest,
    }
}
pub(super) fn files(
    source: &RegisteredSource<NativeAtlasSource>,
    request: &protocol::Request,
    deadline: Instant,
    mut visit: impl FnMut(Entry) -> AtlasResult<()>,
) -> AtlasResult<bool> {
    #[cfg(not(all(windows, feature = "listener")))]
    let root = source.scope.registration.canonical_source_root.clone();
    #[cfg(not(all(windows, feature = "listener")))]
    let global = global_rules(&root, request)?;
    #[cfg(all(windows, feature = "listener"))]
    let policy = ignore_policy(request);
    let cursor = source
        .open_directory(None)?
        .ok_or_else(|| failure("registered root disappeared"))?;
    visit(directory_entry(None, cursor.as_ref())?)?;
    let mut stack = vec![Directory {
        path: None,
        cursor,
        #[cfg(not(all(windows, feature = "listener")))]
        rules: rules(source, None)?,
        #[cfg(all(windows, feature = "listener"))]
        rules: crate::atlas_renewal::ignore::Rules::load(source, &policy, "", deadline)?,
    }];
    let mut directories = 1u32;
    while !stack.is_empty() {
        if Instant::now() >= deadline {
            // The caller publishes only the verified prefix and retains
            // discovery-incomplete/TimeLimit until ordinary reconciliation.
            return Ok(false);
        }
        let last = stack.len() - 1;
        let Some(entry) = stack[last].cursor.next_entry()? else {
            if !stack[last].cursor.validate_path()? {
                return Err(failure("source directory changed during discovery"));
            }
            stack.pop();
            continue;
        };
        let Some(name) = entry.name.to_str() else {
            return Err(failure(
                "unsupported non-UTF8 directory entry; discovery incomplete",
            ));
        };
        if matches!(name, ".git" | ".stateengine")
            || matches!(entry.kind, SourceEntryKind::Link | SourceEntryKind::Other)
        {
            continue;
        }
        let spelling = match &stack[last].path {
            None => name.to_owned(),
            Some(parent) => format!("{}/{name}", parent.as_str()),
        };
        let path = RelativePath::new(&spelling)?;
        if se_atlas::policy::built_in_denied(&path) {
            continue;
        }
        let directory = entry.kind == SourceEntryKind::Directory;
        #[cfg(not(all(windows, feature = "listener")))]
        let absolute = root.join(path.as_str());
        #[cfg(not(all(windows, feature = "listener")))]
        let mut ignored = global.matched(&absolute, directory).is_ignore();
        #[cfg(not(all(windows, feature = "listener")))]
        for ancestor in &stack {
            let matched = ancestor.rules.matched(&absolute, directory);
            if matched.is_ignore() {
                ignored = true;
            } else if matched.is_whitelist() {
                ignored = false;
            }
        }
        #[cfg(all(windows, feature = "listener"))]
        let ignored = !stack[last]
            .rules
            .eligible(path.as_str(), directory, &policy, deadline)?;
        if ignored {
            continue;
        }
        if directory {
            directories += 1;
            if stack.len() >= 128 || directories > 32768 {
                return Err(failure("cold directory depth/count budget exhausted"));
            }
            let cursor = source
                .open_directory(Some(&path))?
                .ok_or_else(|| failure("discovered source directory disappeared"))?;
            visit(directory_entry(Some(path.clone()), cursor.as_ref())?)?;
            #[cfg(not(all(windows, feature = "listener")))]
            let rules = rules(source, Some(&path))?;
            #[cfg(all(windows, feature = "listener"))]
            let rules = crate::atlas_renewal::ignore::Rules::load(
                source,
                &policy,
                path.as_str(),
                deadline,
            )?;
            stack.push(Directory {
                path: Some(path),
                cursor,
                rules,
            });
        } else {
            visit(Entry::File(path))?;
        }
    }
    Ok(true)
}
#[cfg(not(all(windows, feature = "listener")))]
fn rules(
    source: &RegisteredSource<NativeAtlasSource>,
    directory: Option<&RelativePath>,
) -> AtlasResult<Gitignore> {
    let relative = match directory {
        None => ".gitignore".into(),
        Some(p) => format!("{}/.gitignore", p.as_str()),
    };
    let root = &source.scope.registration.canonical_source_root;
    let mut builder =
        GitignoreBuilder::new(directory.map_or_else(|| root.clone(), |p| root.join(p.as_str())));
    if let Some(mut file) = source.open(&RelativePath::new(&relative)?)? {
        let before = file.identity()?;
        if before.size > 65536 {
            return Err(failure("ignore file exceeds 64 KiB; discovery incomplete"));
        }
        let mut bytes = Vec::with_capacity(before.size as usize);
        (&mut file)
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(failure)?;
        if bytes.len() > 65536 || file.identity()? != before || !file.validate_path()? {
            return Err(failure("ignore file changed during bounded read"));
        }
        for line in std::str::from_utf8(&bytes).map_err(failure)?.lines() {
            builder.add_line(None, line).map_err(failure)?;
        }
    }
    builder.build().map_err(failure)
}
