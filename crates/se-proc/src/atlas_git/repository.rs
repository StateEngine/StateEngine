//! Registered metadata custody and bounded first-parent commit windows.
use super::*;
use crate::source_root::NativeSourceRoot;
use std::{io::Read, path::PathBuf};
pub const WINDOW_BYTES: usize = 65_536;
pub const MAX_COMMITS: u16 = 128;
#[derive(Clone, Debug)]
pub struct GitRegistration {
    pub git_directory: PathBuf,
    pub common_directory: PathBuf,
    pub git_identity: [u8; 32],
    pub common_identity: [u8; 32],
}
#[derive(Clone, Debug)]
pub struct GitCommit {
    pub oid: String,
    pub parent: Option<String>,
    pub author_unix_ms: i64,
    pub author: String,
    pub subject: String,
    pub paths: Vec<String>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HistoryLimit {
    Complete,
    CommitCount,
    Bytes,
}
pub struct GitWindow {
    /// Exact requested start, which may be an older continuation, not live HEAD.
    pub start: String,
    pub next: Option<String>,
    pub limit: HistoryLimit,
    pub commits: Vec<GitCommit>,
}
pub struct GitRepository {
    image: PathBuf,
    git: NativeSourceRoot,
    common: NativeSourceRoot,
    objects: NativeSourceRoot,
    objects_path: PathBuf,
    object_fence: std::cell::RefCell<Option<super::objects::Fence>>,
    control: super::control::Control,
}
impl GitRepository {
    /// The host supplies registered physical metadata identities and an absent
    /// protected staging directory. None from head() is an unborn branch only.
    pub fn open(image: &Path, registration: &GitRegistration, control: &Path) -> io::Result<Self> {
        let git = NativeSourceRoot::open(&registration.git_directory)?;
        let common = NativeSourceRoot::open(&registration.common_directory)?;
        if git.physical_identity()? != registration.git_identity
            || common.physical_identity()? != registration.common_identity
        {
            return Err(invalid(
                "registered Git metadata root identity changed; rebind the source",
            ));
        }
        let objects_path = registration.common_directory.join("objects");
        let objects = common.subroot("objects")?;
        if objects.open_relative("info/alternates")?.is_some()
            || objects.open_relative("info/http-alternates")?.is_some()
        {
            return Err(invalid(
                "Git history with alternate object directories is outside the registered bounded reader",
            ));
        }
        let head = resolve(&git, &common)?;
        let private =
            super::control::Control::create(control, head.as_ref().is_some_and(|s| s.len() == 64))?;
        Ok(Self {
            image: image.into(),
            git,
            common,
            objects,
            objects_path,
            object_fence: std::cell::RefCell::new(None),
            control: private,
        })
    }
    pub fn head(&self) -> io::Result<Option<String>> {
        resolve(&self.git, &self.common)
    }
    fn command(&self, command: GitRead<'_>, deadline: Instant) -> io::Result<Vec<u8>> {
        self.git.check()?;
        self.common.check()?;
        self.objects.check()?;
        self.control.check()?;
        let mut retained = self.object_fence.borrow_mut();
        // A namespace update invalidates the cached complete no-follow scan.
        // Re-scan current names; errors from that fresh observation propagate.
        if retained
            .as_ref()
            .is_none_or(|f| f.check(&self.objects).is_err())
        {
            *retained = Some(super::objects::Fence::open(&self.objects, deadline)?);
        }
        let fence = retained
            .as_ref()
            .ok_or_else(|| invalid("Git object fence was not initialized"))?;
        fence.check(&self.objects)?;
        let output = read_pinned(
            &self.image,
            self.control.path(),
            &self.objects_path,
            [self.control.root(), &self.objects],
            command,
            deadline,
        )?;
        self.git.check()?;
        self.common.check()?;
        self.objects.check()?;
        self.control.check()?;
        fence.check(&self.objects)?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "bounded Git history refused ({}, 64000000-byte address-space cap): {}; source index remains available",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(output.stdout)
    }
    pub fn root_tree(&self, commit: &str, deadline: Instant) -> io::Result<String> {
        let out = self.command(GitRead::RootTree { commit }, deadline)?;
        let text = std::str::from_utf8(&out)
            .map_err(|_| invalid("Git root tree has invalid encoding"))?
            .trim_end();
        oid(text)?;
        Ok(text.into())
    }
    pub fn window(&self, start: &str, maximum: u16, deadline: Instant) -> io::Result<GitWindow> {
        if !(1..=MAX_COMMITS).contains(&maximum) {
            return Err(invalid("Git history window requires 1..128 commits"));
        }
        let output = self.command(
            GitRead::Log {
                start,
                commits: maximum + 1,
            },
            deadline,
        )?;
        let metadata = metadata(&output)?;
        let mut result = GitWindow {
            start: start.into(),
            next: None,
            limit: HistoryLimit::Complete,
            commits: Vec::new(),
        };
        let mut used = 0;
        for mut commit in metadata {
            if result.commits.len() == usize::from(maximum) {
                result.next = Some(commit.oid);
                result.limit = HistoryLimit::CommitCount;
                break;
            }
            let bytes = self.command(
                GitRead::Changed {
                    commit: &commit.oid,
                    parent: commit.parent.as_deref(),
                },
                deadline,
            )?;
            if !bytes.is_empty() && bytes.last() != Some(&0) {
                return Err(invalid(
                    "Git changed paths lack the complete native terminator",
                ));
            }
            for path in bytes
                .strip_suffix(&[0])
                .unwrap_or(&[])
                .split(|b| *b == 0)
                .filter(|_| !bytes.is_empty())
            {
                let path = std::str::from_utf8(path).map_err(|_| {
                    invalid(
                        "Git history path encoding is unsupported; source index remains available",
                    )
                })?;
                if path.is_empty() || path.len() > 1024 || commit.paths.len() == 256 {
                    return Err(invalid(
                        "Git history commit exceeds the complete 256-path/1024-byte path bound; source index remains available",
                    ));
                }
                commit.paths.push(path.into());
            }
            let cost = std::mem::size_of::<GitCommit>()
                + commit.oid.capacity()
                + commit.parent.as_ref().map_or(0, String::capacity)
                + commit.author.capacity()
                + commit.subject.capacity()
                + commit.paths.capacity() * std::mem::size_of::<String>()
                + commit.paths.iter().map(String::capacity).sum::<usize>();
            if cost > WINDOW_BYTES {
                return Err(invalid(
                    "one Git history commit exceeds the 65536-byte window; source index remains available",
                ));
            }
            if used + cost > WINDOW_BYTES {
                result.next = Some(commit.oid);
                result.limit = HistoryLimit::Bytes;
                break;
            }
            used += cost;
            result.commits.push(commit);
        }
        Ok(result)
    }
    pub fn close(mut self) -> io::Result<()> {
        // A read error may have terminated a child in Drop. A poisoned lease
        // means exact reap failed; callers must not treat that as source-only success.
        #[cfg(target_os = "linux")]
        let _reaped = crate::atlas_worker::lease::Lease::acquire()?;
        self.control.close()
    }
}
fn metadata(bytes: &[u8]) -> io::Result<Vec<GitCommit>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| invalid("Git commit metadata encoding is unsupported"))?;
    let mut fields = text.split_terminator('\0');
    let mut result = Vec::new();
    while let Some(id) = fields.next() {
        oid(id)?;
        let parents = fields
            .next()
            .ok_or_else(|| invalid("Git parent field missing"))?;
        let parent = parents.split_ascii_whitespace().next().map(str::to_owned);
        for value in parents.split_ascii_whitespace() {
            oid(value)?;
        }
        let seconds = fields
            .next()
            .ok_or_else(|| invalid("Git author time missing"))?
            .parse::<i64>()
            .map_err(|_| invalid("Git author time is not an integer"))?;
        let author = fields.next().ok_or_else(|| invalid("Git author missing"))?;
        let subject = fields
            .next()
            .ok_or_else(|| invalid("Git subject missing"))?;
        if fields.next() != Some("")
            || author.len() > 512
            || subject.len() > 1024
            || result.len() == 129
        {
            return Err(invalid("Git metadata exceeds complete bounded fields"));
        }
        result.push(GitCommit {
            oid: id.to_ascii_lowercase(),
            parent,
            author_unix_ms: seconds
                .checked_mul(1000)
                .ok_or_else(|| invalid("Git timestamp overflow"))?,
            author: author.into(),
            subject: subject.into(),
            paths: Vec::new(),
        });
    }
    if result.is_empty() {
        return Err(invalid("Git returned no commit for an exact object ID"));
    }
    Ok(result)
}

fn small(root: &NativeSourceRoot, path: &str) -> io::Result<Option<String>> {
    let Some(mut file) = root.open_relative(path)? else {
        return Ok(None);
    };
    let before = file.revision()?;
    let mut bytes = Vec::new();
    file.by_ref().take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 || file.revision()? != before || !file.validate_name()? {
        return Err(invalid(
            "Git reference exceeds bounds or changed during read",
        ));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| invalid("Git reference is not UTF-8"))
}
fn resolve(git: &NativeSourceRoot, common: &NativeSourceRoot) -> io::Result<Option<String>> {
    let head = small(git, "HEAD")?.ok_or_else(|| {
        invalid("registered Git HEAD is absent; repository metadata is unreadable")
    })?;
    let text = head.trim_end_matches(['\r', '\n']);
    let result = if let Some(reference) = text.strip_prefix("ref: ") {
        if !reference.starts_with("refs/")
            || reference
                .split('/')
                .any(|s| s.is_empty() || s == "." || s == "..")
            || reference.contains(['\\', '\0', '\r', '\n'])
        {
            return Err(invalid("Git HEAD has an unsupported symbolic reference"));
        }
        if let Some(value) = small(common, reference)? {
            let value = value.trim_end_matches(['\r', '\n']);
            oid(value)?;
            Some(value.to_ascii_lowercase())
        } else {
            packed(common, reference)?
        }
    } else {
        oid(text)?;
        Some(text.to_ascii_lowercase())
    };
    if small(git, "HEAD")?.as_deref() != Some(head.as_str()) {
        return Err(invalid("Git HEAD changed while resolving its object ID"));
    }
    Ok(result)
}
fn packed(root: &NativeSourceRoot, reference: &str) -> io::Result<Option<String>> {
    use std::io::{BufRead, BufReader};
    let Some(mut file) = root.open_relative("packed-refs")? else {
        return Ok(None);
    };
    let before = file.revision()?;
    if before.size > 4_000_000 {
        return Err(invalid(
            "Git packed refs exceed the 4000000-byte read bound",
        ));
    }
    let mut reader = BufReader::with_capacity(4096, &mut file);
    let mut bytes = Vec::new();
    let mut result = None;
    let mut consumed = 0usize;
    loop {
        bytes.clear();
        let n = reader.by_ref().take(4097).read_until(b'\n', &mut bytes)?;
        consumed += n;
        if consumed > 4_000_000 {
            return Err(invalid(
                "Git packed refs grew beyond the 4000000-byte read bound",
            ));
        }
        if n == 0 {
            break;
        }
        if n > 4096 {
            return Err(invalid("Git packed reference line exceeds 4096 bytes"));
        }
        let line = std::str::from_utf8(&bytes)
            .map_err(|_| invalid("Git packed reference encoding is unsupported"))?
            .trim_end_matches(['\r', '\n']);
        if line.starts_with(['#', '^']) {
            continue;
        }
        let (value, name) = line
            .split_once(' ')
            .ok_or_else(|| invalid("Git packed reference is malformed"))?;
        if name == reference {
            oid(value)?;
            if result.is_some() {
                return Err(invalid("duplicate packed Git reference"));
            }
            result = Some(value.to_ascii_lowercase());
        }
    }
    drop(reader);
    if file.revision()? != before || !file.validate_name()? {
        return Err(invalid("Git packed refs changed during read"));
    }
    Ok(result)
}
