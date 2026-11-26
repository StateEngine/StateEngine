//! SemVer 2.0.0 parsing and floor comparison for provider CLI versions,
//! including `-prerelease` and `+build` suffixes.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Semver {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub prerelease: bool,
}

impl Semver {
    /// Whether this version satisfies a release floor `(major, minor, patch)`.
    /// Per SemVer 2.0.0, a prerelease of the floor itself (e.g. `1.2.3-rc.1`
    /// against `1.2.3`) is below the floor, while any prerelease of a higher
    /// core version (e.g. `1.2.4-alpha.1` against `1.2.3`) satisfies it, and
    /// build metadata (`+build`) does not affect precedence.
    pub fn meets_minimum(self, minimum: (u16, u16, u16)) -> bool {
        let core = (self.major, self.minor, self.patch);
        core > minimum || (core == minimum && !self.prerelease)
    }
}

/// Parse `MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]`.
pub fn parse_semver(text: &str) -> Option<Semver> {
    let (without_build, build) = match text.split_once('+') {
        Some((head, tail)) => (head, Some(tail)),
        None => (text, None),
    };
    if let Some(build) = build
        && !valid_build_identifiers(build)
    {
        return None;
    }
    let (core, prerelease) = match without_build.split_once('-') {
        Some((head, tail)) => (head, Some(tail)),
        None => (without_build, None),
    };
    if let Some(pre) = prerelease
        && !valid_prerelease_identifiers(pre)
    {
        return None;
    }
    let mut parts = core.split('.');
    let major = parse_numeric_part(parts.next()?)?;
    let minor = parse_numeric_part(parts.next()?)?;
    let patch = parse_numeric_part(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some(Semver {
        major,
        minor,
        patch,
        prerelease: prerelease.is_some(),
    })
}

fn parse_numeric_part(part: &str) -> Option<u16> {
    if part.is_empty()
        || !part.bytes().all(|byte| byte.is_ascii_digit())
        || (part.len() > 1 && part.starts_with('0'))
    {
        return None;
    }
    part.parse::<u16>().ok()
}

/// SemVer 2.0.0 §9: numeric prerelease identifiers MUST NOT include leading zeroes.
fn valid_prerelease_identifiers(text: &str) -> bool {
    !text.is_empty()
        && text.split('.').all(|ident| {
            !ident.is_empty()
                && ident
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !(ident.len() > 1
                    && ident.starts_with('0')
                    && ident.bytes().all(|byte| byte.is_ascii_digit()))
        })
}

/// SemVer 2.0.0 §10: build metadata identifiers MAY include leading zeroes.
fn valid_build_identifiers(text: &str) -> bool {
    !text.is_empty()
        && text.split('.').all(|ident| {
            !ident.is_empty()
                && ident
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}
