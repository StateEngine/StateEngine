use super::*;

/// Retains the notifications issued while the cold worker reads its snapshot.
pub(super) struct Capture {
    pub id: RootId,
    pub native: Native,
    pub registration: se_proc::NativeWatchRegistration,
    pub activated: bool,
}

impl Capture {
    pub fn start(source: &Source, policy: &AtlasPolicy) -> AtlasResult<Self> {
        let scope = &source.scope;
        let root = NativeSourceRoot::open(&scope.registration.canonical_source_root)
            .map_err(|error| source_error("cold source activation", error))?;
        if root
            .physical_identity()
            .map_err(|error| source_error("cold source activation", error))?
            != scope.physical_root
        {
            return Err(source_error(
                "cold source activation",
                "physical root changed; rebind",
            ));
        }
        let watch =
            NativeSourceWatch::new().map_err(|error| source_error("cold source watch", error))?;
        let registration = watch
            .subscribe_tree(&root)
            .map_err(|error| source_error("cold source subscription", error))?
            .ok_or_else(|| source_error("cold source subscription", "source disappeared"))?;
        let available = NativeSourceWatch::observed_limit()
            .map_or(1024, |n| (n / 8).min(MAX_MAP as u64) as u32);
        let cap = policy
            .watch
            .max_directories
            .min(available)
            .min((policy.watch.max_mapping_bytes / 16).min(MAX_MAP as u32));
        if cap == 0 {
            return Err(source_error(
                "cold source subscription",
                "watch budget exhausted",
            ));
        }
        let metadata = if let Some(git) = &scope.registration.git_metadata {
            let watches = metadata::Watches::install(
                git,
                &watch,
                cap.saturating_sub(1) as usize,
                Instant::now() + Duration::from_millis(200),
            )?;
            if !watches.complete || watches.lock_held()? {
                return Err(source_error(
                    "cold metadata subscription",
                    "incomplete or locked",
                ));
            }
            Some(watches)
        } else {
            None
        };
        Ok(Self {
            id: scope.registration.root.clone(),
            native: Native {
                root,
                watch,
                metadata,
                state: WatchState::Active,
            },
            registration,
            activated: false,
        })
    }
}
