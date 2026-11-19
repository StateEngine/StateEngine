use super::*;

/// Retains the notifications issued while the cold worker reads its snapshot.
pub(super) struct Capture {
    pub id: RootId,
    pub native: Native,
    pub registration: se_proc::NativeWatchRegistration,
    pub activated: bool,
}

impl Capture {
    pub fn start(source: &Source, policy: &AtlasPolicy, used: usize) -> AtlasResult<Option<Self>> {
        let scope = &source.scope;
        let prepared = (|| -> AtlasResult<_> {
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
            let available = NativeSourceWatch::observed_limit()
                .map_or(1024, |n| (n / 8).min(MAX_MAP as u64) as u32);
            let cap = policy
                .watch
                .max_directories
                .min(available)
                .min((policy.watch.max_mapping_bytes / 16).min(MAX_MAP as u32));
            if used >= cap as usize {
                return Err(source_error(
                    "cold source subscription",
                    "watch budget exhausted",
                ));
            }
            Ok((root, cap))
        })();
        let Ok((root, cap)) = prepared else {
            return Ok(None);
        };
        let Ok(mut watch) = NativeSourceWatch::new() else {
            return Ok(None);
        };
        let subscriptions = (|| -> AtlasResult<_> {
            let registration = watch
                .subscribe_tree(&root)
                .map_err(|error| source_error("cold source subscription", error))?
                .ok_or_else(|| source_error("cold source subscription", "source disappeared"))?;
            let metadata = if let Some(git) = &scope.registration.git_metadata {
                let watches = metadata::Watches::install(
                    git,
                    &watch,
                    (cap as usize).saturating_sub(used + 1),
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
            Ok((registration, metadata))
        })();
        let (registration, metadata) = match subscriptions {
            Ok(value) => value,
            Err(_) => {
                let timeout = Duration::from_millis(200);
                watch
                    .shutdown(timeout)
                    .map_err(|error| crate::atlas_parse::cleanup_error(error, timeout))?;
                return Ok(None);
            }
        };
        Ok(Some(Self {
            id: scope.registration.root.clone(),
            native: Native {
                root,
                watch,
                metadata,
                state: WatchState::Active,
            },
            registration,
            activated: false,
        }))
    }

    pub fn watch_count(&self) -> usize {
        1 + self
            .native
            .metadata
            .as_ref()
            .map_or(0, metadata::Watches::len)
    }
}
