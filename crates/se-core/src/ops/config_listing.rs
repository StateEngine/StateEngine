//! The effective user configuration read is a static file-policy window:
//! bounded static pages over the closed config.toml key set.
use super::{ConfigList, inputs::Validate};
use crate::scope;
use se_config::config_policy::{Approval, ConfigFile, Provider, Sandbox};
use se_types::{
    Cursor, Omission, OmissionReason, Page, Read, Result, SeError, Sequence, Source, StopReason,
    WindowFields,
};
use serde_json::{Value, json};
use std::num::{NonZeroU32, NonZeroU64};

/// Bounded static pages over the closed config.toml key set. Every row is
/// the effective typed setting; only Option fields can be absent. `--origin`
/// reports the adapter-resolved file-level origin on every row and refuses
/// when the bound adapter carries none instead of inventing one. A page is
/// bounded by the requested row limit and the wire byte budget; the returned
/// cursor continues the list, so a valid large configuration lists completely
/// across pages instead of refusing the whole file.
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub fn list(
    configuration: &ConfigFile,
    origin: Option<&str>,
    input: ConfigList,
) -> Result<super::ConfigPageOutput> {
    input.validate()?;
    let origin = match (input.origin, origin) {
        (true, Some(origin)) => Some(origin.to_owned()),
        (true, None) => {
            return Err(scope::unreadable(
                "configuration origin",
                "the bound adapter carries no configuration origin",
            ));
        }
        (false, _) => None,
    };
    let mut rows: Vec<super::ConfigValueOutput> = Vec::new();
    let row = |rows: &mut Vec<super::ConfigValueOutput>, key: &str, value: Read<Value>| {
        rows.push(super::ConfigValueOutput {
            key: key.to_owned(),
            value,
            origin: origin.clone(),
        });
    };
    row(
        &mut rows,
        "default_project",
        present(json!(configuration.default_project)),
    );
    row(
        &mut rows,
        "launch.provider",
        present(json!(provider_wire(configuration.launch.provider))),
    );
    row(
        &mut rows,
        "launch.terminal",
        present(json!(configuration.launch.terminal)),
    );
    row(
        &mut rows,
        "runtime.listen_port",
        option(&configuration.runtime.listen_port),
    );
    row(
        &mut rows,
        "runtime.blocking_jobs",
        option(&configuration.runtime.blocking_jobs),
    );
    for (name, provider) in [
        ("claude", &configuration.providers.claude),
        ("codex", &configuration.providers.codex),
        ("secode", &configuration.providers.secode),
        ("acp", &configuration.providers.acp),
    ] {
        row(
            &mut rows,
            &format!("providers.{name}.command"),
            option(&provider.command),
        );
        row(
            &mut rows,
            &format!("providers.{name}.model"),
            present(json!(provider.model)),
        );
        row(
            &mut rows,
            &format!("providers.{name}.profile"),
            present(json!(provider.profile)),
        );
    }
    row(
        &mut rows,
        "providers.secode.seed_profile",
        option(&configuration.providers.secode.seed_profile),
    );
    for (key, value) in [
        ("acp.arguments", json!(configuration.acp.arguments)),
        ("acp.environment", json!(configuration.acp.environment)),
        ("acp.mode", json!(configuration.acp.mode)),
    ] {
        row(&mut rows, key, present(value));
    }
    for (name, profile) in &configuration.profiles {
        row(
            &mut rows,
            &format!("profiles.{name}.sandbox"),
            present(json!(sandbox_wire(profile.sandbox))),
        );
        row(
            &mut rows,
            &format!("profiles.{name}.network"),
            present(json!(profile.network)),
        );
        let approval = match &profile.approval {
            Some(approval) => present(json!(approval_wire(*approval))),
            None => Read::Absent {
                checked: "not set in the effective configuration".into(),
            },
        };
        row(&mut rows, &format!("profiles.{name}.approval"), approval);
        row(
            &mut rows,
            &format!("profiles.{name}.bypass"),
            present(json!(profile.bypass)),
        );
        row(
            &mut rows,
            &format!("profiles.{name}.git_write"),
            present(json!(profile.git_write)),
        );
    }
    row(
        &mut rows,
        "atlas.enabled",
        present(json!(configuration.atlas.enabled)),
    );
    row(
        &mut rows,
        "atlas.hooks",
        present(json!(configuration.atlas.hooks)),
    );
    row(
        &mut rows,
        "capture.enabled",
        present(json!(configuration.capture.enabled)),
    );
    // The row set is static, so the cursor is a plain row count: the rows
    // before it are the pages the caller already received.
    let offset = cursor_offset(input.cursor.as_ref())?;
    let total = rows.len() as u64;
    if offset > total {
        return Err(SeError::invalid(
            "cursor",
            "a config list cursor within the row set; it names a row past the end",
        ));
    }
    // Exact per-row wire sizes: serde_json writes a Vec as `[a,b,c]`, so a
    // page's bytes are the two brackets, the row sizes, and one comma per gap.
    let sizes: Vec<u64> = rows
        .iter()
        .map(|row| {
            serde_json::to_vec(row)
                .map(|bytes| bytes.len() as u64)
                .map_err(|cause| {
                    scope::unreadable("configuration row encoding", &cause.to_string())
                })
        })
        .collect::<Result<Vec<u64>>>()?;
    const PAGE_MAX_BYTES: u32 = 192 * 1024;
    let limit = u64::from(input.limit);
    let mut end = offset;
    let mut bytes: u64 = 2;
    while end < total && end - offset < limit {
        let next = bytes
            .checked_add(if end == offset { 0 } else { 1 })
            .and_then(|sum| sum.checked_add(sizes[end as usize]))
            .ok_or_else(|| SeError::invalid("configuration page", "a nonoverflowing byte count"))?;
        if next > u64::from(PAGE_MAX_BYTES) {
            break;
        }
        bytes = next;
        end += 1;
    }
    if end == offset && offset < total {
        return Err(SeError::invalid(
            "configuration row",
            "a single row within the 192 KiB page byte budget",
        ));
    }
    let stop = if end == total {
        StopReason::Exhausted
    } else if end - offset == limit {
        StopReason::ItemLimit
    } else {
        StopReason::ByteLimit
    };
    let omitted_after = match stop {
        StopReason::Exhausted => Omission::None,
        other => Omission::Known {
            count: NonZeroU64::new(total - end).ok_or_else(|| {
                SeError::invalid("configuration page", "a nonempty remainder past the page")
            })?,
            reason: if other == StopReason::ItemLimit {
                OmissionReason::Limit
            } else {
                OmissionReason::Budget
            },
        },
    };
    let end_cursor = Cursor::new(format!("config-list/v1/{end}"))?;
    let fields = WindowFields {
        source: Source::Configuration {
            location: origin
                .clone()
                .unwrap_or_else(|| "effective configuration".into()),
        },
        from: Sequence::new(offset)?,
        to: Sequence::new(end)?,
        start_cursor: input.cursor.clone(),
        end_cursor: Some(end_cursor.clone()),
        returned: end - offset,
        limit: NonZeroU32::new(u32::from(input.limit))
            .ok_or_else(|| SeError::invalid("configuration page", "at least one setting row"))?,
        bytes,
        max_bytes: NonZeroU32::new(PAGE_MAX_BYTES)
            .ok_or_else(|| SeError::invalid("configuration page", "a nonzero byte budget"))?,
        omitted_before: Omission::None,
        omitted_after,
        unreadable: 0,
        stop_reason: stop,
    };
    let next = (stop != StopReason::Exhausted).then_some(end_cursor);
    let items = rows[offset as usize..end as usize].to_vec();
    Ok(super::ConfigPageOutput {
        page: Page::new(items, se_types::Window::new(fields)?, next)?,
    })
}
fn cursor_offset(cursor: Option<&Cursor>) -> Result<u64> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let rest = cursor
        .as_str()
        .strip_prefix("config-list/v1/")
        .ok_or_else(|| SeError::invalid("cursor", "a config list cursor"))?;
    rest.parse()
        .map_err(|_| SeError::invalid("cursor", "a config list cursor"))
}
fn present(value: Value) -> Read<Value> {
    Read::Present { value }
}
fn option<T: serde::Serialize>(value: &Option<T>) -> Read<Value> {
    match value {
        Some(value) => Read::Present {
            value: json!(value),
        },
        None => Read::Absent {
            checked: "not set in the effective configuration".into(),
        },
    }
}
fn provider_wire(provider: Provider) -> &'static str {
    match provider {
        Provider::Claude => "claude",
        Provider::Codex => "codex",
        Provider::SeCode => "secode",
        Provider::Acp => "acp",
    }
}
fn sandbox_wire(sandbox: Sandbox) -> &'static str {
    match sandbox {
        Sandbox::ReadOnly => "read-only",
        Sandbox::WorkspaceWrite => "workspace-write",
    }
}
fn approval_wire(approval: Approval) -> &'static str {
    match approval {
        Approval::OnRequest => "on-request",
        Approval::Untrusted => "untrusted",
        Approval::Never => "never",
    }
}
#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "a failing test names the missing configuration row"
)]
mod list_tests {
    use super::*;
    use se_config::config_policy::Profile;

    const EXPECTED_KEYS: &[&str] = &[
        "default_project",
        "launch.provider",
        "launch.terminal",
        "runtime.listen_port",
        "runtime.blocking_jobs",
        "providers.claude.command",
        "providers.claude.model",
        "providers.claude.profile",
        "providers.codex.command",
        "providers.codex.model",
        "providers.codex.profile",
        "providers.secode.command",
        "providers.secode.model",
        "providers.secode.profile",
        "providers.acp.command",
        "providers.acp.model",
        "providers.acp.profile",
        "providers.secode.seed_profile",
        "acp.arguments",
        "acp.environment",
        "acp.mode",
        "profiles.default.sandbox",
        "profiles.default.network",
        "profiles.default.approval",
        "profiles.default.bypass",
        "profiles.default.git_write",
        "atlas.enabled",
        "atlas.hooks",
        "capture.enabled",
    ];

    fn expected_keys(configuration: &ConfigFile) -> Vec<String> {
        let mut expected: Vec<String> = EXPECTED_KEYS.iter().map(|key| (*key).to_owned()).collect();
        let start = EXPECTED_KEYS
            .iter()
            .position(|key| key.starts_with("profiles.default."))
            .expect("closed key set contains the default profile");
        let fields: Vec<&str> = EXPECTED_KEYS
            .iter()
            .filter_map(|key| key.strip_prefix("profiles.default."))
            .collect();
        let profiles = configuration.profiles.keys().flat_map(|name| {
            fields
                .iter()
                .map(move |field| format!("profiles.{name}.{field}"))
        });
        expected.splice(start..start + fields.len(), profiles);
        expected
    }

    fn value<'a>(page: &'a super::super::ConfigPageOutput, key: &'a str) -> &'a Read<Value> {
        &page
            .page
            .items()
            .iter()
            .find(|row| row.key == key)
            .expect("listed row present")
            .value
    }

    #[test]
    fn list_reports_the_closed_key_set_in_stable_order() -> Result<()> {
        let page = list(
            &ConfigFile::default(),
            None,
            ConfigList {
                origin: false,
                limit: 100,
                cursor: None,
            },
        )?;
        let keys: Vec<&str> = page
            .page
            .items()
            .iter()
            .map(|row| row.key.as_str())
            .collect();
        assert_eq!(keys, EXPECTED_KEYS);
        assert!(page.page.window().complete());
        assert!(page.page.next().is_none());
        assert!(page.page.items().iter().all(|row| row.origin.is_none()));
        Ok(())
    }

    #[test]
    fn list_shows_set_values_with_wire_strings_and_unset_options_as_absent() -> Result<()> {
        let mut configuration = ConfigFile::default();
        configuration.launch.provider = Provider::SeCode;
        configuration.launch.terminal = "conhost".into();
        configuration.runtime.blocking_jobs = Some(4);
        configuration.providers.codex.command = Some("/usr/local/bin/codex".into());
        configuration.providers.secode.seed_profile = Some("seed".into());
        let default_profile = configuration
            .profiles
            .get_mut("default")
            .expect("default profile present");
        default_profile.approval = Some(Approval::Untrusted);
        default_profile.sandbox = Sandbox::ReadOnly;
        default_profile.network = true;
        let page = list(
            &configuration,
            None,
            ConfigList {
                origin: false,
                limit: 100,
                cursor: None,
            },
        )?;
        assert_eq!(
            value(&page, "launch.provider"),
            &Read::Present {
                value: json!("secode")
            }
        );
        assert_eq!(
            value(&page, "launch.terminal"),
            &Read::Present {
                value: json!("conhost")
            }
        );
        assert_eq!(
            value(&page, "runtime.listen_port"),
            &Read::Absent {
                checked: "not set in the effective configuration".into()
            }
        );
        assert_eq!(
            value(&page, "runtime.blocking_jobs"),
            &Read::Present { value: json!(4) }
        );
        assert_eq!(
            value(&page, "providers.codex.command"),
            &Read::Present {
                value: json!("/usr/local/bin/codex")
            }
        );
        assert_eq!(
            value(&page, "providers.claude.command"),
            &Read::Absent {
                checked: "not set in the effective configuration".into()
            }
        );
        assert_eq!(
            value(&page, "providers.secode.seed_profile"),
            &Read::Present {
                value: json!("seed")
            }
        );
        assert_eq!(
            value(&page, "profiles.default.approval"),
            &Read::Present {
                value: json!("untrusted")
            }
        );
        assert_eq!(
            value(&page, "profiles.default.sandbox"),
            &Read::Present {
                value: json!("read-only")
            }
        );
        assert_eq!(
            value(&page, "profiles.default.network"),
            &Read::Present { value: json!(true) }
        );
        Ok(())
    }

    #[test]
    fn list_binds_the_file_level_origin_to_every_row_on_request() -> Result<()> {
        let configuration = ConfigFile::default();
        let page = list(
            &configuration,
            Some("config.toml /home/owner/.stateengine/config.toml"),
            ConfigList {
                origin: true,
                limit: 100,
                cursor: None,
            },
        )?;
        assert!(page.page.items().iter().all(|row| {
            row.origin.as_deref() == Some("config.toml /home/owner/.stateengine/config.toml")
        }));
        assert!(
            list(
                &configuration,
                None,
                ConfigList {
                    origin: true,
                    limit: 100,
                    cursor: None,
                },
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn list_pages_a_large_configuration_to_completion() -> Result<()> {
        let mut configuration = ConfigFile::default();
        for index in 0..600 {
            configuration
                .profiles
                .insert(format!("profile-{index:03}"), Profile::default());
        }
        let expected = expected_keys(&configuration);
        let mut collected: Vec<String> = Vec::new();
        let mut cursor = None;
        let mut pages = 0;
        loop {
            let page = list(
                &configuration,
                None,
                ConfigList {
                    origin: false,
                    limit: 100,
                    cursor: cursor.clone(),
                },
            )?;
            let fields = page.page.window().fields().expect("producer window");
            assert!(fields.bytes <= 192 * 1024, "page within the byte budget");
            assert_eq!(fields.returned, page.page.items().len() as u64);
            for row in page.page.items() {
                collected.push(row.key.clone());
            }
            pages += 1;
            if page.page.window().complete() {
                assert!(page.page.next().is_none());
                assert_eq!(fields.stop_reason, StopReason::Exhausted);
                break;
            }
            assert_eq!(fields.stop_reason, StopReason::ItemLimit);
            assert_eq!(
                page.page.window().omitted().reason,
                Some(OmissionReason::Limit)
            );
            assert_eq!(
                page.page.window().omitted().count,
                Some(expected.len() as u64 - collected.len() as u64)
            );
            // A bounded page is not a failure: the owner CLI stays exit 0.
            assert_eq!(page.page.window().exit_code(false), 0);
            cursor = Some(page.page.next().cloned().expect("continuation cursor"));
        }
        assert_eq!(pages, expected.len().div_ceil(100));
        assert_eq!(collected, expected);
        Ok(())
    }

    #[test]
    fn list_continues_from_a_cursor_without_overlap_or_gap() -> Result<()> {
        let mut configuration = ConfigFile::default();
        for index in 0..300 {
            configuration
                .profiles
                .insert(format!("profile-{index:03}"), Profile::default());
        }
        let first = list(
            &configuration,
            None,
            ConfigList {
                origin: false,
                limit: 100,
                cursor: None,
            },
        )?;
        let next = first.page.next().cloned().expect("continuation cursor");
        let last = first
            .page
            .items()
            .last()
            .expect("first page rows")
            .key
            .clone();
        let second = list(
            &configuration,
            None,
            ConfigList {
                origin: false,
                limit: 100,
                cursor: Some(next),
            },
        )?;
        let second_fields = second.page.window().fields().expect("producer window");
        assert_eq!(second_fields.from.get(), first_fields_to(first));
        assert_ne!(
            second.page.items().first().expect("second page rows").key,
            last
        );
        assert!(
            second.page.items().iter().all(|row| row.key != last),
            "no row repeats across the boundary"
        );
        Ok(())
    }
    fn first_fields_to(page: super::super::ConfigPageOutput) -> u64 {
        page.page
            .window()
            .fields()
            .expect("producer window")
            .to
            .get()
    }

    #[test]
    fn list_stops_a_page_at_the_byte_budget() -> Result<()> {
        let mut configuration = ConfigFile::default();
        for index in 0..300 {
            configuration
                .profiles
                .insert(format!("profile-{index:03}"), Profile::default());
        }
        let origin = format!("config.toml {}", "x".repeat(4000));
        let first = list(
            &configuration,
            Some(&origin),
            ConfigList {
                origin: true,
                limit: 500,
                cursor: None,
            },
        )?;
        let fields = first.page.window().fields().expect("producer window");
        assert_eq!(fields.stop_reason, StopReason::ByteLimit);
        assert!(fields.bytes <= 192 * 1024, "budgeted page");
        assert_eq!(
            first.page.window().omitted().reason,
            Some(OmissionReason::Budget)
        );
        assert_eq!(first.page.window().exit_code(false), 0);
        let mut cursor = first.page.next().cloned().expect("budget continuation");
        let mut seen = first.page.items().len();
        loop {
            let page = list(
                &configuration,
                Some(&origin),
                ConfigList {
                    origin: true,
                    limit: 500,
                    cursor: Some(cursor),
                },
            )?;
            seen += page.page.items().len();
            if page.page.window().complete() {
                assert!(page.page.next().is_none());
                break;
            }
            cursor = page.page.next().cloned().expect("continuation cursor");
        }
        assert_eq!(seen, expected_keys(&configuration).len());
        Ok(())
    }

    #[test]
    fn list_end_cursor_yields_an_empty_complete_page() -> Result<()> {
        let configuration = ConfigFile::default();
        let total = list(
            &ConfigFile::default(),
            None,
            ConfigList {
                origin: false,
                limit: 100,
                cursor: None,
            },
        )?
        .page
        .window()
        .fields()
        .expect("producer window")
        .to
        .get();
        let page = list(
            &configuration,
            None,
            ConfigList {
                origin: false,
                limit: 100,
                cursor: Some(Cursor::new(format!("config-list/v1/{total}")).expect("end cursor")),
            },
        )?;
        assert!(page.page.window().complete());
        assert_eq!(page.page.items().len(), 0);
        assert!(page.page.next().is_none());
        Ok(())
    }

    #[test]
    fn list_refuses_bad_and_past_end_cursors() -> Result<()> {
        let configuration = ConfigFile::default();
        for cursor in [
            "config-list/v1/x",
            "other/v1/1",
            "config-list/v1/",
            "config-list/v1/999999",
        ] {
            let page = list(
                &configuration,
                None,
                ConfigList {
                    origin: false,
                    limit: 100,
                    cursor: Some(Cursor::new(cursor).expect("cursor")),
                },
            );
            assert!(page.is_err(), "cursor {cursor} must refuse");
        }
        Ok(())
    }

    #[test]
    fn list_refuses_limits_outside_the_supported_range() -> Result<()> {
        let configuration = ConfigFile::default();
        for limit in [0u16, 501] {
            let page = list(
                &configuration,
                None,
                ConfigList {
                    origin: false,
                    limit,
                    cursor: None,
                },
            );
            assert!(page.is_err(), "limit {limit} must refuse");
        }
        Ok(())
    }

    #[test]
    fn list_names_the_effective_configuration_without_an_origin() -> Result<()> {
        let configuration = ConfigFile::default();
        let page = list(
            &configuration,
            None,
            ConfigList {
                origin: false,
                limit: 100,
                cursor: None,
            },
        )?;
        assert_eq!(
            page.page.window().fields().expect("producer window").source,
            Source::Configuration {
                location: "effective configuration".into()
            }
        );
        let page = list(
            &configuration,
            Some("config.toml /home/owner/config.toml"),
            ConfigList {
                origin: true,
                limit: 100,
                cursor: None,
            },
        )?;
        assert_eq!(
            page.page.window().fields().expect("producer window").source,
            Source::Configuration {
                location: "config.toml /home/owner/config.toml".into()
            }
        );
        Ok(())
    }
}
