// Append this reviewer-owned module to the CLI status adapter for the hosted
// unit run. It calls the production merge function without a replacement body.
#[cfg(test)]
mod reviewer_resource_merge {
    use super::merge_resources;
    use se_core::ops::{AnyOutput, ResourceSample, RuntimeView};
    use serde_json::{Value, json};
    type Check = Result<(), Box<dyn std::error::Error>>;

    fn sample(cpu: u64) -> ResourceSample {
        ResourceSample {
            self_voluntary_switches: Some(11),
            self_involuntary_switches: Some(3),
            cpu_user_us: cpu,
            cpu_system_us: 7,
            rss_bytes: 4096,
            sampled_at: "2026-01-01T00:00:02Z".into(),
            method: "synthetic-native-accounting".into(),
        }
    }
    fn runtime() -> Result<RuntimeView, serde_json::Error> {
        serde_json::from_value(json!({
            "state":"running", "detachment":null, "host":"local",
            "process":{"pid":1234,"started_at":"2026-01-01T00:00:00Z",
                "exe":"/synthetic/host","machine_id":"synthetic-machine"},
            "generation":7,"endpoint":"synthetic-endpoint","version":"test",
            "observed_at":"2026-01-01T00:00:01Z",
            "resources":null,"resources_unavailable":null
        }))
    }
    fn hosted(runtime: RuntimeView) -> se_types::Result<AnyOutput> {
        let mut value = se_core::ops::status::missing(
            "synthetic-home".into(),
            "2026-01-01T00:00:02Z".into(),
            "synthetic-test".into(),
        );
        value.runtime = runtime;
        Ok(value.into())
    }
    fn witness(runtime: &RuntimeView) -> Result<Value, serde_json::Error> {
        let mut value = serde_json::to_value(runtime)?;
        if let Some(fields) = value.as_object_mut() {
            fields.remove("resources");
            fields.remove("resources_unavailable");
        }
        Ok(value)
    }
    #[test]
    fn matching_identity_copies_fresh_counters_and_preserves_native_witness() -> Check {
        let mut direct = runtime()?;
        direct.resources = Some(sample(999));
        direct.resources_unavailable = Some("stale reason".into());
        let original = witness(&direct)?;
        let mut live = runtime()?;
        live.resources = Some(sample(101));
        live.observed_at = Some("hosted observation must not replace native".into());
        merge_resources(&mut direct, &hosted(live));
        assert_eq!(serde_json::to_value(&direct.resources)?, json!(sample(101)));
        assert!(direct.resources_unavailable.is_none());
        assert_eq!(witness(&direct)?, original);
        Ok(())
    }
    #[test]
    fn every_mismatched_or_missing_identity_clears_stale_and_borrowed_counters() -> Check {
        let mut variants = Vec::new();
        for (field, value) in [
            ("pid", json!(4321)),
            ("started_at", json!("2026-01-01T00:00:01Z")),
            ("exe", json!("/synthetic/other")),
            ("machine_id", json!("another-synthetic-machine")),
        ] {
            let mut changed = serde_json::to_value(runtime()?)?;
            changed["process"][field] = value;
            variants.push(changed);
        }
        for (field, value) in [
            ("generation", json!(8)),
            ("generation", Value::Null),
            ("process", Value::Null),
            ("state", json!("unknown")),
        ] {
            let mut changed = serde_json::to_value(runtime()?)?;
            changed[field] = value;
            variants.push(changed);
        }
        for changed in variants {
            let mut direct = runtime()?;
            direct.resources = Some(sample(999));
            let original = witness(&direct)?;
            let mut served: RuntimeView = serde_json::from_value(changed)?;
            served.resources = Some(sample(101));
            merge_resources(&mut direct, &hosted(served));
            assert!(direct.resources.is_none(), "borrowed counters survived");
            assert!(
                direct
                    .resources_unavailable
                    .as_deref()
                    .is_some_and(|reason| reason.contains("different process or generation"))
            );
            assert_eq!(witness(&direct)?, original);
        }
        Ok(())
    }
    #[test]
    fn unavailable_host_reports_reason_without_reusing_existing_counters() -> Check {
        let mut direct = runtime()?;
        direct.resources = Some(sample(999));
        let original = witness(&direct)?;
        let unavailable = Err(se_types::SeError::invalid(
            "synthetic host identity",
            "native identity is unavailable",
        ));
        merge_resources(&mut direct, &unavailable);
        assert!(direct.resources.is_none());
        let reason = direct.resources_unavailable.as_deref().unwrap_or("");
        assert!(reason.contains("Host resource observation failed"));
        assert!(reason.contains("native identity is unavailable"));
        assert_eq!(witness(&direct)?, original);
        Ok(())
    }
    #[test]
    fn unsupported_sampler_preserves_reason_and_missing_sample_is_explicit() -> Check {
        for reason in [Some("native resource sampler unsupported"), None] {
            let mut direct = runtime()?;
            direct.resources = Some(sample(999));
            let mut served = runtime()?;
            served.resources_unavailable = reason.map(str::to_owned);
            merge_resources(&mut direct, &hosted(served));
            assert!(direct.resources.is_none());
            assert_eq!(
                direct.resources_unavailable.as_deref(),
                Some(reason.unwrap_or("The authenticated host did not report resource counters."))
            );
        }
        Ok(())
    }
}
