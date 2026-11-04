//! Counter failures affect the optional measurement, never the host's status.
use se_core::ops::RuntimeView;

pub(super) fn observe(runtime: &mut RuntimeView) {
    match sample() {
        Ok(sample) => {
            runtime.resources = Some(sample);
            runtime.resources_unavailable = None;
        }
        Err(error) => {
            runtime.resources = None;
            runtime.resources_unavailable = Some(error.to_string());
        }
    }
}

#[cfg(target_os = "linux")]
fn sample() -> se_types::Result<se_core::ops::ResourceSample> {
    let counters = se_proc::observe_self_resources().map_err(|cause| {
        se_core::scope::unreadable("host self resources", &format!("{cause:?}"))
    })?;
    Ok(se_core::ops::ResourceSample {
        self_voluntary_switches: Some(counters.voluntary_switches),
        self_involuntary_switches: Some(counters.involuntary_switches),
        cpu_user_us: counters.cpu_user_us,
        cpu_system_us: counters.cpu_system_us,
        rss_bytes: counters.rss_bytes,
        sampled_at: se_core::ops::receipt::timestamp(crate::runtime::start::now_unix_micros()?)?,
        method: "linux:getrusage(RUSAGE_SELF)+/proc/self/statm".into(),
    })
}

#[cfg(not(target_os = "linux"))]
fn sample() -> se_types::Result<se_core::ops::ResourceSample> {
    Err(se_core::scope::unreadable(
        "host self resources",
        "native self-accounting is unavailable on this platform",
    ))
}
