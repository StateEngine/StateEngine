//! Status construction for a measured absent store; it creates no identity or runtime.
use super::outputs::*;
use se_types::Read;
pub fn missing(home: String, generated_at: String, checked: String) -> StatusOutput {
    StatusOutput {
        scope: "home".into(),
        generated_at,
        version: env!("CARGO_PKG_VERSION").into(),
        setup: SetupView {
            state: SetupState::NotSetUp,
            home,
            reason: Some("StateEngine has not been initialized in this home.".into()),
        },
        runtime: RuntimeView {
            state: "unknown".into(),
            detachment: None,
            host: None,
            process: None,
            generation: None,
            endpoint: None,
            version: None,
            observed_at: None,
            resources: None,
        },
        project: Read::Absent { checked },
        removal: None,
        principal: None,
        agents: None,
        inbox: InboxCounts {
            owner_unread: None,
            self_unread: None,
        },
        decisions: DecisionCounts { pending: None },
        capture: CaptureView {
            state: "unknown".into(),
            last_turn_at: None,
        },
        atlas: AtlasView {
            state: "not-built".into(),
        },
        pending: vec![],
        projects: None,
        next: NextStep {
            text: "Initialize this repository, then launch your first agent.".into(),
            command: "se init".into(),
            argv: vec!["se".into(), "init".into()],
        },
    }
}
