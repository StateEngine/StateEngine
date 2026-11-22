use super::*;
/// Protects: 49 — recovery retains a possible receive gap and a new run cannot inherit continuity.
#[test]
fn successful_poll_does_not_erase_outage_or_restart_uncertainty() {
    let mut observed = ReceiverObservation {
        health: ConnectionHealth::Unavailable {
            code: "starting".into(),
        },
        coverage: ReceiveCoverage::unobserved(10),
    };
    observed.observe(
        ConnectionHealth::Connected {
            last_poll_at_us: Some(20),
        },
        20,
    );
    assert_eq!(observed.coverage.possible_gap.from_us, None);
    observed.observe(
        ConnectionHealth::Unavailable {
            code: "offline".into(),
        },
        30,
    );
    observed.observe(
        ConnectionHealth::Connected {
            last_poll_at_us: Some(40),
        },
        40,
    );
    observed.observe(
        ConnectionHealth::Connected {
            last_poll_at_us: Some(50),
        },
        50,
    );
    assert_eq!(observed.coverage.last_successful_poll_at_us, Some(50));
    assert_eq!(
        observed.coverage.possible_gap,
        ReceiveGap {
            from_us: Some(20),
            through_us: 40,
            reason: ReceiveGapReason::ReceiverUnavailable,
        }
    );
    let restarted = ReceiveCoverage::unobserved(60);
    assert_eq!(restarted.observed_since_us, None);
    assert_eq!(restarted.last_successful_poll_at_us, None);
    assert_eq!(restarted.possible_gap.from_us, None);
}
