#![cfg(windows)]
use se_proc::{NativeOwner, OwnerTarget, ProcessId, StartIdentity, observe_owner};

/// Protects actual self/peer owner observation and exact birth binding while
/// native creator lookup changes from whole-system snapshots to pinned handles.
#[test]
fn real_owner_query_preserves_self_peer_and_wrong_birth_refusal()
-> Result<(), Box<dyn std::error::Error>> {
    let current = observe_owner(OwnerTarget::Current, &[])?;
    assert_eq!(current.pid(), ProcessId(std::process::id()));
    assert!(matches!(current.owner(), NativeOwner::Windows { sid } if sid.starts_with("S-1-")));
    assert!(current.agent_trees().is_empty());
    let peer = observe_owner(
        OwnerTarget::Process {
            pid: current.pid(),
            start: current.start(),
        },
        &[],
    )?;
    assert_eq!(peer.pid(), current.pid());
    assert_eq!(peer.start(), current.start());
    assert_eq!(peer.owner(), current.owner());
    assert!(peer.agent_trees().is_empty());
    let StartIdentity::Windows { creation_filetime } = current.start() else {
        panic!("Windows observation did not retain its native birth clock");
    };
    let wrong = StartIdentity::Windows {
        creation_filetime: creation_filetime
            .checked_add(1)
            .ok_or("native birth clock overflow")?,
    };
    assert!(
        observe_owner(
            OwnerTarget::Process {
                pid: current.pid(),
                start: &wrong,
            },
            &[]
        )
        .is_err(),
        "a mismatched process birth was accepted"
    );
    Ok(())
}
