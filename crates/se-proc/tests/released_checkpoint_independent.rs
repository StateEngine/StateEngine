//! Protects: owner release retains exact uncontained custody without inventing
//! a child or exit proof. These are codec facts, not native process witnesses.
use se_proc::*;
use se_types::AgentId;
use std::num::NonZeroU64;
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn fixture(mac: bool, stage: u8) -> Check<Checkpoint> {
    let lifecycle = LifecycleId::from_parts(1_700_000_000_000, [9; 10])?;
    let host = HostInstanceId([7; 16]);
    let generation = GenerationId::new(2)?;
    let owner = ProcessIdentity {
        machine: MachineId::new("release-codec-judge")?,
        boot: if mac {
            BootIdentity::MacOs {
                seconds: 100,
                microseconds: 7,
            }
        } else {
            BootIdentity::Linux { boot_id: [3; 16] }
        },
        start: if mac {
            StartIdentity::MacOs {
                seconds: 110,
                microseconds: 8,
            }
        } else {
            StartIdentity::Linux { start_ticks: 27 }
        },
        pid: ProcessId(123),
        image: std::env::current_exe()?,
    };
    let mut child = owner.clone();
    child.pid = ProcessId(124);
    let parent = if mac {
        ReservationParent::MacOs
    } else {
        ReservationParent::LinuxTracked
    };
    let reservation = LaunchReservation {
        format_version: 1,
        lifecycle: lifecycle.clone(),
        host,
        owner: owner.clone(),
        generation,
        scope_nonce: [8; 16],
        parent: parent.clone(),
        created_at_unix_ns: 1,
    };
    let prepared_scope = if mac {
        ScopeIdentity::MacOsPrepared { nonce: [8; 16] }
    } else {
        ScopeIdentity::LinuxPrepared { nonce: [8; 16] }
    };
    let tracked = if mac {
        ScopeIdentity::MacOsTracked {
            process_group: child.pid,
            root: child.clone(),
        }
    } else {
        ScopeIdentity::LinuxTracked {
            process_group: child.pid,
            root: child.clone(),
        }
    };
    let guarantee = if mac {
        ContainmentGuarantee::TrackedTree {
            atomic_signal: true,
            escape_prevented: false,
        }
    } else {
        ContainmentGuarantee::Uncontained {
            reason: UncontainedReason::NoUserManager,
        }
    };
    let prepared = ScopeCheckpoint {
        reservation: reservation.clone(),
        parent,
        scope: if stage < 2 {
            prepared_scope.clone()
        } else {
            tracked.clone()
        },
        guarantee,
    };
    let (source, scope, root_identity) = match stage {
        0 => (
            CheckpointSource::Reservation(reservation),
            prepared_scope,
            RootPublication::NoChildCreated,
        ),
        1 => (
            CheckpointSource::Scope(prepared),
            prepared_scope,
            RootPublication::Unpublished,
        ),
        2 => (
            CheckpointSource::Root(RootCheckpoint {
                scope: prepared,
                pre_exec: child,
                intended_executable: std::env::current_exe()?,
            }),
            tracked,
            RootPublication::Identified,
        ),
        3 => (
            CheckpointSource::Process(ProcessRecord {
                format_version: 1,
                lifecycle: lifecycle.clone(),
                host,
                owner,
                generation,
                root: child,
                scope: tracked.clone(),
                tracked_obligations: None,
                guarantee,
                entry: if mac {
                    EntryMethod::MacOsSpawn
                } else {
                    EntryMethod::LinuxProcessGroup
                },
                state: LifecycleState::StopUnproved,
                ownership_release: None,
                exit_status: None,
                observed_at_unix_ns: 2,
                argv_sha256: [4; 32],
            }),
            tracked,
            RootPublication::Identified,
        ),
        _ => return Err("unknown fixture stage".into()),
    };
    Ok(Checkpoint {
        format_version: 1,
        lifecycle: lifecycle.clone(),
        principal: CheckpointPrincipal::Agent(AgentId::from_parts(1_700_000_000_000, [4; 10])?),
        session: None,
        root_identity,
        checkpoint: CheckpointKind::Released {
            source: Box::new(source),
            release: UnwitnessedRelease {
                lifecycle,
                generation: GenerationId::new(3)?,
                revision: NonZeroU64::new(7).ok_or("revision")?,
                scope,
                remaining: RemainingScope {
                    population: Population::Unknown,
                    known_live: Vec::new(),
                    extent: EnumerationExtent::Partial {
                        reason: "owner explicitly released unproved custody".into(),
                        omitted: None,
                    },
                    observed_at_unix_ns: 2,
                },
                released_at_unix_ns: 3,
            },
        },
    })
}
fn release(checkpoint: &mut Checkpoint) -> &mut UnwitnessedRelease {
    let CheckpointKind::Released { release, .. } = &mut checkpoint.checkpoint else {
        panic!("release fixture")
    };
    release
}
/// Protects: all four retained source stages on Linux and macOS keep their facts;
/// NoChildCreated/Unpublished are not converted into a fictitious ProcessRecord.
#[test]
fn released_sources_roundtrip_without_fabricated_process_or_exit() -> Check {
    for mac in [false, true] {
        for stage in 0..4 {
            let original = fixture(mac, stage)?;
            let bytes = encode_checkpoint(&original)?;
            let decoded = decode_checkpoint(1, &bytes)?;
            assert_eq!(
                serde_json::to_value(&decoded)?,
                serde_json::to_value(&original)?,
                "release changed retained custody"
            );
            assert_eq!(encode_checkpoint(&decoded)?, bytes);
            assert!(
                decoded.owner_guard_record()?.is_none(),
                "released custody reentered owner guard"
            );
            let CheckpointKind::Released { source, release } = decoded.checkpoint else {
                return Err("release variant lost".into());
            };
            assert_eq!(release.remaining.population, Population::Unknown);
            assert!(matches!(
                release.remaining.extent,
                EnumerationExtent::Partial { omitted: None, .. }
            ));
            if let CheckpointSource::Process(record) = source.as_ref() {
                assert_eq!(record.state, LifecycleState::StopUnproved);
                assert!(record.exit_status.is_none());
                assert!(record.ownership_release.is_none());
            } else {
                assert!(stage < 3);
            }
        }
    }
    Ok(())
}
/// Protects: indexed publication, retained identity, generation and observation
/// time must remain bound; only the current-or-adopted generation is legal.
#[test]
fn released_checkpoint_refuses_drift_and_malformed_wire() -> Check {
    for stage in 0..4 {
        for fault in [
            "lifecycle",
            "scope",
            "generation",
            "time-zero",
            "observation",
            "publication",
        ] {
            let mut checkpoint = fixture(false, stage)?;
            match fault {
                "lifecycle" => {
                    release(&mut checkpoint).lifecycle =
                        LifecycleId::from_parts(1_700_000_000_001, [5; 10])?
                }
                "scope" => {
                    release(&mut checkpoint).scope =
                        ScopeIdentity::LinuxPrepared { nonce: [99; 16] }
                }
                "generation" => release(&mut checkpoint).generation = GenerationId::new(1)?,
                "time-zero" => release(&mut checkpoint).released_at_unix_ns = 0,
                "observation" => release(&mut checkpoint).remaining.observed_at_unix_ns = 4,
                "publication" => checkpoint.root_identity = RootPublication::Unknown,
                _ => panic!("unrecognized checkpoint fault fixture"),
            }
            assert!(
                encode_checkpoint(&checkpoint).is_err(),
                "released {fault} drift was accepted at stage {stage}"
            );
            assert!(
                decode_checkpoint(1, &serde_json::to_vec(&checkpoint)?).is_err(),
                "wire reader accepted {fault} drift at stage {stage}"
            );
        }
    }
    let checkpoint = fixture(false, 0)?;
    let mut wire = serde_json::to_value(&checkpoint)?;
    wire["checkpoint"]["value"]["release"]["unexpected"] = true.into();
    assert!(decode_checkpoint(1, &serde_json::to_vec(&wire)?).is_err());
    assert!(decode_checkpoint(2, &encode_checkpoint(&checkpoint)?).is_err());
    let mut trailing = encode_checkpoint(&checkpoint)?;
    trailing.extend_from_slice(b"{}");
    assert!(decode_checkpoint(1, &trailing).is_err());
    assert!(decode_checkpoint(1, &vec![b' '; 1024 * 1024 + 1]).is_err());
    Ok(())
}
/// Protects: a kernel scope remains native custody; its owner cannot turn it
/// into an unwitnessed release by changing only the wrapper or reservation.
#[test]
fn released_checkpoint_never_relinquishes_a_kernel_cgroup() -> Check {
    for stage in 0..4 {
        let mut checkpoint = fixture(false, stage)?;
        let parent = ReservationParent::Linux {
            path: std::env::current_dir()?,
            device: 1,
            inode: 2,
            boot_id: [3; 16],
        };
        let scope = ScopeIdentity::LinuxCgroup {
            path: std::env::current_dir()?,
            device: 1,
            inode: 2,
            boot_id: [3; 16],
        };
        let CheckpointKind::Released { source, release } = &mut checkpoint.checkpoint else {
            panic!("fixture must contain a released checkpoint")
        };
        match source.as_mut() {
            CheckpointSource::Reservation(v) => v.parent = parent,
            CheckpointSource::Scope(v) => {
                v.reservation.parent = parent.clone();
                v.parent = parent;
                v.scope = scope.clone();
                v.guarantee = ContainmentGuarantee::KernelScope {
                    explicit_breakaway: false,
                };
            }
            CheckpointSource::Root(v) => {
                v.scope.reservation.parent = parent.clone();
                v.scope.parent = parent;
                v.scope.scope = scope.clone();
                v.scope.guarantee = ContainmentGuarantee::KernelScope {
                    explicit_breakaway: false,
                };
            }
            CheckpointSource::Process(v) => {
                v.scope = scope.clone();
                v.guarantee = ContainmentGuarantee::KernelScope {
                    explicit_breakaway: false,
                };
                v.entry = EntryMethod::LinuxClone3;
            }
        }
        release.scope = scope;
        // First prove the retained contained source itself is a valid checkpoint.
        let mut unreleased = checkpoint.clone();
        let CheckpointKind::Released { source, .. } = unreleased.checkpoint else {
            panic!("cloned fixture must contain a released checkpoint")
        };
        unreleased.checkpoint = match *source {
            CheckpointSource::Reservation(v) => CheckpointKind::Reservation(v),
            CheckpointSource::Scope(v) => CheckpointKind::Scope(v),
            CheckpointSource::Root(v) => CheckpointKind::Root(v),
            CheckpointSource::Process(v) => CheckpointKind::Process(v),
        };
        encode_checkpoint(&unreleased)?;
        assert!(
            encode_checkpoint(&checkpoint).is_err(),
            "kernel-contained source was relinquished at stage {stage}"
        );
    }
    Ok(())
}
