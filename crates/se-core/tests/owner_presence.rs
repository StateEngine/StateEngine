#[path = "../../se/src/render/error.rs"]
mod render_error;

use se_core::admission::{AgentTreeCheck, OwnerObservations, authorize_file_owner};
use se_types::{Code, RenderCx};

type Check = Result<(), Box<dyn std::error::Error>>;

fn owner(stdin_console: bool, stdout_console: bool) -> OwnerObservations {
    OwnerObservations {
        os_owner: "native-owner".into(),
        agent_tree: AgentTreeCheck::Outside,
        stdin_console,
        stdout_console,
        provider_marker: false,
    }
}

/// Protects: a human-only refusal identifies each actual console fact in plain
/// text and JSON; a missing stream never silently becomes human presence.
#[test]
fn console_refusal_reaches_both_public_error_formats() -> Check {
    for (stdin, stdout) in [(false, true), (true, false), (false, false)] {
        let error = authorize_file_owner(
            "installation.uninstall",
            "native-owner",
            false,
            true,
            &owner(stdin, stdout),
        )
        .err()
        .ok_or("missing console admitted a human-only operation")?;
        assert_eq!(error.code(), Code::HumanTerminalRequired);
        for json in [false, true] {
            let (mut output, mut diagnostic) = (Vec::new(), Vec::new());
            assert_eq!(
                render_error::write(
                    &error,
                    &RenderCx::default(),
                    json,
                    &mut output,
                    &mut diagnostic,
                )?,
                1
            );
            let diagnostic = String::from_utf8(diagnostic)?;
            for fact in [
                format!("stdin_console={stdin}"),
                format!("stdout_console={stdout}"),
            ] {
                assert!(
                    diagnostic.contains(&fact),
                    "lost console fact: {diagnostic}"
                );
                if json {
                    let value: serde_json::Value = serde_json::from_slice(&output)?;
                    assert_eq!(value["code"], "human-terminal-required");
                    assert!(
                        value["detail"]["reason"]
                            .as_str()
                            .ok_or("reason")?
                            .contains(&fact)
                    );
                    assert!(value["message"].as_str().ok_or("message")?.contains(&fact));
                }
            }
            assert!(diagnostic.contains("not proof against a determined agent"));
            if !json {
                assert!(output.is_empty());
            }
        }
    }
    Ok(())
}

/// Protects: diagnostic changes preserve the existing owner/session/provider
/// and ancestry checks, and do not add console requirements to ordinary owner work.
#[test]
fn console_diagnostics_preserve_owner_policy() -> Check {
    authorize_file_owner(
        "installation.uninstall",
        "native-owner",
        false,
        true,
        &owner(true, true),
    )?;
    authorize_file_owner(
        "ordinary-owner",
        "native-owner",
        false,
        false,
        &owner(false, false),
    )?;
    for (observed, session) in [
        (owner(true, true), true),
        (
            OwnerObservations {
                provider_marker: true,
                ..owner(true, true)
            },
            false,
        ),
        (
            OwnerObservations {
                agent_tree: AgentTreeCheck::Inside {
                    record: "recorded-agent".into(),
                },
                ..owner(true, true)
            },
            false,
        ),
    ] {
        let error = authorize_file_owner(
            "installation.uninstall",
            "native-owner",
            session,
            true,
            &observed,
        )
        .err()
        .ok_or("agent admission unexpectedly passed")?;
        assert_eq!(error.code(), Code::OwnerRequired);
    }
    let error = authorize_file_owner(
        "installation.uninstall",
        "another-owner",
        false,
        true,
        &owner(true, true),
    )
    .err()
    .ok_or("different OS owner admitted")?;
    assert_eq!(error.code(), Code::OsUserMismatch);
    Ok(())
}
