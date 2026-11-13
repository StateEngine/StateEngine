//! Native pairing asks the Owner to choose existing saved destination identities.
use super::*;
use se_store::remote::LaunchCandidate;
use se_types::Read;
use std::io::BufRead;

pub(super) fn review(
    m: &ArgMatches,
    stdout: &mut impl Write,
    input: &mut impl BufRead,
) -> io::Result<()> {
    let cx = crate::bootstrap::Bootstrap::resolve_remote_owner(
        text(m, "home").map(Into::into),
        m.get_flag("no_color"),
        false,
    )
    .map_err(io::Error::other)?;
    let alias = required(m, "name").map_err(io::Error::other)?;
    let mut after = None;
    let mut change = None;
    loop {
        let output = crate::route::remote_owner::execute(
            &cx,
            Input::Ready(OwnerInput::PairingLaunchPermissions {
                alias: alias.clone(),
                after: after.clone(),
                change: change.take(),
            }),
        )
        .map_err(io::Error::other)?;
        let targets: Vec<LaunchCandidate> = serde_json::from_value(output.value["targets"].clone())
            .map_err(|_| {
                io::Error::other("pairing returned an incompatible destination inventory")
            })?;
        if output.value["changed"].is_object() {
            writeln!(
                stdout,
                "Launch consent saved. Revoking consent stops future launches; already admitted launches and running agents continue."
            )?;
        }
        show_targets(stdout, &targets)?;
        writeln!(
            stdout,
            "Choose an agent number to allow or revoke, n for the next page, or Enter to finish."
        )?;
        stdout.flush()?;
        let selected = super::permissions::line(input)?;
        if selected.is_empty() {
            return Ok(());
        }
        if selected == "n" {
            if output.value["more"] == true {
                after = serde_json::from_value(output.value["next"].clone())
                    .map_err(io::Error::other)?;
            } else {
                writeln!(stdout, "There are no more destination agents.")?;
            }
            continue;
        }
        let target = selected
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|n| targets.get(n));
        let Some(target) = target else {
            writeln!(stdout, "Choose a number shown on this page.")?;
            continue;
        };
        change = choose_change(stdout, input, target)?;
    }
}

fn show_targets(stdout: &mut impl Write, targets: &[LaunchCandidate]) -> io::Result<()> {
    if targets.is_empty() {
        writeln!(
            stdout,
            "No existing destination agents on this page. Create and save an agent on the destination before granting launch consent."
        )?;
    }
    for (index, target) in targets.iter().enumerate() {
        let name =
            serde_json::to_string(&format!("{} / {}", target.project_name, target.agent_name))
                .map_err(io::Error::other)?;
        let state = match &target.permission {
            Read::Present { value } if value.allowed => "allowed",
            Read::Present { .. } | Read::Absent { .. } => "not allowed",
            Read::Unreadable { .. } => "unreadable",
            Read::Unknown { .. } => "unknown",
        };
        writeln!(stdout, "{}: {} — {}", index + 1, name, state)?;
        let address = serde_json::to_string(&format!(
            "{}/{}",
            target.target.project, target.target.agent
        ))
        .map_err(io::Error::other)?;
        writeln!(stdout, "   Target {}", address)?;
        match &target.profile {
            Read::Present { value } => writeln!(
                stdout,
                "   Saved provider {:?}; permissions {}.",
                value.provider,
                permissions(&value.permission)
            )?,
            Read::Absent { .. } => writeln!(
                stdout,
                "   Saved launch profile is missing; save it before allowing launches."
            )?,
            Read::Unreadable { .. } => writeln!(
                stdout,
                "   Saved launch profile is unreadable; restore it before allowing launches."
            )?,
            Read::Unknown { .. } => writeln!(
                stdout,
                "   Saved launch profile is unknown; inspect it before allowing launches."
            )?,
        }
    }
    Ok(())
}

fn choose_change(
    stdout: &mut impl Write,
    input: &mut impl BufRead,
    target: &LaunchCandidate,
) -> io::Result<Option<se_host::remote::LaunchPermissionChange>> {
    writeln!(
        stdout,
        "Allow this paired machine to start the selected saved agent, or revoke that consent? [allow/revoke/Enter to cancel]"
    )?;
    stdout.flush()?;
    let allowed = match super::permissions::line(input)?.as_str() {
        "allow" => true,
        "revoke" => false,
        _ => return Ok(None),
    };
    let expected_revision = match &target.permission {
        Read::Present { value } => Some(value.revision.value.get()),
        Read::Absent { .. } => None,
        _ => {
            return Err(io::Error::other(
                "current launch consent is unreadable; restore readable pairing permissions before changing it",
            ));
        }
    };
    Ok(Some(se_host::remote::LaunchPermissionChange {
        target: target.target.clone(),
        allowed,
        expected_revision,
        key: IdempotencyKey::new(uuid::Uuid::new_v4().to_string()).map_err(io::Error::other)?,
    }))
}
fn permissions(value: &se_store::PermissionProfile) -> &'static str {
    match value {
        se_store::PermissionProfile::ReadOnly => "read only",
        se_store::PermissionProfile::WorkspaceWrite => "workspace writes",
        se_store::PermissionProfile::NamedFullBypass => "full access",
    }
}
