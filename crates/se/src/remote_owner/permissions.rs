//! Source permissions are available at the end of the existing pairing flow.
use super::*;
use std::io::{BufRead, IsTerminal};

pub(super) fn command(
    m: &ArgMatches,
    json: bool,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> io::Result<u8> {
    if !m.get_flag("local") && text(m, "name").is_none() {
        return crate::render::error::write(
            &invalid(
                "choose --name <saved-alias> for the destination, or --local for this machine",
            ),
            &se_types::RenderCx::default(),
            json,
            stdout,
            stderr,
        );
    }
    if json
        || !io::stdin().is_terminal()
        || !io::stdout().is_terminal()
        || m.get_flag("version")
        || m.get_one::<String>("project").is_some()
        || text(m, "key").is_some()
    {
        return crate::render::error::write(
            &invalid(
                "agent permission review requires a native Owner terminal: run se remote permissions --name <saved-alias>, or se remote permissions --local on the destination; add --launch to review launch consent; omit --json, --project, --version and --key",
            ),
            &se_types::RenderCx::default(),
            json,
            stdout,
            stderr,
        );
    }
    if m.get_flag("launch") {
        super::launch_permissions::review(m, stdout, &mut io::stdin().lock())?;
    } else {
        review_at(m, stdout, m.get_flag("local"))?;
    }
    Ok(0)
}

pub(super) fn review(m: &ArgMatches, stdout: &mut impl Write) -> io::Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        writeln!(
            stdout,
            "Agent permission review was skipped because input or output is not a terminal. Run se remote permissions --name <saved-alias> in a terminal; add --launch for launch consent, or use --local for this machine's incoming source access."
        )?;
        return Ok(());
    }
    writeln!(
        stdout,
        "Review agent access on the destination or this machine? [destination/local/launch/Enter to finish]"
    )?;
    stdout.flush()?;
    let mut input = io::stdin().lock();
    let local = match line(&mut input)?.as_str() {
        "destination" => false,
        "local" => true,
        "launch" => return super::launch_permissions::review(m, stdout, &mut input),
        _ => return Ok(()),
    };
    drop(input);
    review_at(m, stdout, local)
}

pub(super) fn review_at(m: &ArgMatches, stdout: &mut impl Write, local: bool) -> io::Result<()> {
    let mut input = io::stdin().lock();
    let cx = crate::bootstrap::Bootstrap::resolve_remote_owner(
        text(m, "home").map(Into::into),
        m.get_flag("no_color"),
        false,
    )
    .map_err(io::Error::other)?;
    let alias = if local {
        None
    } else {
        Some(required(m, "name").map_err(io::Error::other)?)
    };
    let mut after = None;
    let mut change = None;
    loop {
        let output = crate::route::remote_owner::execute(
            &cx,
            Input::Ready(if local {
                OwnerInput::LocalPairingPermissions {
                    after: after.clone(),
                    change: change.take(),
                }
            } else {
                OwnerInput::PairingPermissions {
                    alias: alias
                        .clone()
                        .ok_or_else(|| io::Error::other("a saved remote alias is required"))?,
                    after: after.clone(),
                    change: change.take(),
                }
            }),
        )
        .map_err(io::Error::other)?;
        let contacts: Vec<se_store::remote::SourceContact> =
            serde_json::from_value(output.value["sources"].clone()).map_err(|_| {
                io::Error::other("pairing permissions returned an incompatible source inventory")
            })?;
        if output.value["changed"].is_object() {
            writeln!(stdout, "Source permission saved.")?;
        }
        print_contacts(stdout, &contacts)?;
        writeln!(
            stdout,
            "Choose an agent number to allow or revoke, n for the next page, or Enter to finish."
        )?;
        stdout.flush()?;
        let selected = line(&mut input)?;
        if selected.is_empty() {
            return Ok(());
        }
        if selected == "n" {
            if output.value["more"] == true {
                after = serde_json::from_value(output.value["next"].clone())
                    .map_err(io::Error::other)?;
            } else {
                writeln!(stdout, "There are no more source agents.")?;
            }
            continue;
        }
        let Some(contact) = selected
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|n| contacts.get(n))
        else {
            writeln!(stdout, "Choose a number shown on this page.")?;
            continue;
        };
        writeln!(
            stdout,
            "Allow or revoke this source agent? [allow/revoke/Enter to cancel]"
        )?;
        stdout.flush()?;
        let allowed = match line(&mut input)?.as_str() {
            "allow" => true,
            "revoke" => false,
            _ => continue,
        };
        change = Some(permission_change(contact, allowed)?);
    }
}

pub(super) fn line(input: &mut impl BufRead) -> io::Result<String> {
    let mut bytes = Vec::new();
    let count = std::io::Read::take(input, 257).read_until(b'\n', &mut bytes)?;
    if count > 256 || (count > 0 && bytes.last() != Some(&b'\n')) {
        return Err(io::Error::other("pairing choice exceeds 256 bytes"));
    }
    String::from_utf8(bytes)
        .map(|s| s.trim().to_owned())
        .map_err(io::Error::other)
}

fn print_contacts(
    stdout: &mut impl Write,
    contacts: &[se_store::remote::SourceContact],
) -> io::Result<()> {
    if contacts.is_empty() {
        writeln!(
            stdout,
            "No source agents on this page. Agents appear after their first authenticated message."
        )?;
    }
    for (index, contact) in contacts.iter().enumerate() {
        // JSON string escaping prevents peer-controlled names from emitting
        // terminal controls while retaining the exact public selector.
        let address =
            serde_json::to_string(&contact.address.selector()).map_err(io::Error::other)?;
        writeln!(
            stdout,
            "{}: {} — {}",
            index + 1,
            address,
            if contact.pending_revocation.is_some() {
                "revocation pending; access blocked"
            } else if contact.permission.as_ref().is_some_and(|p| !p.allowed) {
                "revoked"
            } else {
                "allowed"
            }
        )?;
    }
    Ok(())
}

fn permission_change(
    contact: &se_store::remote::SourceContact,
    allowed: bool,
) -> io::Result<se_host::remote::SourcePermissionChange> {
    Ok(se_host::remote::SourcePermissionChange {
        address: contact.address.clone(),
        allowed,
        expected_revision: contact.permission.as_ref().map(|p| p.revision.value.get()),
        key: if !allowed {
            contact
                .pending_revocation
                .clone()
                .map(Ok)
                .unwrap_or_else(|| IdempotencyKey::new(uuid::Uuid::new_v4().to_string()))
                .map_err(io::Error::other)?
        } else {
            IdempotencyKey::new(uuid::Uuid::new_v4().to_string()).map_err(io::Error::other)?
        },
    })
}
