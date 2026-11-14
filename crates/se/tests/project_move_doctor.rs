//! A moved project is named by doctor, re-attached with se project move, and a
//! bare repository is refused at init.
#![allow(
    dead_code,
    reason = "Shared real store fixture serves other consumers."
)]
use std::{error::Error, path::Path, process::Command};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;

fn command(home: &Path, root: &Path, json: bool, project: Option<&str>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_se"));
    command.arg("--home").arg(home).current_dir(root);
    if let Some(project) = project {
        command.args(["--project", project]);
    }
    if json {
        command.arg("--json");
    }
    for key in [
        "SE_HOME",
        "SE_CONFIG",
        "SE_PROJECT",
        "SE_SESSION",
        "SE_LOG",
        "CLAUDECODE",
        "CODEX_THREAD_ID",
        "CODEX_CI",
    ] {
        command.env_remove(key);
    }
    command
}

fn git(root: &Path, args: &[&str]) -> Check {
    let output = Command::new("git").args(args).current_dir(root).output()?;
    assert!(
        output.status.success(),
        "git {args:?} refused: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn doctor_check(
    output: &std::process::Output,
    id: &str,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let row = value["checks"]
        .as_array()
        .ok_or("doctor JSON has no checks")?
        .iter()
        .find(|row| row["id"] == id)
        .ok_or("project root check was not diagnosed")?;
    Ok(row.clone())
}

#[test]
fn moved_project_is_diagnosed_and_reattached_with_the_recorded_git_identity() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let fixture = Fixture::new()?;
    let home = &fixture.options.state_directory;
    let original = fixture.home.join("move repository");
    let moved = fixture.home.join("moved repository");
    std::fs::create_dir(&original)?;
    git(&original, &["init", "-q", "-b", "main", "."])?;
    git(&original, &["config", "user.email", "se@stateengine.local"])?;
    git(&original, &["config", "user.name", "SE"])?;
    std::fs::write(original.join("note.txt"), "moved later\n")?;
    git(&original, &["add", "."])?;
    git(&original, &["commit", "-qm", "base"])?;
    let output = command(home, &original, true, None)
        .args(["init", "--name", "Mover"])
        .output()?;
    assert!(
        output.status.success(),
        "init refused: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Init consumes the caller's original spelling. Compare later reports with
    // the registered canonical spelling, including expanded Windows aliases.
    let registered = se_proc::canonicalize_path(&original)?;
    let row = doctor_check(
        &command(home, &original, true, None)
            .arg("doctor")
            .output()?,
        "project.root.Mover",
    )?;
    assert_eq!(row["state"], "ok");
    assert_eq!(row["observed"], "1 of 1 registered roots present on disk");
    assert!(row["fix"].is_null(), "{row}");
    std::fs::rename(&original, &moved)?;
    let failed = doctor_check(
        &command(home, &moved, true, None).arg("doctor").output()?,
        "project.root.Mover",
    )?;
    assert_eq!(failed["state"], "failed");
    let observed = failed["observed"]
        .as_str()
        .ok_or("failed check has no observed text")?;
    let original_text = registered.to_str().ok_or("original root is not UTF-8")?;
    assert!(observed.contains(original_text), "{failed}");
    assert_eq!(
        failed["fix"]["argv"],
        serde_json::json!([
            "se",
            "--home",
            home.to_str().ok_or("state home is not UTF-8")?,
            "--project",
            "Mover",
            "project",
            "move",
            "<new-folder>"
        ])
    );
    let output = command(home, &moved, false, Some("Mover"))
        .args([
            "project",
            "move",
            moved.to_str().ok_or("moved root is not UTF-8")?,
        ])
        .output()?;
    assert!(
        output.status.success(),
        "project move refused: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert!(
        stdout.contains(&format!(
            "Project Mover moved from {}",
            registered.display()
        )),
        "{stdout}"
    );
    assert!(
        stdout.contains("Git identity: HEAD") && stdout.contains("on main"),
        "{stdout}"
    );
    assert!(stdout.contains("Event: "), "{stdout}");
    let row = doctor_check(
        &command(home, &moved, true, None).arg("doctor").output()?,
        "project.root.Mover",
    )?;
    assert_eq!(row["state"], "ok");
    assert_eq!(row["observed"], "1 of 1 registered roots present on disk");
    Ok(())
}

#[test]
fn init_refuses_a_bare_repository_before_registering_a_project() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let fixture = Fixture::new()?;
    let home = &fixture.options.state_directory;
    let bare = fixture.home.join("bare repository");
    std::fs::create_dir(&bare)?;
    git(&bare, &["init", "-q", "--bare", "."])?;
    let output = command(home, &bare, false, None)
        .args(["init", "--name", "Bare"])
        .output()?;
    assert!(!output.status.success(), "bare init must refuse");
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        rendered.contains("a bare Git repository has no working tree for an agent to work in"),
        "{rendered}"
    );
    Ok(())
}

fn event_id(stdout: &str) -> Result<&str, Box<dyn Error>> {
    let err = |what: &str| -> Box<dyn Error> { what.into() };
    let line = stdout
        .lines()
        .find(|line| line.starts_with("Event: "))
        .ok_or_else(|| err("output has no event line"))?;
    let rest = line
        .strip_prefix("Event: ")
        .ok_or_else(|| err("event line lost its prefix"))?;
    rest.split(';')
        .next()
        .ok_or_else(|| err("event line has no id"))
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn move_replays_the_retained_receipt_on_the_same_request_key() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let fixture = Fixture::new()?;
    let home = &fixture.options.state_directory;
    let original = fixture.home.join("replay repository");
    let moved = fixture.home.join("replayed repository");
    std::fs::create_dir(&original)?;
    git(&original, &["init", "-q", "-b", "main", "."])?;
    git(&original, &["config", "user.email", "se@stateengine.local"])?;
    git(&original, &["config", "user.name", "SE"])?;
    std::fs::write(original.join("note.txt"), "replayed\n")?;
    git(&original, &["add", "."])?;
    git(&original, &["commit", "-qm", "base"])?;
    let output = command(home, &original, true, None)
        .args(["init", "--name", "Replayer"])
        .output()?;
    assert!(
        output.status.success(),
        "init refused: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::rename(&original, &moved)?;
    let moved_str = moved.to_str().ok_or("moved root is not UTF-8")?;
    let key = "se-fh07-replay-key-1";
    let first = command(home, &moved, false, Some("Replayer"))
        .args(["project", "move", moved_str, "--key", key])
        .output()?;
    assert!(
        first.status.success(),
        "first move refused: {} {}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    let first_stdout = String::from_utf8(first.stdout)?;
    assert!(
        first_stdout.contains("Project Replayer moved from"),
        "{first_stdout}"
    );
    let first_event = event_id(&first_stdout)?;
    // Same key, same target: the move already committed, so the retry returns
    // the original receipt instead of refusing the present folder as a copy.
    let replay = command(home, &moved, false, Some("Replayer"))
        .args(["project", "move", moved_str, "--key", key])
        .output()?;
    assert!(
        replay.status.success(),
        "same-key replay refused: {} {}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
    let replay_stdout = String::from_utf8(replay.stdout)?;
    assert!(
        replay_stdout.contains("Project Replayer moved from"),
        "{replay_stdout}"
    );
    assert_eq!(
        event_id(&replay_stdout)?,
        first_event,
        "the replay must return the committed receipt, not a new event"
    );
    // Moving the repository on to a third folder under a new key leaves the
    // first key's target gone; the retained replay must still return the
    // original receipt without that folder remaining.
    let again = fixture.home.join("moved on repository");
    std::fs::rename(&moved, &again)?;
    let again_str = again.to_str().ok_or("again root is not UTF-8")?;
    let second_move = command(home, &again, false, Some("Replayer"))
        .args([
            "project",
            "move",
            again_str,
            "--key",
            "se-fh07-replay-key-3",
        ])
        .output()?;
    assert!(
        second_move.status.success(),
        "move on refused: {} {}",
        String::from_utf8_lossy(&second_move.stdout),
        String::from_utf8_lossy(&second_move.stderr)
    );
    let replay_after = command(home, &again, false, Some("Replayer"))
        .args(["project", "move", moved_str, "--key", key])
        .output()?;
    assert!(
        replay_after.status.success(),
        "replay of a retained key must not require its target folder to remain: {} {}",
        String::from_utf8_lossy(&replay_after.stdout),
        String::from_utf8_lossy(&replay_after.stderr)
    );
    assert_eq!(
        event_id(&String::from_utf8(replay_after.stdout)?)?,
        first_event,
        "the replay must return the committed receipt after the repository moved on"
    );
    // The same key against a different target is a collision, refused as such.
    let other = fixture.home.join("somewhere else");
    std::fs::create_dir(&other)?;
    let collision = command(home, &other, false, Some("Replayer"))
        .args([
            "project",
            "move",
            other.to_str().ok_or("other root is not UTF-8")?,
            "--key",
            key,
        ])
        .output()?;
    assert!(!collision.status.success(), "key collision must refuse");
    let collision_rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&collision.stdout),
        String::from_utf8_lossy(&collision.stderr)
    );
    assert!(
        collision_rendered.contains("retained for a different move target"),
        "{collision_rendered}"
    );
    // A different key still refuses the copy: the target folder is present.
    let copy = command(home, &again, false, Some("Replayer"))
        .args([
            "project",
            "move",
            again_str,
            "--key",
            "se-fh07-replay-key-2",
        ])
        .output()?;
    assert!(
        !copy.status.success(),
        "a second key must refuse the present folder"
    );
    let copy_rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&copy.stdout),
        String::from_utf8_lossy(&copy.stderr)
    );
    assert!(
        copy_rendered.contains("the original folder still exists at"),
        "{copy_rendered}"
    );
    Ok(())
}

#[test]
#[cfg(unix)]
fn move_refuses_an_unreadable_original_folder_instead_of_copying() -> Check {
    use std::os::unix::fs::PermissionsExt;
    se_proc::initialize_file_creation_owner()?;
    let fixture = Fixture::new()?;
    let home = &fixture.options.state_directory;
    let deep = fixture.home.join("locked away");
    let original = deep.join("original repository");
    let moved = fixture.home.join("moved repository");
    std::fs::create_dir_all(&original)?;
    git(&original, &["init", "-q", "-b", "main", "."])?;
    git(&original, &["config", "user.email", "se@stateengine.local"])?;
    git(&original, &["config", "user.name", "SE"])?;
    std::fs::write(original.join("note.txt"), "unreadable guard\n")?;
    git(&original, &["add", "."])?;
    git(&original, &["commit", "-qm", "base"])?;
    let output = command(home, &original, true, None)
        .args(["init", "--name", "Locked"])
        .output()?;
    assert!(
        output.status.success(),
        "init refused: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // The repository physically moved, and an unreadable placeholder now
    // occupies the registered path: the folder exists but its contents are
    // not observable, which is not proof the repository left.
    std::fs::rename(&original, &moved)?;
    std::fs::create_dir(&original)?;
    std::fs::set_permissions(&deep, std::fs::Permissions::from_mode(0o000))?;
    let refused = command(home, &moved, false, Some("Locked"))
        .args([
            "project",
            "move",
            moved.to_str().ok_or("moved root is not UTF-8")?,
        ])
        .output()?;
    std::fs::set_permissions(&deep, std::fs::Permissions::from_mode(0o755))?;
    std::fs::remove_dir(&original)?;
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        !refused.status.success(),
        "unreadable original folder must refuse"
    );
    assert!(rendered.contains("is unreadable"), "{rendered}");
    assert!(rendered.contains("not proof that it is gone"), "{rendered}");
    // With the folder truly gone the move commits on a fresh generated key:
    // the refusal copied nothing.
    let moved_ok = command(home, &moved, false, Some("Locked"))
        .args([
            "project",
            "move",
            moved.to_str().ok_or("moved root is not UTF-8")?,
        ])
        .output()?;
    assert!(
        moved_ok.status.success(),
        "move after restoration refused: {} {}",
        String::from_utf8_lossy(&moved_ok.stdout),
        String::from_utf8_lossy(&moved_ok.stderr)
    );
    let row = doctor_check(
        &command(home, &moved, true, None).arg("doctor").output()?,
        "project.root.Locked",
    )?;
    assert_eq!(row["state"], "ok");
    Ok(())
}

#[test]
#[cfg(unix)]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn move_replay_identifies_a_gone_target_spelled_through_a_folder_symlink() -> Check {
    use std::os::unix::fs::symlink;
    se_proc::initialize_file_creation_owner()?;
    let fixture = Fixture::new()?;
    let home = &fixture.options.state_directory;
    let original = fixture.home.join("original repository");
    let moved = fixture.home.join("moved repository");
    let again = fixture.home.join("moved on repository");
    std::fs::create_dir(&original)?;
    git(&original, &["init", "-q", "-b", "main", "."])?;
    git(&original, &["config", "user.email", "se@stateengine.local"])?;
    git(&original, &["config", "user.name", "SE"])?;
    std::fs::write(original.join("note.txt"), "symlink replay\n")?;
    git(&original, &["add", "."])?;
    git(&original, &["commit", "-qm", "base"])?;
    let output = command(home, &original, true, None)
        .args(["init", "--name", "Shortcut"])
        .output()?;
    assert!(
        output.status.success(),
        "init refused: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::rename(&original, &moved)?;
    let key = "se-fh07-symlink-replay-key";
    let moved_str = moved.to_str().ok_or("moved root is not UTF-8")?;
    let output = command(home, &moved, false, Some("Shortcut"))
        .args(["project", "move", moved_str, "--key", key])
        .output()?;
    assert!(
        output.status.success(),
        "move refused: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let first_stdout = String::from_utf8(output.stdout)?;
    let first_event = event_id(&first_stdout)?;
    // While the target is still live, the spelling through a folder symlink
    // canonicalizes to the committed target and replays.
    let link = fixture.home.join("shortcut");
    symlink(&fixture.home, &link)?;
    let linked = link.join("moved repository");
    let linked_str = linked.to_str().ok_or("linked root is not UTF-8")?;
    let pre = command(home, &moved, false, Some("Shortcut"))
        .args(["project", "move", linked_str, "--key", key])
        .output()?;
    assert!(
        pre.status.success(),
        "symlink-spelled replay of a live target refused: {} {}",
        String::from_utf8_lossy(&pre.stdout),
        String::from_utf8_lossy(&pre.stderr)
    );
    assert_eq!(event_id(&String::from_utf8(pre.stdout)?)?, first_event);
    // An alias pointing directly at the moved folder canonicalizes to the
    // committed target while the folder is still live.
    let alias = fixture.home.join("alias");
    symlink(&moved, &alias)?;
    let alias_str = alias.to_str().ok_or("alias is not UTF-8")?;
    let alias_pre = command(home, &moved, false, Some("Shortcut"))
        .args(["project", "move", alias_str, "--key", key])
        .output()?;
    assert!(
        alias_pre.status.success(),
        "direct-alias replay of a live target refused: {} {}",
        String::from_utf8_lossy(&alias_pre.stdout),
        String::from_utf8_lossy(&alias_pre.stderr)
    );
    assert_eq!(
        event_id(&String::from_utf8(alias_pre.stdout)?)?,
        first_event
    );
    // The repository moves on under a new key; the committed target is gone,
    // but the same request spelled through the folder symlink must still
    // identify it and return the retained receipt.
    std::fs::rename(&moved, &again)?;
    let replay = command(home, &again, false, Some("Shortcut"))
        .args(["project", "move", linked_str, "--key", key])
        .output()?;
    assert!(
        replay.status.success(),
        "a gone target spelled through a folder symlink must replay its retained receipt: {} {}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
    assert_eq!(
        event_id(&String::from_utf8(replay.stdout)?)?,
        first_event,
        "the symlink-spelled replay must return the committed receipt, not a new event"
    );
    // The direct alias now dangles: the retained key must still resolve
    // through it to the committed target.
    let alias_replay = command(home, &again, false, Some("Shortcut"))
        .args(["project", "move", alias_str, "--key", key])
        .output()?;
    assert!(
        alias_replay.status.success(),
        "a dangling direct alias must replay its retained receipt: {} {}",
        String::from_utf8_lossy(&alias_replay.stdout),
        String::from_utf8_lossy(&alias_replay.stderr)
    );
    assert_eq!(
        event_id(&String::from_utf8(alias_replay.stdout)?)?,
        first_event,
        "the dangling-alias replay must return the committed receipt, not a new event"
    );
    // A different gone folder behind the same symlink is a different target.
    let other = link.join("never moved here");
    let other_str = other.to_str().ok_or("other root is not UTF-8")?;
    let refused = command(home, &again, false, Some("Shortcut"))
        .args(["project", "move", other_str, "--key", key])
        .output()?;
    assert!(
        !refused.status.success(),
        "a different gone target must refuse"
    );
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        rendered.contains("retained for a different move target"),
        "{rendered}"
    );
    // A dangling alias to a different gone folder still refuses.
    let side = fixture.home.join("side repository");
    std::fs::create_dir(&side)?;
    let side_alias = fixture.home.join("side alias");
    symlink(&side, &side_alias)?;
    std::fs::remove_dir(&side)?;
    let side_alias_str = side_alias.to_str().ok_or("side alias is not UTF-8")?;
    let side_refused = command(home, &again, false, Some("Shortcut"))
        .args(["project", "move", side_alias_str, "--key", key])
        .output()?;
    assert!(
        !side_refused.status.success(),
        "a different dangling target must refuse"
    );
    let side_rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&side_refused.stdout),
        String::from_utf8_lossy(&side_refused.stderr)
    );
    assert!(
        side_rendered.contains("retained for a different move target"),
        "{side_rendered}"
    );
    Ok(())
}
