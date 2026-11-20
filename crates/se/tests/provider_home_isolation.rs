//! Refuse inherited, escaped, and redirected provider configuration before launch.
#[path = "../../test-support/directory.rs"]
mod directory;
#[path = "../../test-support/provider_home.rs"]
mod provider_home;

use std::process::Command;

type Check = Result<(), Box<dyn std::error::Error>>;

#[test]
fn every_provider_home_must_be_set_inside_the_fixture() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let fixture = directory::private_directory()?;
    let unrelated = directory::private_directory()?;
    let mut child = Command::new("unused");
    provider_home::isolate(&mut child, &fixture);
    assert!(fixture.join("user-home/.codex").is_dir());
    assert!(fixture.join("user-home/.claude").is_dir());
    for key in [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "CODEX_HOME",
        "CLAUDE_CONFIG_DIR",
    ] {
        child.env_remove(key);
        assert!(provider_home::assert_isolated(&child, &fixture).is_err());
        child.env(key, unrelated.join("outside"));
        assert!(provider_home::assert_isolated(&child, &fixture).is_err());
        provider_home::isolate(&mut child, &fixture);
    }
    child.env("CODEX_HOME", fixture.join("../escaped"));
    assert!(provider_home::assert_isolated(&child, &fixture).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_provider_home_cannot_resolve_through_a_link_outside_the_fixture() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let fixture = directory::private_directory()?;
    let unrelated = directory::private_directory()?;
    let linked = fixture.join("linked");
    std::os::unix::fs::symlink(unrelated.as_ref(), &linked)?;
    let mut child = Command::new("unused");
    provider_home::isolate(&mut child, &fixture);
    child.env("CODEX_HOME", linked.join("nonexistent"));
    let refused = provider_home::assert_isolated(&child, &fixture);
    std::fs::remove_file(linked)?;
    assert!(refused.is_err());

    let codex = fixture.join("codex");
    std::fs::create_dir(&codex)?;
    let config = codex.join("config.toml");
    std::os::unix::fs::symlink(unrelated.join("config.toml"), &config)?;
    child.env("CODEX_HOME", codex);
    let refused = provider_home::assert_isolated(&child, &fixture);
    std::fs::remove_file(config)?;
    assert!(refused.is_err());
    Ok(())
}
