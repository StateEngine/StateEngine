#![cfg(feature = "remote")]

use se_host::remote::ssh::{build_remote_se_command, posix_single_quote, powershell_single_quote};
use se_remote_cli::{derive_alias, parse_remote_spec, validate_agent_name};

#[test]
fn parse_remote_spec_accepts_unix_ipv6_and_windows_paths() {
    assert_eq!(
        parse_remote_spec("user@build-box:/srv/repo").ok(),
        Some(("user@build-box".into(), "/srv/repo".into()))
    );
    assert_eq!(
        parse_remote_spec("[::1]:/srv/repo").ok(),
        Some(("[::1]".into(), "/srv/repo".into()))
    );
    assert_eq!(
        parse_remote_spec("winhost:C:\\work\\repo").ok(),
        Some(("winhost".into(), "C:\\work\\repo".into()))
    );
}

#[test]
fn parse_remote_spec_refuses_injection_and_malformed_inputs() {
    for bad in [
        "missing-colon",
        ":/only-path",
        "host:",
        "-oProxyCommand=evil:/tmp",
        "host;id:/tmp",
        "host:/tmp/\0bad",
        "host:/tmp/\nnewline",
        "host:C:\\work\\has\"quote",
        "host:C:\\work\\trailing\\",
        "host:C:\\work\\space\\ dir",
    ] {
        assert!(parse_remote_spec(bad).is_err(), "must refuse {bad:?}");
    }
}

#[test]
fn derive_alias_sanitizes_user_and_host() {
    assert_eq!(
        derive_alias("dev@build-01.example.com").ok().as_deref(),
        Some("build-01-example-com")
    );
    assert_eq!(derive_alias("gpu-box").ok().as_deref(), Some("gpu-box"));
}

#[test]
fn validate_agent_name_rejects_shell_metacharacters() {
    assert!(validate_agent_name("worker_1-a").is_ok());
    for bad in [
        "",
        "-leading",
        "--flag",
        "a;rm -rf /",
        "$(whoami)",
        "has space",
        "a/b",
    ] {
        assert!(validate_agent_name(bad).is_err(), "must refuse {bad:?}");
    }
}

#[test]
fn quoting_neutralizes_shell_metacharacters() {
    let evil = "/tmp/o'reilly; $(rm -rf /) `id` $HOME";
    assert_eq!(
        posix_single_quote(evil),
        "'/tmp/o'\\''reilly; $(rm -rf /) `id` $HOME'"
    );
    assert_eq!(
        powershell_single_quote(evil),
        "'/tmp/o''reilly; $(rm -rf /) `id` $HOME'"
    );
    assert_eq!(
        powershell_single_quote("a\u{2018}b\u{2019}c\u{201A}d\u{201B}e"),
        "'a\u{2018}\u{2018}b\u{2019}\u{2019}c\u{201A}\u{201A}d\u{201B}\u{201B}e'"
    );

    let cmd = build_remote_se_command(".se-bin", false, &["init", "--repo", evil, "--json"]);
    assert!(cmd.starts_with("'./.se-bin' "));
    assert!(cmd.contains("'/tmp/o'\\''reilly; $(rm -rf /) `id` $HOME'"));
    assert!(!cmd.contains("init --repo /tmp"));

    let win_cmd = build_remote_se_command(
        ".se-bin",
        true,
        &["init", "--repo", "a\u{2019};calc", "--json"],
    );
    assert!(win_cmd.starts_with("powershell"));
    assert!(win_cmd.contains("-EncodedCommand"));
}

#[test]
fn remote_init_is_strictly_owner_only_and_absent_from_mcp_tools()
-> Result<(), Box<dyn std::error::Error>> {
    let tools = se_core::ops::mcp_tools()?;
    assert!(
        !tools
            .iter()
            .any(|tool| tool.name.contains("remote_init") || tool.name.contains("remote_add")),
        "owner SSH bootstrap controls must never appear as MCP tools"
    );
    Ok(())
}
