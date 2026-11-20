"""Protects: a launching terminal's Claude sign-in reaches that launch's child only.

Run against an isolated binary with --se IMAGE --output NEW_DIRECTORY. A native
Claude double reports signed in only while the synthetic token is in its
environment, and records whether each child it starts saw the token.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from mail_cli import Fixture

TOKEN = "test-token-not-real-0000"
ENVIRONMENT = "CLAUDE_CODE_OAUTH_TOKEN"
SIGNED_IN_LINE = """if a.get(1).map(String::as_str)==Some("auth") {println!(r#"{{"loggedIn":true}}"#);return;}"""
STUB = """if a.get(1).map(String::as_str)==Some("auth") {
let ok=std::env::var("@NAME@").as_deref()==Ok("@VALUE@");
if ok {println!(r#"{{"loggedIn":true}}"#);} else {println!(r#"{{"loggedIn":false}}"#);std::process::exit(1);}
return;}
{use std::io::Write;let seen=std::env::var("@NAME@").as_deref()==Ok("@VALUE@");
let mut f=std::fs::OpenOptions::new().create(true).append(true).open("child-env.log").unwrap();
writeln!(f,"child_has_token={}",seen).unwrap();}""".replace("@NAME@", ENVIRONMENT).replace("@VALUE@", TOKEN)


def install_double(fixture):
    source = fixture.root / "provider.rs"
    text = source.read_text()
    assert SIGNED_IN_LINE in text, "the shared double changed its sign-in probe"
    # The current provider qualification contract needs this version.
    source.write_text(text.replace(SIGNED_IN_LINE, STUB).replace("2.1.287", "2.1.318"))
    executable = fixture.root / ("provider.exe" if os.name == "nt" else "provider")
    subprocess.run(["rustc", "--edition=2024", str(source), "-o", str(executable)],
                   stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=60)


def child_lines(fixture):
    path = fixture.repo / "child-env.log"
    return path.read_text().splitlines() if path.exists() else []


def files_with_token(fixture):
    roots = [fixture.home, *fixture.root.glob("call-*")]
    found = []
    for root in roots:
        paths = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file() and not p.is_symlink()]
        found += [str(p) for p in paths if TOKEN.encode() in p.read_bytes()]
    return found


def host_environments_with_token(fixture):
    owner = f"HOME={fixture.root / 'owner'}".encode()
    seen, leaked = 0, []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            if Path(os.readlink(entry / "exe")) != fixture.se:
                continue
            environ = (entry / "environ").read_bytes()
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        if owner in environ.split(b"\0"):
            seen += 1
            if TOKEN.encode() in environ:
                leaked.append(entry.name)
    return seen, leaked


def run(image, output):
    fixture = Fixture(image, output)
    install_double(fixture)
    try:
        fixture.ok("up")
        fixture.env[ENVIRONMENT] = TOKEN
        try:
            fixture.launch()
        finally:
            del fixture.env[ENVIRONMENT]
        assert "child_has_token=true" in child_lines(fixture), (
            "a terminal launch must hand its sign-in to the child", child_lines(fixture))
        print("ok 1 - terminal launch passes sign-in and the child receives the token", flush=True)

        fixture.ok("--project", fixture.project, "stop", fixture.agent)
        before = len(child_lines(fixture))
        refused = fixture.call("--project", fixture.project, "launch", fixture.agent,
                               "--detach", "--task", "second launch")
        text = (refused.stdout + refused.stderr).decode(errors="replace").lower()
        assert refused.returncode != 0 and "sign" in text, (refused.returncode, text)
        assert "child_has_token=true" not in child_lines(fixture)[before:], "the token outlived its launch"
        print("ok 2 - the next launch without the token is refused as signed out", flush=True)

        leaks = files_with_token(fixture)
        assert not leaks, ("token found in", leaks)
        hosts, leaked = host_environments_with_token(fixture)
        assert not leaked, ("host process environment holds the token", leaked)
        print(f"ok 3 - token absent from data home, call output and {hosts} host environments", flush=True)
    finally:
        fixture.call("down")
    assert not files_with_token(fixture), "token appeared during shutdown"
    print("ok 4 - token absent after shutdown", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    run(args.se, args.output)
