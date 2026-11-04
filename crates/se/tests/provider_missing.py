"""Author consumer: missing provider guidance through the public CLI.
Uses only owned homes, a native Claude protocol fixture and a pre-spawn terminal
fixture. Run with --se RELEASE_SE --output NEW_OWNED_DIRECTORY on Linux.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).with_name("judges")))
from mail_cli import Fixture


def run(se, output):
    output.mkdir(parents=True, exist_ok=False)
    f = Fixture(se, output / "owner")
    checks = []
    config = f.home / "config.toml"
    original = config.read_text()
    empty_path = f.root / "empty-path"
    empty_path.mkdir()
    terminal = f.root / "xterm"
    terminal.write_text("#!/bin/sh\nexit 91\n")
    terminal.chmod(0o700)
    f.env.update(PATH=str(empty_path), DISPLAY=":owned-unreachable-display")
    denied = f.root / "unreadable"

    def check(name):
        checks.append(name)
        print(f"ok {len(checks)} - {name}", flush=True)

    def guidance(value, provider, command):
        assert value["code"] == "provider-cli-not-found", value
        assert value["detail"]["provider"] == provider, value
        assert command in value["detail"]["searched"], value
        text = value["remedy"]["text"]
        assert command in text and f"[providers.{provider}]" in text, value
        assert str(config) in text and "https://" in text, value
        assert "unreadable state" not in text and "se config set providers." not in text, value

    try:
        codex = f.ok("--project", f.project, "agent", "add", "Missing Codex",
                     "--provider", "codex", "--model", "gpt-6.1-sol")["agent"]["id"]
        missing = original.replace("command = " + json.dumps(str(f.root / "provider")),
                                   'command = "claude"', 1)
        missing = missing.replace('terminal = ""', "terminal = " + json.dumps(str(terminal)), 1)
        config.write_text(missing)
        for provider, agent in [("codex", codex), ("claude", f.agent)]:
            for detached in [True, False]:
                for as_json in [True, False]:
                    args = ["--key", str(uuid.uuid4()), "--project", f.project, "launch", agent,
                            "--task", "Read existing.txt"]
                    if detached:
                        args.append("--detach")
                    f.calls += 1
                    result = subprocess.run([str(se), "--home", str(f.home),
                                             *(["--json"] if as_json else []), *args],
                                            env=f.env, stdin=subprocess.DEVNULL,
                                            capture_output=True, timeout=90)
                    prefix = output / f"cli-{f.calls:02}"
                    prefix.with_suffix(".stdout").write_bytes(result.stdout)
                    prefix.with_suffix(".stderr").write_bytes(result.stderr)
                    assert result.returncode != 0, result.stdout
                    if as_json:
                        guidance(json.loads(result.stdout), provider, provider)
                    else:
                        text = result.stderr.decode()
                        assert "provider-cli-not-found" in text and provider in text and "https://" in text, text
                        assert "unreadable state" not in text, text
                    check(f"{provider} {'detached' if detached else 'attended'} {'JSON' if as_json else 'plain'} names provider, command and install/config recovery")
        f.close()

        absolute = f.root / "not-installed" / "codex"
        config.write_text(original.replace("[providers.codex]", "[providers.codex]\ncommand = " + json.dumps(str(absolute)), 1))
        result = f.call("--project", f.project, "launch", codex, "--detach")
        assert result.returncode != 0
        guidance(json.loads(result.stdout), "codex", str(absolute))
        check("missing absolute executable is a provider absence with the exact configured path")
        f.close()

        denied.mkdir()
        denied.chmod(0)
        absolute = denied / "codex"
        config.write_text(original.replace("[providers.codex]", "[providers.codex]\ncommand = " + json.dumps(str(absolute)), 1))
        result = f.call("--project", f.project, "launch", codex, "--detach")
        assert result.returncode != 0
        value = json.loads(result.stdout)
        assert value["code"] == "source-unreadable", value
        assert "Permission denied" in value["message"], value
        assert "Codex" in value["remedy"]["text"], value
        check("unreadable executable parent remains unreadable, separate from provider absence")
        denied.chmod(0o700)
        f.close()
        config.write_text(original)
        f.launch()
        check("configured native provider still launches with a session pin and both discovery transports")
    finally:
        if denied.exists():
            denied.chmod(0o700)
        config.write_text(original)
        f.close()
    check("public shutdown retires endpoints and the owned parent/helper process births")
    (output / "result.json").write_text(json.dumps({"passed": len(checks), "checks": checks,
                                                    "fixture": str(f.root)}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    run(options.se.resolve(), options.output.resolve())
