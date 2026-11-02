#!/usr/bin/env python3
"""Independent native public-entry judge; run only on the dedicated Windows account.

python crates/se/tests/windows_uninstall_final_status.py --bundle C:\\bundle\\product \
  --terminal C:\\bundle\\journeys\\terminal-windows.ps1 --out C:\\uninstall-judge

The bundle must contain the actual candidate executable, manifest and release
scripts. No production bytes are replaced. The terminal is the journey ConPTY
bridge (2bbcd8c2b or later). Installation edits this account's USER Path; run
serially on the clean test account. Fixtures/transcripts remain under --out.
Linux can check the verdict oracle with --self-test or reject the recorded J1
false-incomplete run with --journey-results PATH.tgz (expected exit 1).
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import unittest


# This caller stays outside both the installed process and its private helper.
# Capture at the script's return, BEFORE the ConPTY bridge drains child output.
# Otherwise an early exit could be hidden by a later successful helper teardown.
CALLER = r'''
param([string]$Plan)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$p = Get-Content -LiteralPath $Plan -Raw | ConvertFrom-Json
$powershell = Join-Path $PSHOME 'powershell.exe'
& $powershell -NoProfile -NonInteractive -File $p.entry @($p.arguments)
$code = $LASTEXITCODE
function Observe([string]$path) {
    try { $null = [IO.File]::GetAttributes($path); return @{path=$path; state='present'} }
    catch [IO.FileNotFoundException] { return @{path=$path; state='absent'} }
    catch [IO.DirectoryNotFoundException] { return @{path=$path; state='absent'} }
    catch { return @{path=$path; state='unreadable'; error=$_.Exception.Message} }
}
function Native-Path($value) {
    if ($value.encoding -cne 'windows_utf16') { throw 'helper custody path is not Windows UTF-16' }
    return -join @($value.units | ForEach-Object { [char]$_ })
}
$observations = @($p.paths | ForEach-Object { Observe $_ })
$journal = Observe $p.journal
$helper = $null
if ($journal.state -eq 'present') {
    $debt = Get-Content -LiteralPath $p.journal -Raw | ConvertFrom-Json
    $helper = Native-Path $debt.path
    $observations += Observe $helper
    if ($null -ne $debt.directory) { $observations += Observe (Native-Path $debt.directory.path) }
} elseif ($code -eq 0) { throw 'success returned without readable helper custody' }
$snapshot = @{code=$code; observations=$observations; helper=$helper;
    user_path=[Environment]::GetEnvironmentVariable('Path','User')}
[IO.File]::WriteAllText($p.snapshot, ($snapshot | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
exit $code
'''

ANSI = re.compile(r"\x1b(?:\][^\x07\x1b]*(?:\x07|\x1b\\)|\[[0-?]*[ -/]*[@-~])")


def clean(text):
    return ANSI.sub("", text).replace("\r", "")


def successful_verdict(code, text, observations, json_mode=False):
    """One public success, agreeing with the caller's immediate outside readback."""
    text = clean(text)
    if code != 0:
        raise AssertionError(f"public uninstall returned {code}, expected final success: {text[-1800:]}")
    if not observations or any(row["state"] != "absent" for row in observations):
        raise AssertionError(f"success preceded outside absence: {observations}")
    if "uninstall incomplete" in text.lower() or "retry se uninstall" in text.lower():
        raise AssertionError("the user received an incomplete verdict or an impossible retry")
    if json_mode:
        replies = [json.loads(line) for line in text.splitlines() if line.startswith("{")]
        if len(replies) != 1 or replies[0].get("complete") is not True:
            raise AssertionError(f"expected exactly one final complete JSON object: {replies}")
        reply = replies[0]
        achieved = reply.get("achieved", {})
        if reply.get("schema") != "se.uninstall-completion/v1" or achieved.get("schema") != "se.uninstall/v1":
            raise AssertionError("final JSON lost the achieved se.uninstall/v1 report")
        for key in ("idempotency_key", "install_files", "directories", "integrations", "stops",
                    "revocations", "path", "preserved", "recovery"):
            if key not in achieved:
                raise AssertionError(f"achieved report lost {key}")
    elif len(re.findall(r"(?im)^Uninstall complete\b", text)) != 1:
        raise AssertionError("expected exactly one final human completion verdict")


def failed_verdict(code, text, path):
    text = clean(text)
    if code == 0:
        raise AssertionError("a changed owned file received success")
    if re.search(r"(?im)^Uninstall complete\b", text) or '"complete":true' in text.replace(" ", ""):
        raise AssertionError("a failed uninstall printed a success verdict")
    if str(path).lower() not in text.lower():
        raise AssertionError(f"failure did not name the unresolved owned path: {text[-1800:]}")


class VerdictOracle(unittest.TestCase):
    def test_witnessed_success(self):
        successful_verdict(0, "Uninstall complete (verified).", [{"state": "absent"}])

    def test_false_incomplete_stays_red_even_after_helper_deletes(self):
        with self.assertRaisesRegex(AssertionError, "returned 2"):
            successful_verdict(2, "Uninstall incomplete\nRemoved installed image (witnessed)", [{"state": "absent"}])

    def test_premature_success_stays_red(self):
        for state in ("present", "unreadable"):
            with self.subTest(state=state), self.assertRaisesRegex(AssertionError, "outside absence"):
                successful_verdict(0, "Uninstall complete", [{"state": state}])

    def test_success_does_not_erase_an_earlier_false_verdict(self):
        with self.assertRaisesRegex(AssertionError, "incomplete verdict"):
            successful_verdict(0, "retry se uninstall\nUninstall complete", [{"state": "absent"}])

    def test_json_requires_one_complete_object(self):
        report = {"schema": "se.uninstall/v1", "idempotency_key": "request", "path": {},
                  **{key: [] for key in ("install_files", "directories", "integrations", "stops",
                                        "revocations", "preserved", "recovery")}}
        reply = json.dumps({"schema": "se.uninstall-completion/v1", "complete": True, "achieved": report})
        successful_verdict(0, reply, [{"state": "absent"}], True)
        for text in ('{"complete":false}', '{"complete":true}\n{"complete":true}'):
            with self.subTest(text=text), self.assertRaises(AssertionError):
                successful_verdict(0, text, [{"state": "absent"}], True)

    def test_final_json_keeps_achieved_facts(self):
        with self.assertRaisesRegex(AssertionError, "achieved"):
            successful_verdict(0, '{"schema":"se.uninstall-completion/v1","complete":true}',
                               [{"state": "absent"}], True)

    def test_failure_requires_named_cause_and_no_success(self):
        failed_verdict(2, "Uninstall incomplete: C:\\owned was modified", r"C:\owned")
        for code, text in ((0, "C:\\owned"), (2, "Uninstall incomplete"), (2, "Uninstall complete C:\\owned")):
            with self.subTest(code=code, text=text), self.assertRaises(AssertionError):
                failed_verdict(code, text, r"C:\owned")


class NativeFinalStatus(unittest.TestCase):
    options = None

    def run_command(self, argv, env, root, name, terminal=False):
        if terminal:
            encoded = base64.b64encode(json.dumps(argv).encode()).decode()
            argv = ["powershell.exe", "-NoProfile", "-NonInteractive", "-File",
                    str(self.options.terminal), "-ArgvBase64", encoded]
        result = subprocess.run(argv, env=env, capture_output=True, timeout=210)
        (root / (name + ".stdout")).write_bytes(result.stdout)
        (root / (name + ".stderr")).write_bytes(result.stderr)
        (root / (name + ".json")).write_text(json.dumps({"argv": argv, "code": result.returncode}, indent=2))
        return result, (result.stdout + result.stderr).decode("utf-8", errors="replace")

    def exercise(self, json_mode=False, changed=False, home_form=None, conflicting_home=False):
        import winreg

        root = self.options.out / self._testMethodName
        if home_form:
            root /= "conflicting-environment" if conflicting_home else "unset-environment"
        root.mkdir(parents=True, exist_ok=False)
        bundle = root / "archive"
        shutil.copytree(self.options.bundle, bundle)
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("SE_") and key not in ("CLAUDECODE", "CODEX_THREAD_ID", "CODEX_CI")}
        env.update(LOCALAPPDATA=str(root / "local"), SE_HOME=str(root / "state"))
        # Read the real native registry value; never repair a product outcome.
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            try:
                before_path = winreg.QueryValueEx(key, "Path")[0]
            except FileNotFoundError:
                before_path = None
        install, text = self.run_command(["powershell.exe", "-NoProfile", "-NonInteractive", "-File",
                                          str(bundle / "install.ps1")], env, root, "install")
        self.assertEqual(install.returncode, 0, text)
        image = root / "local/StateEngine/bin/se.exe"
        record = root / "state/standalone-install.json"
        inventory = json.loads(record.read_bytes())
        (root / "installed-inventory.json").write_text(json.dumps(inventory, indent=2))
        self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(),
                         json.loads((bundle / "manifest.json").read_bytes())["files"]["se.exe"]["sha256"])
        repo = root / "repository"
        repo.mkdir()
        sentinel = repo / "user-work.txt"
        sentinel.write_bytes(b"user work survives uninstall\n")
        init, text = self.run_command([str(image), "--json", "init", "--repo", str(repo),
                                      "--name", "uninstall-judge", "--agent", "main", "--provider", "claude"],
                                     env, root, "init")
        self.assertEqual(init.returncode, 0, text)
        retained = {path: path.read_bytes() for path in (root / "state/state.db", root / "state/config.toml")}
        asset = next(Path(row["path"]) for row in inventory["files"] if Path(row["path"]).name == "NOTICE.txt")
        if changed:
            asset.write_bytes(b"user changed this owned asset\n")
        caller = root / "caller.ps1"
        caller.write_text(CALLER, encoding="utf-8")
        snapshot_path = root / "at-public-return.json"
        # Plain uses the archive entry; JSON uses the installed mirror entry.
        entry = root / "local/StateEngine/installation/uninstall.ps1" if json_mode else bundle / "uninstall.ps1"
        arguments = ["--json"] if json_mode else []
        uninstall_env = env.copy()
        unrelated = None
        if home_form:
            # Installation/init used the actual custom home. Only the public
            # uninstall invocation now changes environment/flag selection.
            if conflicting_home:
                other_home = root / "unrelated-state"
                other_home.mkdir()
                unrelated = other_home / "user-work.txt"
                unrelated.write_bytes(b"unrelated home must remain untouched\n")
                uninstall_env["SE_HOME"] = str(other_home)
            else:
                uninstall_env.pop("SE_HOME")
            arguments += (["--home", str(record.parent)] if home_form == "separate"
                          else ["--home=" + str(record.parent)])
        plan = {"entry": str(entry), "arguments": arguments,
                "paths": [row["path"] for row in inventory["files"]] + [str(record)],
                "journal": str(root / "state/uninstall-helper-cleanup.json"), "snapshot": str(snapshot_path)}
        plan_path = root / "plan.json"
        plan_path.write_text(json.dumps(plan), encoding="utf-8")
        result, text = self.run_command([shutil.which("powershell.exe"), "-NoProfile", "-NonInteractive", "-File",
                                         str(caller), "-Plan", str(plan_path)], uninstall_env, root, "uninstall", terminal=True)
        self.assertTrue(snapshot_path.is_file(), "outside caller could not capture the returned outcome: " + text[-1800:])
        snapshot = json.loads(snapshot_path.read_bytes())
        self.assertEqual(result.returncode, snapshot["code"], "terminal changed the public exit code")
        if changed:
            # No helper should have been authorized for this partial failure.
            failed_verdict(result.returncode, text, asset)
            self.assertEqual(asset.read_bytes(), b"user changed this owned asset\n")
            self.assertTrue(image.is_file(), "failure stranded the native retry entry")
            self.assertTrue(record.is_file(), "failure discarded installation custody")
        else:
            successful_verdict(snapshot["code"], text, snapshot["observations"], json_mode)
            self.assertEqual(snapshot["user_path"], before_path, "USER Path was not restored at public return")
        self.assertEqual(sentinel.read_bytes(), b"user work survives uninstall\n")
        for path, data in retained.items():
            self.assertEqual(path.read_bytes(), data, "uninstall changed retained user data")
        if unrelated:
            self.assertEqual(unrelated.read_bytes(), b"unrelated home must remain untouched\n")
            self.assertEqual(list(unrelated.parent.iterdir()), [unrelated], "uninstall wrote into the conflicting environment home")

    def test_plain_archive_entry_waits_for_native_cleanup(self):
        self.exercise()

    def test_json_installed_entry_waits_for_native_cleanup(self):
        self.exercise(json_mode=True)

    def test_real_changed_asset_has_named_failure_and_retains_retry(self):
        self.exercise(changed=True)

    def test_home_flag_selects_own_record_over_unset_or_conflicting_environment(self):
        for conflicting in (False, True):
            with self.subTest(conflicting_home=conflicting):
                self.exercise(home_form="separate", conflicting_home=conflicting)

    def test_home_equals_selects_own_record_over_unset_or_conflicting_environment(self):
        for conflicting in (False, True):
            with self.subTest(conflicting_home=conflicting):
                self.exercise(json_mode=True, home_form="equals", conflicting_home=conflicting)


def recorded_journey(archive):
    with tarfile.open(archive) as source:
        names = source.getnames()
        candidates = [name for name in names if name.endswith(".json") and "/1-Install/" in name]
        runs = [(name, json.load(source.extractfile(name))) for name in candidates]
        uninstall = [(name, row) for name, row in runs if isinstance(row, dict)
                     and "-ArgvBase64" in row.get("args", [])
                     and "uninstall.ps1" in base64.b64decode(row["args"][-1]).decode(errors="replace")]
        if len(uninstall) != 1:
            raise AssertionError(f"expected exactly one recorded public uninstall, got {len(uninstall)}")
        name, row = uninstall[0]
        text = source.extractfile(name[:-5] + ".stdout").read().decode("utf-8", errors="replace")
        # This route only establishes the recorded nonzero regression. It must
        # refuse success evidence: the historical run has no return-time snapshot.
        successful_verdict(row["code"], text, [])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--terminal", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--journey-results", type=Path)
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(VerdictOracle)
    elif args.journey_results:
        recorded_journey(args.journey_results)
        return 0
    else:
        if sys.platform != "win32":
            parser.error("native Windows is required; Linux oracle checks do not establish uninstall completion")
        if not all((args.bundle, args.terminal, args.out)):
            parser.error("--bundle, --terminal and --out are required")
        args.bundle, args.terminal, args.out = args.bundle.resolve(), args.terminal.resolve(), args.out.resolve()
        for name in ("se.exe", "manifest.json", "install.ps1", "uninstall.ps1"):
            if not (args.bundle / name).is_file():
                parser.error(f"candidate bundle missing {name}")
        if not args.terminal.is_file():
            parser.error("ConPTY terminal script unavailable")
        NativeFinalStatus.options = args
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeFinalStatus)
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
