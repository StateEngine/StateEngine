#!/usr/bin/env python3
"""Run the public PowerShell completion reader with a native protocol fixture.

This checks script result/readback handling, not native uninstall authority or J1.
Run on Windows: python crates/se/tests/windows_uninstall_completion.py
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import threading
import time

SOURCE = r'''
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Web.Script.Serialization;
public static class CompletionFixture {
    public static int Main(string[] args) {
        string mode = Environment.GetEnvironmentVariable("SE_TEST_COMPLETION_MODE");
        string root = Environment.GetEnvironmentVariable("SE_TEST_COMPLETION_ROOT");
        string image = Environment.GetEnvironmentVariable("SE_TEST_INSTALLED_IMAGE");
        string record = Path.Combine(Environment.GetEnvironmentVariable("SE_HOME"), "standalone-install.json");
        string directory = Path.Combine(root, "helper-directory");
        string helper = Path.Combine(directory, "staged-helper.exe");
        if (args.Length == 0 || args[0] != "--fixture-child") {
            if (mode == "parent-failure") return 23;
            Directory.CreateDirectory(directory);
            File.Copy(image, helper);
            Process parent = Process.GetCurrentProcess();
            ProcessStartInfo start = new ProcessStartInfo(helper, "--fixture-child " + parent.Id + " " + parent.StartTime.ToUniversalTime().Ticks);
            start.UseShellExecute = false; start.CreateNoWindow = true;
            start.RedirectStandardOutput = true; start.RedirectStandardError = true;
            Process.Start(start).Dispose(); return 75;
        }
        try {
            // Wait on the fixture parent's exact process object before deleting
            // its actual image. The worker executes a distinct staged copy.
            try {
                using (Process parent = Process.GetProcessById(Int32.Parse(args[1]))) {
                    if (parent.StartTime.ToUniversalTime().Ticks == Int64.Parse(args[2]) && !parent.WaitForExit(10000))
                        throw new Exception("fixture parent did not exit");
                }
            } catch (ArgumentException) { }
            using (NamedPipeClientStream pipe = new NamedPipeClientStream(".", Environment.GetEnvironmentVariable("SE_UNINSTALL_COMPLETION_PIPE"), PipeDirection.Out)) {
                pipe.Connect(10000);
                if (mode != "empty") {
                    string token = Environment.GetEnvironmentVariable("SE_UNINSTALL_COMPLETION_TOKEN");
                    if (mode == "wrong-token") token = new string('0', 64);
                    var achieved = new Dictionary<string, object> {
                        {"schema", "se.uninstall/v1"}, {"idempotency_key", "fixture-request"}, {"complete", false},
                        {"stops", new object[0]}, {"revocations", new object[0]},
                        {"preserved", new string[]{"retained-history"}}, {"recovery", new object[0]},
                        {"path", new Dictionary<string, object>{{"before_entries", new string[]{"owned-path"}}, {"after_entries", new string[0]}}}
                    };
                    Dictionary<string, object> reply = new Dictionary<string, object> {
                        {"schema", "se.uninstall-completion/v1"}, {"token", token},
                        {"complete", mode != "failure"}, {"error", "fixture named deletion failure"},
                        {"image", image}, {"record", record}, {"helper", helper}, {"directory", directory}, {"achieved", achieved}
                    };
                    if (mode == "invalid-path") reply["helper"] = "relative-helper";
                    if (mode == "bogus-image") reply["image"] = Path.Combine(root, "never-installed-image");
                    if (mode != "image-present" && mode != "bogus-image") File.Delete(image);
                    File.Delete(record);
                    using (StreamWriter output = new StreamWriter(pipe)) {
                        output.WriteLine(new JavaScriptSerializer().Serialize(reply));
                    }
                }
            }
            Thread.Sleep(2000);
        } finally {
            // The external test monitor removes the real mapped helper only
            // after it can be deleted. The script must wait for that readback.
            File.WriteAllText(Path.Combine(root, "worker-finished"), "done");
        }
        return 0;
    }
}
'''


@unittest.skipUnless(sys.platform == "win32", "native Windows PowerShell required")
class CompletionReader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="se-uninstall-reader-")
        cls.root = Path(cls.scratch.name)
        source = cls.root / "fixture.cs"
        source.write_text(SOURCE)
        cls.binary = cls.root / "fixture.exe"
        compile_script = cls.root / "compile.ps1"
        compile_script.write_text("param($Source, $Output)\n$ErrorActionPreference='Stop'\n"
                                  "Add-Type -Path $Source -OutputAssembly $Output -OutputType ConsoleApplication "
                                  "-ReferencedAssemblies System.dll,System.Core.dll,System.Web.Extensions.dll\n")
        subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(compile_script),
                        str(source), str(cls.binary)], check=True, capture_output=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def run_reader(self, mode, json_output=False):
        root = self.root / (mode + ("-json" if json_output else ""))
        root.mkdir()
        archive = root / "archive"
        archive.mkdir()
        script = archive / "uninstall.ps1"
        shutil.copy2(Path(__file__).resolve().parents[3] / "scripts/release/uninstall.ps1", script)
        local = root / "local"
        installed = local / "StateEngine/bin/se.exe"
        installed.parent.mkdir(parents=True)
        shutil.copy2(self.binary, installed)
        (archive / "manifest.json").write_text(json.dumps({"files": {"se.exe": {
            "sha256": hashlib.sha256(installed.read_bytes()).hexdigest()}}}))
        state = root / "state"
        state.mkdir()
        (state / "standalone-install.json").write_text("owned fixture record")
        if mode == "image-present":
            # Exercise the unchanged readback loop with a short test-only wait.
            script.write_text(script.read_text().replace("45000", "1000"))
        errors = []
        def retire_worker():
            try:
                until = time.monotonic() + 30
                while not (root / "worker-finished").exists():
                    if time.monotonic() >= until:
                        raise AssertionError("fixture worker did not finish")
                    time.sleep(.02)
                helper = root / "helper-directory/staged-helper.exe"
                while True:
                    try:
                        helper.unlink()
                        helper.parent.rmdir()
                        break
                    except PermissionError:
                        if time.monotonic() >= until:
                            raise
                        time.sleep(.02)
            except Exception as error:
                errors.append(error)
        monitor = None if mode == "parent-failure" else threading.Thread(target=retire_worker)
        if monitor:
            monitor.start()
        env = {**os.environ, "LOCALAPPDATA": str(local), "SE_HOME": str(root / "state"),
               "SE_TEST_COMPLETION_MODE": mode, "SE_TEST_COMPLETION_ROOT": str(root), "SE_TEST_INSTALLED_IMAGE": str(installed),
               "SE_UNINSTALL_COMPLETION_PIPE": "outer-pipe", "SE_UNINSTALL_COMPLETION_TOKEN": "outer-token"}
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(script)]
                                + (["--json"] if json_output else []), env=env,
                                capture_output=True, text=True, timeout=60)
        result.cleanup_pending_on_return = (root / "helper-directory").exists()
        if monitor:
            monitor.join(30)
            self.assertFalse(monitor.is_alive(), "fixture cleanup monitor remains live")
            self.assertFalse(errors, str(errors))
        return result, root

    def test_success_waits_for_outside_cleanup(self):
        result, root = self.run_reader("success")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("removal and cleanup verified", result.stdout)
        self.assertFalse(result.cleanup_pending_on_return, "success returned before helper cleanup")
        self.assertFalse((root / "helper-directory").exists())
        self.assertNotIn("retry se uninstall", result.stdout + result.stderr)

    def test_json_success_is_one_final_object(self):
        result, _ = self.run_reader("success", True)
        self.assertEqual(result.returncode, 0, result.stderr)
        reply = json.loads(result.stdout)
        self.assertTrue(reply["complete"])
        self.assertEqual(reply["achieved"]["schema"], "se.uninstall/v1")
        self.assertEqual(reply["achieved"]["idempotency_key"], "fixture-request")
        self.assertEqual(reply["achieved"]["preserved"], ["retained-history"])
        self.assertEqual(reply["achieved"]["path"]["before_entries"], ["owned-path"])

    def test_helper_failure_is_named_and_nonzero(self):
        result, _ = self.run_reader("failure")
        self.assertEqual(result.returncode, 2)
        self.assertIn("fixture named deletion failure", result.stderr)
        self.assertNotIn("Uninstall complete (", result.stdout)

    def test_json_failure_is_one_final_incomplete_object(self):
        result, _ = self.run_reader("failure", True)
        self.assertEqual(result.returncode, 2)
        reply = json.loads(result.stdout)
        self.assertFalse(reply["complete"])
        self.assertIn("fixture named deletion failure", reply["error"])

    def test_wrong_token_cannot_claim_success(self):
        result, _ = self.run_reader("wrong-token")
        self.assertEqual(result.returncode, 2)
        self.assertIn("does not match this invocation", result.stderr)

    def test_eof_without_result_cannot_claim_success(self):
        result, _ = self.run_reader("empty")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Uninstall complete (", result.stdout)

    def test_invalid_cleanup_path_cannot_claim_success(self):
        result, _ = self.run_reader("invalid-path")
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid cleanup path", result.stderr)

    def test_truthful_present_installed_image_cannot_claim_success(self):
        result, _ = self.run_reader("image-present")
        self.assertEqual(result.returncode, 2)
        self.assertIn("cleanup absence was not witnessed", result.stderr)

    def test_bogus_absent_image_cannot_replace_own_binary_readback(self):
        result, _ = self.run_reader("bogus-image")
        self.assertEqual(result.returncode, 2)
        self.assertIn("different installed image or record", result.stderr)

    def test_pre_handoff_failure_keeps_its_exit_code(self):
        result, _ = self.run_reader("parent-failure")
        self.assertEqual(result.returncode, 23)
        self.assertNotIn("Uninstall complete (", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
