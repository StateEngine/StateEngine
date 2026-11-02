#!/usr/bin/env python3
"""Independent process-boundary regression for the public completion reader.

Run on Windows: python crates/se/tests/windows_uninstall_reply_paths.py
--source-root selects the candidate whose unmodified uninstall.ps1 is exercised.
This protocol process conveys no uninstall authority and deletes nothing. These
two tests complement, rather than establish, actual-native uninstall acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from windows_uninstall_final_status import clean


SOURCE = r'''
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Web.Script.Serialization;
public static class ReplyPaths {
    public static int Main(string[] args) {
        if (args.Length == 0 || args[0] != "--reply") {
            ProcessStartInfo child = new ProcessStartInfo(
                Environment.GetEnvironmentVariable("SE_JUDGE_SENDER"), "--reply");
            child.UseShellExecute = false;
            child.CreateNoWindow = true;
            child.RedirectStandardOutput = true;
            child.RedirectStandardError = true;
            Process.Start(child).Dispose();
            return 75;
        }
        string root = Environment.GetEnvironmentVariable("SE_JUDGE_ROOT");
        bool bogus = Environment.GetEnvironmentVariable("SE_JUDGE_MODE") == "bogus-absent";
        string image = Path.Combine(root, "local", "StateEngine", "bin", "se.exe");
        string record = Path.Combine(root, "state", "standalone-install.json");
        Dictionary<string, object> reply = new Dictionary<string, object> {
            {"schema", "se.uninstall-completion/v1"},
            {"token", Environment.GetEnvironmentVariable("SE_UNINSTALL_COMPLETION_TOKEN")},
            {"complete", true}, {"error", null},
            {"image", bogus ? Path.Combine(root, "absent-image") : image},
            {"record", bogus ? Path.Combine(root, "absent-record") : record},
            {"helper", Path.Combine(root, "absent-helper")}, {"directory", null}
        };
        using (NamedPipeClientStream pipe = new NamedPipeClientStream(".",
                   Environment.GetEnvironmentVariable("SE_UNINSTALL_COMPLETION_PIPE"), PipeDirection.Out)) {
            pipe.Connect(10000);
            using (StreamWriter writer = new StreamWriter(pipe)) {
                writer.WriteLine(new JavaScriptSerializer().Serialize(reply));
            }
        }
        // All advertised bogus paths were absent, but the actual image and
        // ownership record are intentionally still present when we exit.
        return 0;
    }
}
'''


class ReplyPathJudge(unittest.TestCase):
    source_root = Path(__file__).resolve().parents[3]

    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="se-uninstall-path-judge-")
        cls.root = Path(cls.scratch.name)
        source = cls.root / "reply.cs"
        source.write_text(SOURCE, encoding="utf-8")
        cls.sender = cls.root / "sender.exe"
        compile_script = cls.root / "compile.ps1"
        compile_script.write_text("param($Source, $Output)\n$ErrorActionPreference='Stop'\n"
                                  "Add-Type -Path $Source -OutputAssembly $Output -OutputType ConsoleApplication "
                                  "-ReferencedAssemblies System.dll,System.Core.dll,System.Web.Extensions.dll\n")
        subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(compile_script),
                        str(source), str(cls.sender)], capture_output=True, timeout=30, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def reject_reply(self, mode):
        root = self.root / mode
        script = root / "archive/uninstall.ps1"
        script.parent.mkdir(parents=True)
        shutil.copyfile(self.source_root / "scripts/release/uninstall.ps1", script)
        image = root / "local/StateEngine/bin/se.exe"
        image.parent.mkdir(parents=True)
        shutil.copyfile(self.sender, image)
        record = root / "state/standalone-install.json"
        record.parent.mkdir()
        record.write_bytes(b"retained installation custody\n")
        before_image, before_record = image.read_bytes(), record.read_bytes()
        (script.parent / "manifest.json").write_text(json.dumps({"files": {"se.exe": {
            "sha256": hashlib.sha256(before_image).hexdigest()}}}))
        env = {key: value for key, value in os.environ.items() if not key.startswith("SE_")}
        env.update(LOCALAPPDATA=str(root / "local"), SE_HOME=str(record.parent),
                   SE_JUDGE_ROOT=str(root), SE_JUDGE_MODE=mode, SE_JUDGE_SENDER=str(self.sender))
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(script)],
                                env=env, capture_output=True, timeout=65)
        text = clean((result.stdout + result.stderr).decode("utf-8", errors="replace"))
        self.assertEqual(image.read_bytes(), before_image, "the fixture's actual installed image changed")
        self.assertEqual(record.read_bytes(), before_record, "the fixture's actual record changed")
        self.assertNotEqual(result.returncode, 0, "complete:true bypassed actual installation readback:\n" + text)
        self.assertNotIn("Uninstall complete (", text, "failure printed success")
        self.assertRegex(text.lower(), r"(image|record|cleanup|absence|path)", "failure did not name its reason")
        if mode == "honest-present":
            self.assertIn(str(image).lower(), text.lower(), "the unresolved installed image was not named")

    def test_matching_reply_cannot_succeed_while_actual_image_is_present(self):
        self.reject_reply("honest-present")

    def test_absent_foreign_reply_paths_cannot_replace_actual_installation_readback(self):
        self.reject_reply("bogus-absent")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=ReplyPathJudge.source_root)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("native Windows PowerShell is required; no skipped-green result")
    ReplyPathJudge.source_root = args.source_root.resolve()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ReplyPathJudge))
    raise SystemExit(0 if result.wasSuccessful() else 1)
