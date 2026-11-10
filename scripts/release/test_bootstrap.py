"""Exercise the one-shot install bootstrappers against a local release server.

The server holds one signed stub package: a secode shim that validates the
payload manifest with a real JSON parser and then records its argv, plus
the StateEngine payload manifest — the legacy
``stateengine-payload.json`` by default, or any mix of the legacy and
``native-payload.json`` manifests chosen with ``set_payloads`` before the
run. The harness generates an RSA key pair, signs the archive, and serves
the index, archive and detached signature over 127.0.0.1. Every happy path
must hand off to `secode update --from <dir>`; every bad release must be
refused in plain words before any hand off.
"""
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import threading
import unittest
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP_SH = ROOT / "scripts" / "release" / "bootstrap.sh"
NPX_BIN = ROOT / "scripts" / "release" / "npx-install" / "bin" / "se-one-line.mjs"

VERSION = "0.1.0"
TARGET = "x86_64-unknown-linux-gnu"
ARCHIVE_NAME = f"stateengine-{VERSION}-{TARGET}.tar.gz"
SIGNATURE_NAME = ARCHIVE_NAME + ".sig"
PACKAGE_DIR_NAME = f"stateengine-{VERSION}-{TARGET}"

LEGACY_PAYLOAD = {
    "schema": "stateengine.se-payload.v1",
    "name": "stateengine",
    "version": VERSION,
}
NATIVE_PAYLOAD = {
    "schema": "stateengine.native-payload/v1",
    "name": "stateengine",
    "runtime": "rust-embedded",
    "version": VERSION,
}


SECODE_STUB = r"""#!/bin/sh
# Stub secode: emulates the package's native installer at handoff. It
# validates the StateEngine payload manifest with a real JSON parser
# before recording the handoff: the native manifest is the package's when
# present, never a fallback to the legacy file; a malformed or
# wrong-schema manifest is a refusal with a reason, and a refused package
# is never handed off.
if [ "${1:-}" != "update" ]; then
    printf 'stub secode: expected update, got %s\n' "${1:-}" >&2
    exit 64
fi
invocation=$*
pkg=
while [ $# -gt 1 ]; do
    case "$1" in
        --from) pkg=$2; shift 2 ;;
        *) shift ;;
    esac
done
payload=
expected=
if [ -n "$pkg" ] && [ -f "$pkg/stateengine/native-payload.json" ]; then
    payload=$pkg/stateengine/native-payload.json
    expected='stateengine.native-payload/v1'
elif [ -n "$pkg" ] && [ -f "$pkg/stateengine/stateengine-payload.json" ]; then
    payload=$pkg/stateengine/stateengine-payload.json
    expected='stateengine.se-payload.v1'
fi
if [ -n "$payload" ]; then
    python3 - "$payload" "$expected" <<'PY' || exit 2
import json, sys

path, expected = sys.argv[1], sys.argv[2]
try:
    with open(path, "rb") as handle:
        doc = json.load(handle)
except ValueError as exc:
    sys.stderr.write("secode: the StateEngine payload manifest is not valid JSON: %s\n" % exc)
    sys.exit(2)
if not isinstance(doc, dict):
    sys.stderr.write("secode: the StateEngine payload manifest has no object root; do not install it\n")
    sys.exit(2)
if doc.get("schema") != expected:
    sys.stderr.write("secode: the StateEngine payload manifest does not carry schema %s; do not install it\n" % expected)
    sys.exit(2)
PY
fi
printf "%s\n" "$invocation" >> "${SE_TEST_HANDOFF_LOG:?}"
exit "${SE_TEST_EXIT:-0}"
"""


def openssl(*args):
    subprocess.run(["openssl", *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def node_major_version():
    if not shutil.which("node"):
        return 0
    try:
        out = subprocess.run(["node", "--version"], check=True, capture_output=True, text=True).stdout
        return int(re.match(r"v(\d+)", out).group(1))
    except (ValueError, subprocess.CalledProcessError, re.error):
        return 0


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class ReleaseServer:
    """One signed stub package plus a mutable release index on 127.0.0.1."""

    def __init__(self, workdir, key, other_key, pub_b64):
        self.workdir = workdir
        self.key = key
        self.releases = workdir / "releases"
        self.releases.mkdir()
        self.package = workdir / PACKAGE_DIR_NAME
        (self.package / "stateengine").mkdir(parents=True)
        handoff = self.package / "secode"
        handoff.write_text(SECODE_STUB)
        handoff.chmod(0o755)
        self.set_payloads(legacy=LEGACY_PAYLOAD)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), lambda *a, **kw: QuietHandler(*a, directory=str(workdir), **kw))
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def set_payloads(self, legacy=LEGACY_PAYLOAD, native=None):
        """Rebuild the signed package around a chosen payload mix.

        ``legacy`` and ``native`` are the documents written at
        ``stateengine/stateengine-payload.json`` and
        ``stateengine/native-payload.json`` respectively; ``None`` omits a
        file. A mapping is serialized with two-space indent; a ``str`` is
        written as UTF-8 and ``bytes`` verbatim, so a mix may carry a compact,
        malformed or otherwise shaped manifest. The archive, its signature
        and the index are rebuilt from the new bytes so the release stays
        verified.
        """
        for name, document in (("stateengine-payload.json", legacy), ("native-payload.json", native)):
            payload_path = self.package / "stateengine" / name
            if document is None:
                if payload_path.exists():
                    payload_path.unlink()
            elif isinstance(document, bytes):
                payload_path.write_bytes(document)
            elif isinstance(document, str):
                payload_path.write_bytes(document.encode("utf-8"))
            else:
                payload_path.write_text(json.dumps(document, indent=2) + "\n")
        self.archive = self.releases / ARCHIVE_NAME
        with tarfile.open(self.archive, "w:gz") as tar:
            tar.add(self.package, arcname=PACKAGE_DIR_NAME)
        self.archive_sha256 = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.sign(self.key)
        self.write_index()

    def sign(self, key):
        openssl("dgst", "-sha256", "-sign", str(key), "-out", str(self.releases / SIGNATURE_NAME), str(self.archive))

    def write_index(self, trust="signed:rsa-sha256", sha256=None, signature="/releases/" + SIGNATURE_NAME, null_signature=False):
        if sha256 is None:
            sha256 = self.archive_sha256
        sig_field = "null" if null_signature else json.dumps(signature)
        index = (
            "{\n"
            '  "schema": "secode.release-index.v1",\n'
            f'  "version": "{VERSION}",\n'
            f'  "trust": "{trust}",\n'
            '  "packages": {\n'
            f'  "{TARGET}": {{ "url": "/releases/{ARCHIVE_NAME}", "sha256": "{sha256}", "signature": {sig_field} }}\n'
            "  }\n"
            "}\n"
        )
        (self.releases / "index.json").write_text(index)

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def run_script(cmd, base, pub_b64, handoff_log, extra_env=None, path_prefix=None):
    env = dict(os.environ)
    env["SE_RELEASE_BASE"] = base
    env["SE_RELEASE_PUBLIC_KEY_B64"] = pub_b64
    env["SE_TEST_HANDOFF_LOG"] = str(handoff_log)
    if path_prefix:
        env["PATH"] = str(path_prefix) + os.pathsep + env["PATH"]
    if extra_env:
        env.update(extra_env)
    return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=180)


class BootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keydir = TemporaryDirectory()
        cls.workdir = Path(cls.keydir.name)
        cls.key = cls.workdir / "key.pem"
        cls.other_key = cls.workdir / "other-key.pem"
        for key in (cls.key, cls.other_key):
            openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key))
        pub = cls.workdir / "pub.der"
        openssl("pkey", "-in", str(cls.key), "-pubout", "-outform", "DER", "-out", str(pub))
        cls.pub_b64 = base64.b64encode(pub.read_bytes()).decode()

    @classmethod
    def tearDownClass(cls):
        cls.keydir.cleanup()

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.server = ReleaseServer(Path(self.tmp.name), self.key, self.other_key, self.pub_b64)
        self.handoff = Path(self.tmp.name) / "handoff.log"

    def tearDown(self):
        self.server.close()
        self.tmp.cleanup()

    def run_sh(self, base=None, extra_env=None, path_prefix=None):
        return run_script(
            ["sh", str(BOOTSTRAP_SH)],
            base if base is not None else self.server.base,
            self.pub_b64, self.handoff, extra_env, path_prefix,
        )

    def run_npx(self, base=None, extra_env=None):
        return run_script(
            ["node", str(NPX_BIN)],
            base if base is not None else self.server.base,
            self.pub_b64, self.handoff, extra_env,
        )

    def handoff_lines(self):
        if not self.handoff.exists():
            return []
        return [line for line in self.handoff.read_text().splitlines() if line]

    def assert_refused(self, result, fragment):
        self.assertEqual(result.returncode, 1, f"stdout={result.stdout!r} stderr={result.stderr!r}")
        self.assertIn("Install refused", result.stderr)
        self.assertIn(fragment, result.stderr)
        self.assertEqual(self.handoff_lines(), [], "a refused run must not hand off")

    def test_happy_path_hands_off_and_is_safe_to_run_twice(self):
        first = self.run_sh()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("Installed. Open a new terminal and run: se --version", first.stdout)
        lines = self.handoff_lines()
        self.assertEqual(len(lines), 1)
        args, separator, pkg_root = lines[0].partition(" --from ")
        self.assertEqual(args, "update")
        self.assertTrue(separator)
        self.assertTrue(pkg_root.endswith(f"/{PACKAGE_DIR_NAME}"), pkg_root)
        second = self.run_sh()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(len(self.handoff_lines()), 2, "a second run must re-verify and update, not refuse")

    def test_hash_mismatch_refuses_before_handoff(self):
        self.server.write_index(sha256="0" * 64)
        self.assert_refused(self.run_sh(), "does not match its published checksum")

    def test_unsigned_release_refused(self):
        self.server.write_index(trust="unsigned")
        self.assert_refused(self.run_sh(), "only installs signed releases")

    def test_missing_signature_refused(self):
        self.server.write_index(null_signature=True)
        self.assert_refused(self.run_sh(), "names no signature")

    def test_wrong_key_signature_refused(self):
        self.server.sign(self.other_key)
        self.assert_refused(self.run_sh(), "does not verify against the release key")

    def test_no_base_url_refused(self):
        self.assert_refused(self.run_sh(base=""), "no release base URL is set")

    def test_unsupported_platform_refused(self):
        fakebin = Path(self.tmp.name) / "fakebin"
        fakebin.mkdir()
        uname = fakebin / "uname"
        uname.write_text("#!/bin/sh\n"
                         "if [ \"$1\" = \"-s\" ]; then echo Linux; exit 0; fi\n"
                         "if [ \"$1\" = \"-m\" ]; then echo armv7l; exit 0; fi\n"
                         "echo Linux\n")
        uname.chmod(0o755)
        self.assert_refused(self.run_sh(path_prefix=fakebin), "not supported by this one-liner")

    def test_unreachable_base_refused(self):
        self.assert_refused(self.run_sh(base="http://127.0.0.1:1"), "cannot reach")

    def test_sh_handoff_failure_reports_the_true_exit_code(self):
        result = self.run_sh(extra_env={"SE_TEST_EXIT": "37"})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("the installer stopped (exit 37)", result.stderr)
        self.assertEqual(len(self.handoff_lines()), 1, "the failed handoff must still be the reported one")

    def test_sh_refusal_leaves_no_workdir(self):
        scoped = Path(self.tmp.name) / "scoped-tmp"
        scoped.mkdir()
        self.server.sign(self.other_key)
        result = self.run_sh(extra_env={"TMPDIR": str(scoped)})
        self.assert_refused(result, "does not verify against the release key")
        self.assertEqual([path.name for path in scoped.iterdir()], [], "a refused run must not retain its workdir")

    @unittest.skipUnless(node_major_version() >= 18, "the npx route needs Node 18 or newer")
    def test_npx_handoff_failure_reports_the_true_exit_code(self):
        result = self.run_npx(extra_env={"SE_TEST_EXIT": "37"})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("the installer stopped (exit 37)", result.stderr)
        self.assertEqual(len(self.handoff_lines()), 1, "the failed handoff must still be the reported one")

    @unittest.skipUnless(node_major_version() >= 18, "the npx route needs Node 18 or newer")
    def test_npx_refusal_leaves_no_workdir(self):
        scoped = Path(self.tmp.name) / "scoped-tmp"
        scoped.mkdir()
        self.server.sign(self.other_key)
        result = self.run_npx(extra_env={"TMPDIR": str(scoped)})
        self.assert_refused(result, "does not verify against the release key")
        self.assertEqual([path.name for path in scoped.iterdir()], [], "a refused run must not retain its workdir")

    @unittest.skipUnless(node_major_version() >= 18, "the npx route needs Node 18 or newer")
    def test_npx_happy_path_hands_off(self):
        result = self.run_npx()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Installed. Open a new terminal and run: se --version", result.stdout)
        lines = self.handoff_lines()
        self.assertEqual(len(lines), 1)
        args, separator, pkg_root = lines[0].partition(" --from ")
        self.assertEqual(args, "update")
        self.assertTrue(separator)
        self.assertTrue(pkg_root.endswith(f"/{PACKAGE_DIR_NAME}"), pkg_root)

    @unittest.skipUnless(node_major_version() >= 18, "the npx route needs Node 18 or newer")
    def test_npx_wrong_key_refused(self):
        self.server.sign(self.other_key)
        self.assert_refused(self.run_npx(), "does not verify against the release key")


if __name__ == "__main__":
    unittest.main()
