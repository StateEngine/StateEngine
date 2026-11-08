"""Review portable administrator configuration through real files and flock readers."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import dispatch


class PortableConfigReview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin = [] if os.geteuid() == 0 else ["sudo", "-n"]
        try:
            probe = subprocess.run([*cls.admin, "/usr/bin/true"], capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            raise unittest.SkipTest("real root-owned fixtures need local administrator access") from None
        if probe.returncode:
            raise unittest.SkipTest("real root-owned fixtures need local administrator access")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="se-portable-config-review-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.serial = 0
        required = {".github/workflows/ci.yml", ".github/actions/rust/action.yml",
                    ".github/actions/test/action.yml", ".config/nextest.toml",
                    "scripts/ci/custom.py", "scripts/ci/installation_account.py",
                    "Cargo.lock", "Cargo.toml"}
        report = dict(image="sha256:" + "1" * 64, seccomp_sha256="2" * 64,
                      policy={key: "3" * 64 for key in required})
        self.image = self.root_file("image.json", json.dumps(report).encode())
        self.cache_bytes = b"approved opaque dependency snapshot"
        self.cache = self.root_file("dependencies.tar.gz", self.cache_bytes)
        self.locks = [self.root / "guest-one/run.lock", self.root / "guest-two/run.lock"]
        self.ci = self.root / "ci/run.lock"
        self.publisher = self.root / "publisher/state.json"
        for path in [*self.locks, self.ci]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("existing lock")
        self.publisher.parent.mkdir()
        self.idle = dict(schema="guest-owner/v1", phase="idle",
                         boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                         guest=None, owner=None, launcher=None, qemu=None, swtpm=None)
        self.publisher.write_text(json.dumps(self.idle))
        self.config = dict(repository_id=11, workflow_id=12, app_id=13, installation_id=14,
                           image_report=str(self.image), cache=str(self.cache),
                           cache_sha256=hashlib.sha256(self.cache_bytes).hexdigest(),
                           state=str(self.root / "private"), vm_locks=list(map(str, self.locks)),
                           ci_lock=str(self.ci), guest_state=str(self.publisher))

    def root_file(self, name, data, mode="0644"):
        self.serial += 1
        source = self.root / ("input-" + str(self.serial))
        source.write_bytes(data)
        target = self.root / (str(self.serial) + "-" + name)
        subprocess.run([*self.admin, "/usr/bin/install", "-o", "root", "-g", "root",
                        "-m", mode, str(source), str(target)],
                       check=True, capture_output=True, timeout=5)
        self.assertEqual(target.lstat().st_uid, 0)
        return target

    def read_config(self, config=None):
        value = self.config if config is None else config
        path = self.root_file("dispatch.json", json.dumps(value).encode())
        return dispatch.config_at(path)

    def lock_states(self):
        program = """import fcntl,json,sys
states=[]
for path in sys.argv[1:]:
 with open(path,'r') as file:
  try: fcntl.flock(file,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError: states.append('held')
  else: states.append('free')
print(json.dumps(states))
"""
        result = subprocess.run([sys.executable, "-I", "-c", program,
                                 *map(str, [*self.locks, self.ci])],
                                check=True, capture_output=True, text=True, timeout=5)
        return json.loads(result.stdout)

    def test_administrator_selected_portable_paths_reach_the_real_reader(self):
        try:
            selected, report = self.read_config()
        except RuntimeError as error:
            self.fail("administrator-selected portable paths were refused: " + str(error))
        self.assertEqual(selected, self.config)
        self.assertEqual(report["policy_digest"], hashlib.sha256(
            json.dumps(report["policy"], sort_keys=True).encode()).hexdigest())

    def test_environment_selector_does_not_override_root_configuration(self):
        with patch.dict(os.environ, {"STATEENGINE_GUEST_OWNER_SOURCE": str(self.root / "other.py"),
                                    "STATEENGINE_VM_GENERATION": "unrelated"}):
            selected, _ = self.read_config()
        self.assertEqual(selected["guest_state"], str(self.publisher))
        self.assertEqual(selected["vm_locks"], list(map(str, self.locks)))

    def test_lock_count_type_duplicate_and_relative_paths_refuse(self):
        invalid = [[], [str(self.locks[0])], [*map(str, self.locks), str(self.ci)],
                   [str(self.locks[0])] * 2, ["relative/run.lock", str(self.locks[1])],
                   [str(self.locks[0]), None], [str(self.locks[0]), 1], "two-locks", None]
        for locks in invalid:
            with self.subTest(locks=locks):
                config = dict(self.config, vm_locks=locks)
                with self.assertRaisesRegex(RuntimeError, "configuration differs"):
                    self.read_config(config)

    def test_relative_or_non_path_publisher_refuses(self):
        for publisher in ["relative/state.json", "", None, False, 1, []]:
            with self.subTest(publisher=publisher):
                with self.assertRaisesRegex(RuntimeError, "configuration differs"):
                    self.read_config(dict(self.config, guest_state=publisher))

    def test_non_root_owned_configuration_cannot_select_a_venue(self):
        path = self.root / "untrusted.json"
        path.write_text(json.dumps(self.config))
        path.chmod(0o644)
        if os.geteuid() == 0:
            os.chown(path, 65534, 65534)
        self.assertNotEqual(path.lstat().st_uid, 0)
        with self.assertRaisesRegex(RuntimeError, "root-owned controller configuration"):
            dispatch.config_at(path)

    def test_writable_or_linked_configuration_refuses(self):
        for mode in ["0664", "0646"]:
            with self.subTest(mode=mode):
                path = self.root_file("writable.json", json.dumps(self.config).encode(), mode)
                with self.assertRaisesRegex(RuntimeError, "root-owned controller configuration"):
                    dispatch.config_at(path)
        original = self.root_file("original.json", json.dumps(self.config).encode())
        linked = self.root / "linked.json"
        linked.symlink_to(original)
        with self.assertRaisesRegex(RuntimeError, "root-owned controller configuration"):
            dispatch.config_at(linked)

    def test_image_and_cache_authority_remain_independent(self):
        image = self.root / "untrusted-image.json"
        image.write_bytes(self.image.read_bytes())
        cache = self.root / "untrusted-cache"
        cache.write_bytes(self.cache_bytes)
        image.chmod(0o644)
        cache.chmod(0o644)
        if os.geteuid() == 0:
            os.chown(image, 65534, 65534)
            os.chown(cache, 65534, 65534)
        with self.assertRaisesRegex(RuntimeError, "root-owned controller configuration"):
            self.read_config(dict(self.config, image_report=str(image)))
        with self.assertRaisesRegex(RuntimeError, "root-owned dependency snapshot"):
            self.read_config(dict(self.config, cache=str(cache)))
        with self.assertRaisesRegex(RuntimeError, "snapshot identity differs"):
            self.read_config(dict(self.config, cache_sha256="f" * 64))

    def test_portable_venue_holds_both_selected_guest_locks_and_ci_lock(self):
        selected, _ = self.read_config()
        self.assertEqual(self.lock_states(), ["free"] * 3)
        with dispatch.venue(selected, recover=True):
            self.assertEqual(self.lock_states(), ["held"] * 3)
        self.assertEqual(self.lock_states(), ["free"] * 3)

    def test_missing_selected_lock_is_not_created(self):
        selected, _ = self.read_config()
        self.locks[1].unlink()
        with self.assertRaises(FileNotFoundError):
            with dispatch.venue(selected, recover=True):
                self.fail("missing guest lock admitted a venue")
        self.assertFalse(self.locks[1].exists())

    def test_busy_selected_guest_and_nonidle_publisher_refuse(self):
        import fcntl
        selected, _ = self.read_config()
        with self.locks[1].open("r") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                with dispatch.venue(selected, recover=True):
                    self.fail("busy guest lock admitted a venue")
        self.publisher.write_text(json.dumps(dict(self.idle, phase="admitted")))
        with self.assertRaisesRegex(RuntimeError, "not independently idle"):
            with dispatch.venue(selected, recover=True):
                self.fail("nonidle guest publisher admitted a venue")
        self.assertEqual(self.lock_states(), ["free"] * 3)


class OptionalGuestSourceReview(unittest.TestCase):
    def module(self):
        return runpy.run_path(str(Path(__file__).with_name("test_guest_fence.py")))

    def test_unset_source_has_no_machine_default_and_skips_integration(self):
        with patch.dict(os.environ, {}, clear=True):
            module = self.module()
        self.assertEqual(module["SOURCE"], Path(""))
        self.assertTrue(module["GuestFence"].__unittest_skip__)

    def test_explicit_source_is_selected_and_missing_source_remains_skipped(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "publisher.py"
            source.write_text("# optional source selection fixture\n")
            with patch.dict(os.environ, {"STATEENGINE_GUEST_OWNER_SOURCE": str(source)}):
                module = self.module()
            self.assertEqual(module["SOURCE"], source)
            self.assertFalse(getattr(module["GuestFence"], "__unittest_skip__", False))
            source.unlink()
            with patch.dict(os.environ, {"STATEENGINE_GUEST_OWNER_SOURCE": str(source)}):
                module = self.module()
            self.assertTrue(module["GuestFence"].__unittest_skip__)
