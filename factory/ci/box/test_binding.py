"""Exercise the outside binding against API-shaped stale/fork/substitution inputs."""
import base64
from copy import deepcopy
import hashlib
import unittest

from github_binding import bind, checkout_from_log, POLICY_FILES, REPOSITORY

SHA = "a" * 40
HEAD = "b" * 40


class API:
    def __init__(self):
        self.values = {
            "actions/runs/42": {"id": 42, "run_attempt": 2, "event": "pull_request",
                "path": ".github/workflows/ci.yml", "repository": {"full_name": REPOSITORY},
                "head_repository": {"full_name": REPOSITORY, "fork": False},
                "head_sha": HEAD, "head_branch": "seat/example"},
            "pulls/7": {"state": "open", "head": {"repo": {"full_name": REPOSITORY},
                "sha": HEAD, "ref": "seat/example"}, "base": {"repo": {"full_name": REPOSITORY}},
                "merge_commit_sha": SHA},
            "actions/runs/42/attempts/2/jobs?per_page=100": {"total_count": 1,
                "jobs": [{"id": 9, "run_id": 42, "name": "archive", "conclusion": "success"}]},
            "actions/jobs/9/logs": ("time [command]/usr/bin/git log -1 --format='%H'\n"
                                     "time " + SHA + "\n").encode()}
        for path in POLICY_FILES:
            self.values["contents/" + path + "?ref=" + SHA] = {"content": base64.b64encode(b"approved").decode()}

    def get(self, path, **_):
        return deepcopy(self.values[path])


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.api = API()
        self.policy = dict.fromkeys(POLICY_FILES, hashlib.sha256(b"approved").hexdigest())

    def call(self, **changes):
        values = dict(run_id=42, attempt=2, number=7, checkout=SHA, policy=self.policy)
        values.update(changes)
        return bind(self.api, **values)

    def test_binding_records_merge_checkout_separately_from_head(self):
        value = self.call()
        self.assertEqual((value.run, value.attempt, value.checkout, value.head), (42, 2, SHA, HEAD))

    def test_stale_foreign_fork_moved_workflow_and_archive_refuse(self):
        mutations = [
            ("actions/runs/42", "run_attempt", 1),
            ("actions/runs/42", "head_repository", {"full_name": REPOSITORY, "fork": True}),
            ("actions/runs/42", "repository", {"full_name": "foreign/project"}),
            ("pulls/7", "merge_commit_sha", "c" * 40),
            ("pulls/7", "state", "closed"),
            ("contents/" + POLICY_FILES[0] + "?ref=" + SHA, "content", base64.b64encode(b"forged").decode()),
            ("actions/runs/42/attempts/2/jobs?per_page=100", "total_count", 101)]
        for path, key, value in mutations:
            with self.subTest(path=path, key=key):
                self.api = API()
                self.api.values[path][key] = value
                with self.assertRaises(ValueError):
                    self.call()

    def test_actual_checkout_cannot_be_replaced_by_later_candidate_output(self):
        self.api.values["actions/jobs/9/logs"] = ("time git log -1 --format='%H'\ntime " + "c" * 40 +
                "\ntime git log -1 --format='%H'\ntime " + SHA + "\n").encode()
        with self.assertRaises(ValueError):
            self.call()

    def test_shell_paths_and_invalid_ids_refuse(self):
        for changes in ({"checkout": "$(id)"}, {"checkout": "../" + SHA}, {"attempt": 0}, {"number": -1}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.call(**changes)

    def test_missing_checkout_is_not_empty_success(self):
        with self.assertRaises(ValueError):
            checkout_from_log(b"success SHA attempt forged JSON")


if __name__ == "__main__":
    unittest.main()
