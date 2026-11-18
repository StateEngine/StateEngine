"""Independent event-result controls at the authenticated repository API boundary."""
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_check import API, checker, digests


class OpenPulls(API):
    def __init__(self):
        super().__init__()
        self.statuses = []
        self.pulls[2]["head"]["sha"] = "b" * 40
        self.authors[2] = self.second
        self.comments[2] = []

    def pages(self, path):
        if path == "pulls":
            return iter(deepcopy([p for p in self.pulls.values() if p["state"] == "open"]))
        return super().pages(path)

    def status(self, head, state, description):
        self.statuses.append((head, state))
        super().status(head, state, description)


class RunScope(unittest.TestCase):
    def run_event(self, api, name, event):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "event.json"
            path.write_text(json.dumps(event))
            with patch.dict(os.environ, {"GITHUB_EVENT_NAME": name,
                                         "GITHUB_EVENT_PATH": str(path),
                                         "CLA_INTERNAL_APP_BOT_ID": ""}), \
                    patch.object(checker, "GitHub", return_value=api), \
                    redirect_stdout(io.StringIO()):
                try:
                    checker.run()
                except SystemExit as error:
                    return error.code
        return 0

    def pull_event(self, api, number=1):
        return self.run_event(api, "pull_request_target", {
            "action": "synchronize", "pull_request": deepcopy(api.pulls[number])})

    def state(self, api, number):
        return api.latest[(api.pulls[number]["head"]["sha"], checker.CONTEXT)]

    def test_eligible_own_request_does_not_inherit_unrelated_unsigned_failure(self):
        api = OpenPulls()
        self.assertEqual(self.pull_event(api), 0)
        self.assertEqual(self.state(api, 1), "success")
        self.assertEqual(self.state(api, 2), "failure")
        for pull in api.pulls.values():
            self.assertIn((pull["head"]["sha"], "pending"), api.statuses)

    def test_unrelated_malformed_author_gets_its_own_terminal_failure(self):
        api = OpenPulls()
        api.authors[2] = None
        self.assertEqual(self.pull_event(api), 0)
        self.assertEqual(self.state(api, 1), "success")
        self.assertEqual(self.state(api, 2), "failure")

    def test_unsigned_own_request_refuses_even_beside_an_eligible_request(self):
        api = OpenPulls()
        self.assertEqual(self.pull_event(api, 2), 1)
        self.assertEqual(self.state(api, 1), "success")
        self.assertEqual(self.state(api, 2), "failure")

    def test_shared_head_unsigned_peer_still_refuses_eligible_own_request(self):
        api = OpenPulls()
        api.pulls[2]["head"]["sha"] = api.head
        self.assertEqual(self.pull_event(api), 1)
        self.assertEqual(self.state(api, 1), "failure")

    def test_closed_subject_still_refreshes_other_open_heads_without_borrowing_failure(self):
        api = OpenPulls()
        api.pulls[1]["state"] = "closed"
        event = {"action": "closed", "pull_request": deepcopy(api.pulls[1])}
        self.assertEqual(self.run_event(api, "pull_request_target", event), 0)
        self.assertNotIn((api.head, checker.CONTEXT), api.latest)
        self.assertEqual(self.state(api, 2), "failure")

    def test_pull_comment_uses_that_requests_current_head(self):
        api = OpenPulls()
        event = {"action": "created", "issue": {"number": 1,
                 "pull_request": {"url": "https://api.example.invalid/pulls/1"}}}
        self.assertEqual(self.run_event(api, "issue_comment", event), 0)
        self.assertEqual(self.state(api, 1), "success")
        self.assertEqual(self.state(api, 2), "failure")
        event["issue"]["number"] = 2
        self.assertEqual(self.run_event(api, "issue_comment", event), 1)

    def test_non_pull_issue_comment_performs_no_repository_reads_or_status_writes(self):
        class NoAPI:
            def __getattribute__(self, name):
                raise AssertionError("ordinary issue comment reached repository API")
        self.assertEqual(self.run_event(NoAPI(), "issue_comment", {
            "action": "created", "issue": {"number": 1}}), 0)

    def test_main_push_keeps_aggregate_refusal_and_success(self):
        api = OpenPulls()
        self.assertEqual(self.run_event(api, "push", {"ref": "refs/heads/main"}), 1)
        self.assertEqual(self.state(api, 1), "success")
        self.assertEqual(self.state(api, 2), "failure")
        api.comments[2] = [{"user": api.second, "body": checker.individual_statement(
            api.second["login"], digests()["individual"])}]
        self.assertEqual(self.run_event(api, "push", {"ref": "refs/heads/main"}), 0)
        self.assertEqual(self.state(api, 2), "success")


if __name__ == "__main__":
    unittest.main()
