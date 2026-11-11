"""Independent controls for authenticated comments and commit-scoped status storage."""
from copy import deepcopy
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from urllib.parse import unquote

spec = importlib.util.spec_from_file_location("agreement_check", Path(__file__).with_name("check.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def user(number, login):
    return {"id": number, "login": login, "type": "User"}


def digests():
    return {kind: hashlib.sha256((checker.ROOT / f"docs/cla/{kind}.md").read_bytes()).hexdigest()
            for kind in ("individual", "entity")}


class API:
    """GitHub-shaped reads with statuses shared by SHA, as the REST API specifies."""
    repository = "example/project"

    def __init__(self):
        self.trusted = subprocess.check_output(["git", "rev-parse", "HEAD"],
                                               cwd=checker.ROOT, text=True).strip()
        self.first = user(101, "contributor-one")
        self.second = user(102, "contributor-two")
        self.head = "a" * 40
        self.pulls = {n: {"number": n, "state": "open", "head": {"sha": self.head},
                           "base": {"sha": self.trusted, "ref": "main",
                                    "repo": {"full_name": self.repository}},
                           "user": deepcopy(opener), "commits": 1,
                           "author_association": "NONE"}
                      for n, opener in [(1, self.first), (2, self.second)]}
        signature = {"user": self.first,
                     "body": checker.individual_statement(self.first["login"], digests()["individual"])}
        self.comments = {1: [deepcopy(signature)], 2: [deepcopy(signature)]}
        self.authors = {1: self.first, 2: self.first}
        self.latest = {}
        self.permissions = {}
        self.permission_reads = []

    def request(self, path, payload=None):
        if path == "":
            return {"default_branch": "main"}
        if path == "git/ref/heads/main":
            return {"object": {"sha": self.trusted}}
        if path.startswith("pulls/") and path.count("/") == 1:
            return deepcopy(self.pulls[int(path.split("/")[1])])
        if path.startswith("collaborators/") and path.endswith("/permission"):
            login = unquote(path.split("/")[1])
            self.permission_reads.append(login)
            account = next(person for person in [self.first, self.second, *self.authors.values()]
                           if person["login"] == login)
            return {"permission": self.permissions.get(login, "none"), "user": deepcopy(account)}
        raise AssertionError("unmodeled API read: " + path)

    def pages(self, path):
        if path == "pulls":
            return iter(deepcopy(list(self.pulls.values())))
        if path.startswith("pulls/") and path.endswith("/commits"):
            return iter([{"sha": self.head, "author": self.authors[int(path.split("/")[1])]}])
        if path.startswith("issues/") and path.endswith("/comments"):
            return iter(deepcopy(self.comments[int(path.split("/")[1])]))
        raise AssertionError("unmodeled API list: " + path)

    def status(self, head, state, description):
        self.latest[(head, checker.CONTEXT)] = state


class Signatures(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"CLA_INTERNAL_APP_BOT_ID": ""})
        env.start()
        self.addCleanup(env.stop)
        self.person = user(101, "contributor-one")
        self.hashes = digests()
        self.statement = checker.individual_statement(self.person["login"], self.hashes["individual"])

    def test_authenticated_matching_individual(self):
        self.assertTrue(checker.signed({"user": self.person, "body": self.statement},
                                       self.person, self.hashes))

    def test_other_account_cannot_sign_for_opener(self):
        self.assertFalse(checker.signed({"user": user(102, self.person["login"]),
                                        "body": self.statement}, self.person, self.hashes))

    def test_old_agreement_digest_is_refused(self):
        statement = checker.individual_statement(self.person["login"], "0" * 64)
        self.assertFalse(checker.signed({"user": self.person, "body": statement},
                                        self.person, self.hashes))

    def test_quoted_statement_is_refused(self):
        self.assertFalse(checker.signed({"user": self.person, "body": "> " + self.statement},
                                        self.person, self.hashes))

    def test_matching_entity_statement(self):
        body = checker.entity_statement(self.person["login"], self.hashes["entity"], "Example Entity")
        self.assertTrue(checker.signed({"user": self.person, "body": body}, self.person, self.hashes))

    def test_placeholder_entity_is_refused(self):
        body = checker.entity_statement(self.person["login"], self.hashes["entity"], "YOUR LEGAL ENTITY NAME")
        self.assertFalse(checker.signed({"user": self.person, "body": body}, self.person, self.hashes))

    def test_comment_code_stays_unsigned_data(self):
        self.assertFalse(checker.signed({"user": self.person,
                                        "body": self.statement + "\n$(exit 0)"},
                                        self.person, self.hashes))

    def test_single_signed_pull_can_pass(self):
        api = API()
        del api.pulls[2]
        self.assertTrue(checker.check_pull(api, 1))
        self.assertEqual(api.latest[(api.head, checker.CONTEXT)], "success")

    def test_unsigned_pull_cannot_borrow_another_pulls_status(self):
        api = API()
        self.assertFalse(checker.check_pull(api, 2))
        self.assertEqual(api.latest[(api.head, checker.CONTEXT)], "failure")
        # Any commenter can trigger a fresh issue_comment check on signed PR 1.
        checker.check_pull(api, 1)
        self.assertNotEqual(api.latest[(api.head, checker.CONTEXT)], "success",
                            "the shared head gives unsigned PR 2 the success from signed PR 1")


    def single(self):
        api = API()
        del api.pulls[2]
        api.comments[1] = []
        return api

    def test_configured_app_opener_and_internal_commit_author(self):
        api = self.single()
        bot = {"id": 301, "login": "internal-app[bot]", "type": "Bot"}
        api.pulls[1]["user"] = bot
        api.permissions[api.first["login"]] = "admin"
        with patch.dict(os.environ, {"CLA_INTERNAL_APP_BOT_ID": "301"}):
            self.assertTrue(checker.check_pull(api, 1))
        self.assertEqual(api.permission_reads, [api.first["login"]])
        self.assertEqual(api.latest[(api.head, checker.CONTEXT)], "success")

    def test_internal_opener_does_not_exempt_unsigned_outside_author(self):
        api = self.single()
        api.pulls[1]["author_association"] = "OWNER"
        api.authors[1] = api.second
        self.assertFalse(checker.check_pull(api, 1))
        self.assertEqual(api.permission_reads, [api.second["login"]])
        self.assertEqual(api.latest[(api.head, checker.CONTEXT)], "failure")
        api.comments[1] = [{"user": api.second, "body": checker.individual_statement(
            api.second["login"], digests()["individual"])}]
        self.assertTrue(checker.check_pull(api, 1))

    def test_internal_commit_author_does_not_exempt_unsigned_opener(self):
        api = self.single()
        api.authors[1] = api.second
        api.permissions[api.second["login"]] = "write"
        self.assertFalse(checker.check_pull(api, 1))

    def test_collaborator_opener_is_exempt(self):
        api = self.single()
        api.pulls[1]["author_association"] = "COLLABORATOR"
        self.assertTrue(checker.check_pull(api, 1))

    def test_current_role_is_reread_after_revocation(self):
        api = self.single()
        api.permissions[api.first["login"]] = "write"
        self.assertTrue(checker.check_pull(api, 1))
        api.permissions[api.first["login"]] = "none"
        self.assertFalse(checker.check_pull(api, 1))
        self.assertEqual(api.permission_reads, [api.first["login"]] * 2)

    def test_another_bot_cannot_borrow_configured_app_exemption(self):
        api = self.single()
        api.authors[1] = {"id": 302, "login": "other-app[bot]", "type": "Bot"}
        with patch.dict(os.environ, {"CLA_INTERNAL_APP_BOT_ID": "301"}):
            with self.assertRaisesRegex(ValueError, "nonhuman author"):
                checker.check_pull(api, 1)
        self.assertEqual(api.latest[(api.head, checker.CONTEXT)], "pending")

    def test_permission_response_cannot_change_author_identity(self):
        api = self.single()
        original = api.request
        def wrong(path, payload=None):
            if path.endswith("/permission"):
                return {"permission": "admin", "user": api.second}
            return original(path, payload)
        api.request = wrong
        with self.assertRaisesRegex(ValueError, "different author identity"):
            checker.check_pull(api, 1)
        self.assertEqual(api.latest[(api.head, checker.CONTEXT)], "pending")

    def test_permission_failure_never_supplies_success(self):
        api = self.single()
        original = api.request
        def failed(path, payload=None):
            if path.endswith("/permission"):
                raise OSError("permission API unavailable")
            return original(path, payload)
        api.request = failed
        with self.assertRaises(OSError):
            checker.check_pull(api, 1)
        self.assertEqual(api.latest[(api.head, checker.CONTEXT)], "pending")


if __name__ == "__main__":
    unittest.main()
