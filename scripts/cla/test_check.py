"""Independent controls for authenticated comments and commit-scoped status storage."""
from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import unittest

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

    def request(self, path, payload=None):
        if path == "":
            return {"default_branch": "main"}
        if path == "git/ref/heads/main":
            return {"object": {"sha": self.trusted}}
        if path.startswith("pulls/") and path.count("/") == 1:
            return deepcopy(self.pulls[int(path.split("/")[1])])
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


if __name__ == "__main__":
    unittest.main()
