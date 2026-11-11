"""Delivery-order controls for the workflow's real concurrency expressions.

Models cancellation before draft jobs are skipped, so a late draft snapshot is
allowed to overlap an already-running ready workflow. It does not start hosted jobs.
"""
import ast
from dataclasses import dataclass
import os
from pathlib import Path
import re
import unittest


WORKFLOW = Path(os.environ.get(
    "CI_WORKFLOW_UNDER_TEST",
    Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"))


def expression(text, context):
    """Evaluate the workflow's scalar context/boolean subset; refuse new syntax."""
    tokens = re.compile(r"\s*('[^']*'|[A-Za-z_][A-Za-z_0-9.]*|&&|\|\||==|!=|[!()])")
    position, parts = 0, []
    while position < len(text.rstrip()):
        match = tokens.match(text, position)
        if not match:
            raise ValueError("unsupported concurrency expression syntax")
        token = match[1]
        position = match.end()
        if token.startswith("'"):
            parts.append(token)
        elif re.fullmatch(r"[A-Za-z_][A-Za-z_0-9.]*", token):
            if not token.startswith(("github.", "inputs.")):
                raise ValueError("unsupported concurrency expression context")
            parts.append(repr(context.get(token, "")))
        else:
            parts.append({"&&": " and ", "||": " or ", "!": " not "}.get(token, token))
    tree = ast.parse("".join(parts).strip(), mode="eval")
    allowed = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare,
               ast.Eq, ast.NotEq, ast.UnaryOp, ast.Not, ast.Constant)
    if any(not isinstance(node, allowed) for node in ast.walk(tree)):
        raise ValueError("unsupported concurrency expression operation")
    return eval(compile(tree, "<workflow-expression>", "eval"), {"__builtins__": {}}, {})


def scalar(value):
    # Actions interpolates boolean false as "false", not the empty missing value.
    return str(value).lower() if isinstance(value, bool) else str(value)


@dataclass(frozen=True)
class Event:
    name: str
    head: str
    draft: bool
    action: str = "synchronize"
    repo: str = "contributor/repo"
    branch: str = "topic"

    def context(self):
        return {"github.event_name": "pull_request", "github.repository": "owner/repo",
                "github.event.pull_request.head.repo.full_name": self.repo,
                "github.head_ref": self.branch, "github.ref_name": "7/merge",
                "github.event.pull_request.draft": self.draft,
                "github.event.action": self.action,
                "github.event.pull_request.head.sha": self.head}


class Workflow:
    def __init__(self, path):
        text = path.read_text()
        block = re.search(r"^concurrency:\n((?:[ \t].*\n|\n)+)", text, re.M)
        if not block:
            raise ValueError("workflow concurrency block absent")
        self.group = re.search(r"^  group: (.+)$", block[1], re.M)[1]
        self.cancel = re.search(r"^  cancel-in-progress: \$\{\{(.*?)\}\}$", block[1], re.M)[1]
        self.changes = re.search(r"^  changes:\n    if: \$\{\{(.*?)\}\}$", text, re.M)[1]
        self.triggers = text.split("  pull_request:\n", 1)[1].split("\n  push:", 1)[0]

    def key(self, context):
        return re.sub(r"\$\{\{(.*?)\}\}",
                      lambda match: scalar(expression(match[1], context)), self.group).lower()

    def real_run(self, event):
        return bool(expression(self.changes, event.context()))

    def deliver(self, events):
        running, cancelled = {}, []
        for event in events:
            context = event.context()
            key = self.key(context)
            if key in running:
                if not expression(self.cancel, context):
                    raise ValueError("control expects cancellation within PR groups")
                cancelled.append(running[key])
            running[key] = event
        return [event for event in running.values() if self.real_run(event)], cancelled


class DeliveryOrder(unittest.TestCase):
    def setUp(self):
        self.workflow = Workflow(WORKFLOW)

    def test_push_then_ready_preserves_one_real_final_head(self):
        draft = Event("draft-push", "head-b", True)
        ready = Event("ready", "head-b", False, "ready_for_review")
        real, cancelled = self.workflow.deliver([draft, ready])
        self.assertEqual(real, [ready])
        self.assertNotIn(ready, cancelled)

    def test_ready_then_delayed_draft_push_preserves_one_real_final_head(self):
        draft = Event("delayed-draft-push", "head-b", True)
        ready = Event("ready", "head-b", False, "ready_for_review")
        real, cancelled = self.workflow.deliver([ready, draft])
        self.assertEqual(real, [ready], "late draft snapshot cancelled the final ready head")
        self.assertNotIn(ready, cancelled)

    def test_ready_push_and_ready_event_converge_in_both_delivery_orders(self):
        push = Event("ready-push", "head-b", False)
        ready = Event("ready", "head-b", False, "ready_for_review")
        for order in ([push, ready], [ready, push]):
            with self.subTest(order=[event.name for event in order]):
                real, cancelled = self.workflow.deliver(order)
                self.assertEqual(real, [order[-1]])
                self.assertEqual(cancelled, [order[0]])

    def test_draft_to_draft_pushes_skip_real_work_and_cancel_older_draft(self):
        old, new = Event("old-draft", "head-a", True), Event("new-draft", "head-b", True)
        real, cancelled = self.workflow.deliver([old, new])
        self.assertEqual(real, [])
        self.assertEqual(cancelled, [old])

    def test_later_ready_push_cancels_older_ready_head(self):
        old, new = Event("old-ready", "head-a", False), Event("new-ready", "head-b", False)
        real, cancelled = self.workflow.deliver([old, new])
        self.assertEqual(real, [new], "ready pushes must not be isolated by SHA or run id")
        self.assertEqual(cancelled, [old])

    def test_other_forks_branches_and_non_pr_events_remain_separate(self):
        event = Event("ready", "head-b", False)
        contexts = [event.context(),
                    Event("fork", "head-b", False, repo="other/repo").context(),
                    Event("branch", "head-b", False, branch="other").context()]
        contexts += [{"github.event_name": name, "github.repository": "owner/repo",
                      "github.ref_name": "main"}
                     for name in ["push", "schedule", "workflow_dispatch"]]
        self.assertEqual(len({self.workflow.key(context) for context in contexts}), len(contexts))
        for context in contexts[3:]:
            self.assertFalse(expression(self.workflow.cancel, context))

    def test_ready_and_synchronize_triggers_are_present(self):
        self.assertIn("ready_for_review", self.workflow.triggers)
        self.assertIn("synchronize", self.workflow.triggers)


if __name__ == "__main__":
    unittest.main()
