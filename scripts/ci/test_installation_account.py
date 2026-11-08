import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import installation_account as account


@unittest.skipIf(os.name == "nt", "Unix ownership controls; native Windows is exercised by its runner")
class AccountRefusal(unittest.TestCase):
    def test_environment_home_cannot_change_native_account(self):
        expected = account.account()
        with patch.dict(os.environ, HOME="/unrelated-fixture", USERPROFILE="/other-fixture"):
            self.assertEqual(account.account(), expected)

    def test_missing_registration_refuses_with_legal_venue(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(account, "registration", return_value=Path(root) / "missing.json"):
                with self.assertRaisesRegex(RuntimeError, "REFUSED.*dedicated OS test account"):
                    account.require()

    def test_user_controlled_registration_cannot_opt_in(self):
        identity, profile = account.account()
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root) / "registration.json"
            marker.write_text(json.dumps({"schema": "stateengine-test-account/v1",
                                          "identity": identity, "profile": str(profile)}))
            marker.parent.chmod(0o777)
            with patch.object(account, "registration", return_value=marker):
                with self.assertRaisesRegex(RuntimeError, "administrator-owned"):
                    account.require()


if __name__ == "__main__":
    unittest.main()
