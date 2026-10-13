"""Local verification of managed policy insertion and polling recovery."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sentinel_policy_sync as sync


class ManagedPolicyTests(unittest.TestCase):
    def test_append_replace_preserves_other_content(self):
        original = "# Agent instructions\r\nKeep these.\r\n"
        first = sync.managed_policy_section("First policy\n")
        installed = sync.replace_policy_section(original, first)
        self.assertTrue(installed.startswith(original))
        self.assertEqual(sync.replace_policy_section(installed, first), installed)
        suffix = "\n# Other additions\nKeep these too.\n"
        second = sync.managed_policy_section("Updated policy\n")
        updated = sync.replace_policy_section(installed + suffix, second)
        self.assertEqual(updated, original + "\n" + second + "\n" + suffix)

    def test_malformed_markers_fail(self):
        for content in [sync.POLICY_SECTION_START, sync.POLICY_SECTION_END,
                        sync.POLICY_SECTION_END + sync.POLICY_SECTION_START,
                        sync.managed_policy_section("a") * 2]:
            with self.subTest(content=content), self.assertRaises(sync.PolicySyncError):
                sync.replace_policy_section(content, sync.managed_policy_section("new"))
        with self.assertRaises(sync.PolicySyncError):
            sync.managed_policy_section(sync.POLICY_SECTION_END)

    def test_main_recovers_removed_section_and_preserves_permissions(self):
        payload = {"schemaVersion": "1.0", "agentKey": "test-agent", "policies": []}
        payload["policySetSha256"] = sync.policy_set_hash(payload)
        with tempfile.TemporaryDirectory() as directory:
            agents = Path(directory) / "AGENTS.md"
            state = Path(directory) / "state.json"
            agents.write_text("Existing instructions\n", encoding="utf-8")
            agents.chmod(0o640)
            env = {"SWYFT_GOVERNANCE_URL": "https://example.test", "SWYFT_AGENT_CREDENTIAL_ID": "id",
                   "SWYFT_AGENT_CREDENTIAL_SECRET": "secret", "AGENTS_MD_PATH": str(agents),
                   "POLICY_SYNC_STATE_PATH": str(state), "SWYFT_ALLOW_EMPTY_POLICY_SET": "true"}
            with patch.dict(os.environ, env), patch.object(sync, "fetch_policy_set", return_value=(200, payload, None)) as fetch:
                self.assertEqual(sync.main(report_change=True), 10)
                self.assertIsNone(fetch.call_args.args[-1])
                self.assertEqual(agents.stat().st_mode & 0o777, 0o640)
                self.assertEqual(sync.main(report_change=True), 0)
                with patch.object(sync, "fetch_policy_set", return_value=(304, None, None)) as unchanged:
                    before = agents.read_bytes()
                    self.assertEqual(sync.main(report_change=True), 0)
                    self.assertIsNotNone(unchanged.call_args.args[-1])
                    self.assertEqual(agents.read_bytes(), before)
                agents.write_text("Other writer replaced the file\n", encoding="utf-8")
                self.assertEqual(sync.main(report_change=True), 0)
                self.assertIsNone(fetch.call_args.args[-1])
                self.assertTrue(agents.read_text().startswith("Other writer replaced the file\n"))


if __name__ == "__main__":
    unittest.main()
