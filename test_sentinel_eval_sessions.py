"""Offline session lifecycle regressions for both evaluation suites."""
import argparse
import contextlib
import io
import json
import os
import subprocess
import unittest
from unittest.mock import patch

import sentinel_agent_correctness_eval as correctness
import sentinel_eval_session as sessions
import sentinel_policy_eval as policy


class EvaluationSessionTests(unittest.TestCase):
    def run_suite(self, runner, failure=None, dry_run=False):
        item = {"id": "case", "input": {"question": "Who?", "operation": {"action": "read"}},
                "expectedOutput": {"answer": "Alice", "decision": "allow"},
                "metadata": {"matchMode": "equals"}}
        commands = []

        def execute(argv, **kwargs):
            commands.append(argv)
            if argv[1] == "agent":
                if failure == "timeout":
                    raise subprocess.TimeoutExpired(argv, 120)
                if failure == "interrupt":
                    raise KeyboardInterrupt
                if failure == "exit":
                    return subprocess.CompletedProcess(argv, 1, "", "failed")
                if failure == "json":
                    return subprocess.CompletedProcess(argv, 0, "invalid", "")
                reply = {"decision": "allow", "reason": "Allowed", "matchedRuleId": None} if runner is policy else {"result": {"payloads": [{"text": "Alice"}]}}
                return subprocess.CompletedProcess(argv, 0, json.dumps(reply), "")
            self.assertEqual(argv[1:4], ["gateway", "call", "sessions.delete"])
            if failure == "cleanup":
                return subprocess.CompletedProcess(argv, 1, "", "failed")
            return subprocess.CompletedProcess(argv, 0, '{"ok":true,"deleted":true}', "")

        with contextlib.ExitStack() as stack:
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            stack.enter_context(patch.object(sessions.subprocess, "run", side_effect=execute))
            stack.enter_context(patch.dict(os.environ, {"LANGFUSE_PUBLIC_KEY": "public", "LANGFUSE_SECRET_KEY": "secret", "SWYFT_POLICY_SET_SHA256": "sha256:fixture"}))
            args = argparse.Namespace(agent_id="ops", dry_run=dry_run, dataset_name=policy.DATASET_NAME, max_concurrency=1)
            if runner is policy:
                stack.enter_context(patch.object(policy, "parse_args", return_value=args))
                stack.enter_context(patch.object(policy, "fetch_dataset", return_value={"id": "dataset"}))
                stack.enter_context(patch.object(policy, "fetch_active_dataset_items", return_value=[item, item]))
                stack.enter_context(patch.object(policy, "emit_experiment_trace"))
                emit = stack.enter_context(patch.object(policy, "emit_boolean_score"))
            else:
                stack.enter_context(patch.object(argparse.ArgumentParser, "parse_args", return_value=args))
                stack.enter_context(patch.object(correctness, "fetch", return_value=({"id": "dataset"}, [item, item])))
                emit = stack.enter_context(patch.object(correctness, "emit"))
            if failure == "interrupt":
                with self.assertRaises(KeyboardInterrupt):
                    runner.main()
                return commands, []
            code = runner.main()
            self.assertEqual(code, 1 if failure == "cleanup" else 0)
            return commands, emit.call_args_list

    def test_each_case_has_unique_session_and_matching_cleanup(self):
        for runner in (policy, correctness):
            with self.subTest(runner=runner.__name__):
                commands, emitted = self.run_suite(runner)
                self.assertEqual(len(commands), 4)
                keys = []
                for turn, cleanup in zip(commands[::2], commands[1::2]):
                    key = turn[turn.index("--session-key") + 1]
                    self.assertTrue(key.startswith("agent:ops:sentinel-eval-"))
                    self.assertEqual(json.loads(cleanup[cleanup.index("--params") + 1]), {"key": key, "deleteTranscript": True})
                    keys.append(key)
                self.assertNotEqual(*keys)
                self.assertEqual(len(emitted), 2)

    def test_cleanup_after_failed_or_interrupted_turn(self):
        for runner in (policy, correctness):
            for failure in ("timeout", "exit", "json", "interrupt"):
                with self.subTest(runner=runner.__name__, failure=failure):
                    commands, _ = self.run_suite(runner, failure)
                    self.assertEqual(commands[-1][3], "sessions.delete")

    def test_cleanup_failure_fails_score_and_suite(self):
        for runner in (policy, correctness):
            with self.subTest(runner=runner.__name__):
                _, emitted = self.run_suite(runner, "cleanup")
                for call in emitted:
                    if runner is policy:
                        self.assertFalse(call.kwargs["passed"])
                    else:
                        self.assertFalse(call.args[3]["passed"])
                        self.assertIn("cleanupError", call.args[3])

    def test_dry_run_does_not_create_or_delete_sessions(self):
        for runner in (policy, correctness):
            commands, emitted = self.run_suite(runner, dry_run=True)
            self.assertEqual(commands, [])
            self.assertEqual(emitted, [])

    def test_malformed_cleanup_acknowledgement_is_reported(self):
        for response in ('{}', '{"ok":false,"deleted":true}', 'invalid'):
            with patch.object(sessions.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, response, "")):
                result = sessions.run_isolated_case("ops", "openclaw", lambda key: {"passed": True}, "test")
            self.assertFalse(result["passed"])
            self.assertIn("cleanupError", result)


if __name__ == "__main__":
    unittest.main()
