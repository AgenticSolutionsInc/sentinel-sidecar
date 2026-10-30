"""Run one evaluation turn in a disposable OpenClaw conversation."""
import json
import subprocess
import sys
import uuid


def run_isolated_case(agent, binary, run, suite):
    # OpenClaw creates an unknown session key on its first agent turn. Use a
    # canonical, reserved key so it cannot route into an existing user chat.
    key = f"agent:{agent}:sentinel-eval-{suite}-{uuid.uuid4().hex}"
    result = {}
    try:
        result = run(key)
        result["sessionKey"] = key
    finally:
        interrupted = sys.exc_info()[0] is not None
        try:
            completed = subprocess.run(
                [binary, "gateway", "call", "sessions.delete", "--params",
                 json.dumps({"key": key, "deleteTranscript": True}),
                 "--timeout", "30000", "--json"],
                capture_output=True, text=True, timeout=35, check=False,
            )
            payload = json.loads(completed.stdout) if completed.returncode == 0 else None
            if not isinstance(payload, dict) or payload.get("ok") is not True or type(payload.get("deleted")) is not bool:
                raise ValueError("Deletion was not acknowledged")
        except (OSError, subprocess.TimeoutExpired, ValueError):
            message = f"Could not discard temporary evaluation session {key}; inspect the Gateway and remove it manually."
            if interrupted:
                print(message, file=sys.stderr, flush=True)
            else:
                result["cleanupError"] = message
                result["runnerError"] = "; ".join(filter(None, (result.get("runnerError"), message)))
                result["passed"] = False
    return result
