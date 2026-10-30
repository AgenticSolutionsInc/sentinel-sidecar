#!/usr/bin/env python3
"""Provisioner-owned bootstrap, run directly from ~/sentinel-sidecar."""
import base64
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

SIDECAR = Path(__file__).resolve().parent


def command(argv, env=None, timeout=120):
    print("[sentinel-bootstrap] Command: " + shlex.join(str(part) for part in argv), flush=True)
    result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("Runtime health/configuration command failed; output suppressed to protect credentials.")
    return result.stdout


def atomic(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as handle:
        os.chmod(handle.name, mode)
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(handle.name, path)


def environment(path):
    # Existing OpenClaw env files are trusted runtime configuration. Only source
    # inside the remote host, and never print the resulting environment.
    return json.loads(command(["bash", "-c", "set -a; source \"$1\" >/dev/null; exec python3 -c 'import os,json; print(json.dumps(dict(os.environ)))'", "bash", str(path)]))


def install(config, desired, home, root):
    desired = dict(desired)
    if config.get("telemetry") == "otel":
        desired["LANGFUSE_OTLP_AUTH"] = base64.b64encode(
            (desired["LANGFUSE_PUBLIC_KEY"] + ":" + desired["LANGFUSE_SECRET_KEY"]).encode()
        ).decode("ascii")
    env_path = home / ".openclaw/.env"
    print("[sentinel-bootstrap] Merging required values into OpenClaw's environment file", flush=True)
    env_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    original = env_path.read_text() if env_path.exists() else ""
    existing = environment(env_path) if env_path.exists() else {}
    owned_settings = ("POLICY_SYNC_STATE_PATH", "OPENCLAW_CONTROL_UI_ALLOWED_ORIGIN")
    # Keep existing credentials/configuration; secret rotation is a separate operation.
    for key, value in desired.items():
        if key in existing and existing[key] != value and key not in owned_settings:
            raise RuntimeError(f"Existing environment value differs for {key}; resolve explicitly before provisioning.")
    missing = {key: value for key, value in desired.items()
               if key not in existing or (key in owned_settings and existing[key] != value)}
    # Persist these values even when Hyper already injects them into the process.
    for key in ("OPENCLAW_GATEWAY_TOKEN", "OPENCLAW_CONTROL_UI_ALLOWED_ORIGIN", "LANGFUSE_OTLP_AUTH"):
        if desired.get(key) and not re.search(r"(?m)^\s*(?:export\s+)?" + key + r"\s*=", original):
            missing[key] = desired[key]
    if missing:
        addition = "\n# Sentinel provisioning\n" + "".join(f"export {key}={shlex.quote(value)}\n" for key, value in missing.items())
        atomic(env_path, original + addition)
    else:
        env_path.chmod(0o600)
    for name in ("sentinel-policy-sync.sh", "sentinel-policy-eval.sh", "sentinel-agent-correctness-eval.sh"):
        (root / name).chmod(0o700)
    state = root / "state"
    state.mkdir(exist_ok=True, mode=0o700)
    print("[sentinel-bootstrap] Finding the configured OpenClaw agent workspace", flush=True)
    env = environment(env_path)
    agents = json.loads(command(["openclaw", "agents", "list", "--json"], env=env))
    rows = agents if isinstance(agents, list) else agents.get("agents", [])
    selected = [a for a in rows if a.get("id") == desired["OPENCLAW_AGENT_ID"]]
    if len(selected) != 1 or not selected[0].get("workspace"):
        raise RuntimeError("Configured OpenClaw agent/workspace not found.")
    agents_path = str(Path(selected[0]["workspace"]).expanduser() / "AGENTS.md")
    if env.get("AGENTS_MD_PATH") and env["AGENTS_MD_PATH"] != agents_path:
        raise RuntimeError("AGENTS_MD_PATH does not match the selected agent workspace.")
    if not env.get("AGENTS_MD_PATH"):
        atomic(env_path, env_path.read_text() + "export AGENTS_MD_PATH=" + shlex.quote(agents_path) + "\n")
        env["AGENTS_MD_PATH"] = agents_path
    # Remove the temporary credentials once installed in OpenClaw's .env.
    (SIDECAR / "environment.json").unlink(missing_ok=True)


def verify(config, home, root):
    plugin = telemetry_plugin(config)[0]
    print("[sentinel-bootstrap] Checking permissions and " + plugin, flush=True)
    env_path = home / ".openclaw/.env"
    if env_path.stat().st_mode & 0o077 or root.stat().st_mode & 0o077:
        raise RuntimeError("Runtime secrets/directory permissions are too broad.")
    env = environment(env_path)
    inventory = json.loads(command(["openclaw", "plugins", "list", "--json"], env=env))
    plugins = inventory if isinstance(inventory, list) else inventory.get("plugins", [])
    if not any(entry.get("id") == plugin and entry.get("status") == "loaded" for entry in plugins):
        raise RuntimeError(plugin + " did not load after gateway configuration; telemetry setup failed.")
    # Verify the model after the gateway patch, and establish the existing
    # session required by the current evaluator without modifying main chat.
    print("[sentinel-bootstrap] Checking model connectivity", flush=True)
    result = json.loads(command(["openclaw", "agent", "--agent", env["OPENCLAW_AGENT_ID"], "--session-key", "sentinel-setup",
                                "--message", "Internal connectivity check: respond OK only. Do not use tools or take external actions.",
                                "--timeout", "60", "--json"], env=env, timeout=90))
    if not result or result.get("status") in ("error", "in_flight"):
        raise RuntimeError("Model connectivity check did not complete successfully.")
    print("[sentinel-bootstrap] Creating or updating the scheduled policy automations", flush=True)
    jobs_response = json.loads(command(["openclaw", "cron", "list", "--all", "--json"], env=env))
    jobs = jobs_response if isinstance(jobs_response, list) else jobs_response.get("jobs", [])
    schedules = (("policy-sync", config["syncSchedule"], 180, "sentinel-policy-sync.sh"),
                 ("policy-eval", config["evalSchedule"], 3600, "sentinel-policy-eval.sh"),
                 ("agent-correctness", "30 2 * * *", 3600, "sentinel-agent-correctness-eval.sh"))
    for suffix, schedule, timeout, runner_name in schedules:
        name = "sentinel-" + suffix + "-" + env["OPENCLAW_AGENT_ID"]
        matches = [job for job in jobs if job.get("name") == name]
        if len(matches) > 1:
            raise RuntimeError("Duplicate Sentinel automation names require manual reconciliation.")
        runner = str(root / runner_name)
        argv = ["flock", "-n", str(root / "state/execution.lock"), "timeout", "-k", "30", str(timeout - 30), runner]
        common = ["--cron", schedule, "--tz", config["timezone"], "--command-argv", json.dumps(argv),
                  "--timeout-seconds", str(timeout), "--output-max-bytes", "16384"]
        if matches:
            if matches[0].get("description") != "sentinel-provisioner-v1":
                raise RuntimeError("Automation name belongs to an unmanaged job.")
            command(["openclaw", "cron", "edit", matches[0]["id"], "--enable", *common], env=env)
        else:
            command(["openclaw", "cron", "add", "--name", name, "--description", "sentinel-provisioner-v1",
                     "--agent", env["OPENCLAW_AGENT_ID"], "--no-deliver", *common], env=env)
    response = json.loads(command(["openclaw", "cron", "list", "--all", "--json"], env=env))
    checked = response if isinstance(response, list) else response.get("jobs", [])
    for suffix in ("policy-sync", "policy-eval", "agent-correctness"):
        name = "sentinel-" + suffix + "-" + env["OPENCLAW_AGENT_ID"]
        if sum(job.get("name") == name and job.get("enabled", True) for job in checked) != 1:
            raise RuntimeError("Sentinel automation verification failed.")
    # The connectivity turn above lets OpenClaw populate its workspace before
    # Sentinel patches AGENTS.md. Never seed a blank file during provisioning.
    agents_path = Path(env["AGENTS_MD_PATH"]).expanduser()
    if not agents_path.is_file() or not agents_path.read_text(encoding="utf-8").strip():
        raise RuntimeError("OpenClaw has not populated AGENTS.md; retry provisioning after workspace initialization.")
    print("[sentinel-bootstrap] Running the initial policy sync after workspace initialization", flush=True)
    # The normal runner also restarts the gateway when the policy set changes.
    command(["bash", str(root / "sentinel-policy-sync.sh")], env=env)
    # This read-only check needs the policy hash written by the initial sync.
    print("[sentinel-bootstrap] Running the policy evaluation dry run", flush=True)
    command(["python3", str(root / "sentinel_policy_eval.py"), "--dry-run"], env=env)
    print("[sentinel-bootstrap] Running the agent correctness dataset dry run", flush=True)
    command(["python3", str(root / "sentinel_agent_correctness_eval.py"), "--dry-run"], env=env)
    print("Sentinel installation, evaluation dry runs, and automations verified.")


def telemetry_plugin(config):
    mode = config.get("telemetry", "langfuse-bridge")
    if mode == "otel":
        return "diagnostics-otel", "clawhub:@openclaw/diagnostics-otel"
    if mode == "langfuse-bridge":
        return "langfuse-bridge", "clawhub:openclaw-x-langfuse-plugin"
    raise ValueError("Unknown telemetry mode.")


def install_telemetry(config, home):
    plugin, package = telemetry_plugin(config)
    env = environment(home / ".openclaw/.env")
    print("[sentinel-bootstrap] Checking plugin installation: " + plugin, flush=True)
    # Use the plugin inventory for reruns; never blindly reinstall another copy.
    result = json.loads(command(["openclaw", "plugins", "list", "--json"], env=env))
    plugins = result if isinstance(result, list) else result.get("plugins", [])
    if not any(entry.get("id") == plugin for entry in plugins):
        command(["openclaw", "plugins", "install", package], env=env, timeout=240)
    result = json.loads(command(["openclaw", "plugins", "list", "--json"], env=env))
    plugins = result if isinstance(result, list) else result.get("plugins", [])
    if not any(entry.get("id") == plugin for entry in plugins):
        raise RuntimeError(plugin + " was not found after installation.")
    if config.get("telemetry") == "otel":
        command(["openclaw", "plugins", "enable", plugin], env=env)


def main():
    os.umask(0o077)
    config = json.loads((SIDECAR / "bootstrap.json").read_text())
    home = Path(config["home"])
    root = home / "sentinel-sidecar"
    root.chmod(0o700)
    with (root / "bootstrap.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if sys.argv[1] == "install":
            install(config, json.loads((SIDECAR / "environment.json").read_text()), home, root)
        elif sys.argv[1] == "verify":
            verify(config, home, root)
        elif sys.argv[1] == "telemetry":
            install_telemetry(config, home)
        else:
            raise RuntimeError("Unknown bootstrap phase.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("ERROR:", e)
        print("Sentinel bootstrap failed; sensitive command output suppressed. Resume provisioning after checking runtime configuration.", file=sys.stderr)
        raise SystemExit(1)
