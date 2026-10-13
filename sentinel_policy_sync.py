#!/usr/bin/env python3
"""Fetch and install Swyft policy in a managed section of OpenClaw AGENTS.md.

Designed for a cron job or a service timer that runs in the same filesystem
namespace and under the same OS user as the OpenClaw runtime.
"""

from __future__ import annotations

import hashlib
import argparse
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TIMEOUT_SECONDS = 20
SUPPORTED_POLICY_SET_SCHEMA = "1.0"
POLICY_SECTION_START = "<!-- BEGIN SWYFT SENTINEL POLICY -->"
POLICY_SECTION_END = "<!-- END SWYFT SENTINEL POLICY -->"
POLICY_SECTION_HEADING = "## SAFETY RED LINES & CONSTRAINTS & ABSOLUTE RESTRICTIONS - YOU MUST AT ALL TIMES OBEY ALL RULES IN THIS POLICY SECTION"


class PolicySyncError(RuntimeError):
    pass


def log(message: str) -> None:
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"{timestamp} swyft-policy-sync: {message}", flush=True)


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise PolicySyncError(f"Required environment variable {name} is missing.")
    return value


def stable_json(value: Any) -> str:
    """Match Governance's stable JSON serialization for policy-set integrity checks."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def policy_set_hash(policy_set_without_hash: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(stable_json(policy_set_without_hash).encode("utf-8")).hexdigest()


def read_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PolicySyncError(f"Unable to read policy sync state at {path}: {error}") from error
    if not isinstance(value, dict):
        raise PolicySyncError(f"Policy sync state at {path} is not a JSON object.")
    return value


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        os.fchmod(fd, path.stat().st_mode & 0o777 if path.exists() else 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def validate_response(payload: Any, expected_agent_key: str | None) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise PolicySyncError("Governance response is not a JSON object.")
    if payload.get("schemaVersion") != SUPPORTED_POLICY_SET_SCHEMA:
        raise PolicySyncError(f"Unsupported policy-set schema {payload.get('schemaVersion')!r}.")
    agent_key = payload.get("agentKey")
    if not isinstance(agent_key, str) or not agent_key:
        raise PolicySyncError("Governance response has no valid agentKey.")
    if expected_agent_key and agent_key != expected_agent_key:
        raise PolicySyncError(f"Credential resolved to agent {agent_key!r}, not expected agent {expected_agent_key!r}.")
    policies = payload.get("policies")
    if not isinstance(policies, list):
        raise PolicySyncError("Governance response has no policies list.")

    for index, policy in enumerate(policies):
        if not isinstance(policy, dict):
            raise PolicySyncError(f"Policy {index} is not an object.")
        rulepack = policy.get("rulepack")
        release = policy.get("release")
        if not isinstance(rulepack, dict) or not all(isinstance(rulepack.get(key), str) and rulepack[key] for key in ("id", "slug", "name")):
            raise PolicySyncError(f"Policy {index} has an invalid rulepack descriptor.")
        if not isinstance(release, dict):
            raise PolicySyncError(f"Policy {index} has no release descriptor.")
        if release.get("schemaVersion") != SUPPORTED_POLICY_SET_SCHEMA:
            raise PolicySyncError(f"Policy {index} uses unsupported release schema {release.get('schemaVersion')!r}.")
        if not all(isinstance(release.get(key), str) and release[key] for key in ("id", "version", "sha256", "publishedAt", "policyMarkdown")):
            raise PolicySyncError(f"Policy {index} has an incomplete release descriptor.")
        if not release["sha256"].startswith("sha256:"):
            raise PolicySyncError(f"Policy {index} has an invalid immutable release hash.")
        if not isinstance(release.get("document"), dict):
            raise PolicySyncError(f"Policy {index} has an invalid release document.")

    policy_set_without_hash = {
        "schemaVersion": payload["schemaVersion"],
        "agentKey": agent_key,
        "policies": policies,
    }
    supplied_hash = payload.get("policySetSha256")
    calculated_hash = policy_set_hash(policy_set_without_hash)
    if supplied_hash != calculated_hash:
        raise PolicySyncError("Policy-set SHA-256 mismatch; retaining the current AGENTS.md.")
    return policies


def render_policy_markdown(payload: dict[str, Any], policies: list[dict[str, Any]]) -> str:
    fragments = [
        "<!-- Managed by Swyft Sentinel. Do not edit this section manually. -->",
        f"<!-- Agent: {payload['agentKey']} | Policy set: {payload['policySetSha256']} -->",
        "",
    ]
    for policy in policies:
        rulepack = policy["rulepack"]
        release = policy["release"]
        fragments.extend([
            f"<!-- Rulepack: {rulepack['name']} ({rulepack['slug']}) | Release: {release['version']} -->",
            release["policyMarkdown"].rstrip(),
            "",
        ])
    return "\n".join(fragments).rstrip() + "\n"


def read_agents(path: Path) -> str:
    if not path.exists():
        return ""
    # Preserve line endings and all text outside the managed section.
    with path.open(encoding="utf-8", newline="") as handle:
        return handle.read()


def policy_section_bounds(content: str) -> tuple[int, int] | None:
    starts = content.count(POLICY_SECTION_START)
    ends = content.count(POLICY_SECTION_END)
    if starts == 0 and ends == 0:
        return None
    if starts != 1 or ends != 1:
        raise PolicySyncError("AGENTS.md has missing or duplicate Sentinel policy markers; refusing to modify it.")
    start = content.index(POLICY_SECTION_START)
    end = content.index(POLICY_SECTION_END)
    if end < start:
        raise PolicySyncError("AGENTS.md has reversed Sentinel policy markers; refusing to modify it.")
    return start, end + len(POLICY_SECTION_END)


def managed_policy_section(markdown: str) -> str:
    if POLICY_SECTION_START in markdown or POLICY_SECTION_END in markdown:
        raise PolicySyncError("Policy content contains reserved Sentinel section markers.")
    return f"{POLICY_SECTION_START}\n{POLICY_SECTION_HEADING}\n\n{markdown.rstrip()}\n{POLICY_SECTION_END}"


def replace_policy_section(content: str, section: str) -> str:
    bounds = policy_section_bounds(content)
    if bounds:
        start, end = bounds
        return content[:start] + section + content[end:]
    separator = "" if not content else "\n" if content.endswith("\n") else "\n\n"
    return content + separator + section + "\n"


def section_hash(section: str) -> str:
    return hashlib.sha256(section.encode("utf-8")).hexdigest()


def fetch_policy_set(base_url: str, credential_id: str, credential_secret: str, etag: str | None) -> tuple[int, dict[str, Any] | None, str | None]:
    url = base_url.rstrip("/") + "/v1/agent/policies"
    headers = {
        "Authorization": f"SwyftAgent {credential_id}:{credential_secret}",
        "Accept": "application/json",
        "User-Agent": "swyft-openclaw-policy-sync/1.0",
    }
    if etag:
        headers["If-None-Match"] = etag
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            status = response.status
            response_etag = response.headers.get("ETag")
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        if error.code == 304:
            return 304, None, error.headers.get("ETag")
        message = error.read().decode("utf-8", errors="replace")[:300]
        raise PolicySyncError(f"Governance returned HTTP {error.code}: {message}") from error
    except urllib.error.URLError as error:
        raise PolicySyncError(f"Unable to reach Governance API: {error.reason}") from error

    if status != 200:
        raise PolicySyncError(f"Governance returned unexpected HTTP {status}.")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as error:
        raise PolicySyncError("Governance returned invalid JSON.") from error
    if not isinstance(payload, dict):
        raise PolicySyncError("Governance returned an invalid policy payload.")
    return status, payload, response_etag


def main(report_change: bool = False) -> int:
    os.umask(0o077)
    try:
        base_url = required_env("SWYFT_GOVERNANCE_URL")
        credential_id = required_env("SWYFT_AGENT_CREDENTIAL_ID")
        credential_secret = required_env("SWYFT_AGENT_CREDENTIAL_SECRET")
        policy_path = Path(required_env("AGENTS_MD_PATH")).expanduser().resolve()
        state_path = Path(required_env("POLICY_SYNC_STATE_PATH")).expanduser().resolve()
        expected_agent_key = os.environ.get("SWYFT_EXPECTED_AGENT_KEY", "").strip() or None
        allow_empty = os.environ.get("SWYFT_ALLOW_EMPTY_POLICY_SET", "false").strip().lower() in {"1", "true", "yes"}
        state = read_state(state_path)
        previous_etag = state.get("etag") if isinstance(state.get("etag"), str) else None
        content = read_agents(policy_path)
        bounds = policy_section_bounds(content)
        # Only trust a cached ETag when this destination still contains the
        # exact policy section we installed. Recover removed/edited sections.
        if not bounds or POLICY_SECTION_HEADING not in content[bounds[0]:bounds[1]] or state.get("agentsMdPath") != str(policy_path) or state.get("sectionSha256") != section_hash(content[bounds[0]:bounds[1]]):
            previous_etag = None
        status, payload, response_etag = fetch_policy_set(base_url, credential_id, credential_secret, previous_etag)
        print("[Swyft][Sentinel] Policy Set:", payload)
        if status == 304:
            current = read_agents(policy_path)
            current_bounds = policy_section_bounds(current)
            if not current_bounds or state.get("sectionSha256") != section_hash(current[current_bounds[0]:current_bounds[1]]):
                raise PolicySyncError("Sentinel policy section changed during polling; retry sync to restore it.")
            log("policy set unchanged")
            return 0
        assert payload is not None
        policies = validate_response(payload, expected_agent_key)
        if not policies and not allow_empty:
            raise PolicySyncError("Governance returned an empty policy set; refusing to clear the Sentinel section in AGENTS.md. Set SWYFT_ALLOW_EMPTY_POLICY_SET=true only when that behavior is intentional.")
        calculated_etag = '"' + str(payload["policySetSha256"]) + '"'
        if response_etag and response_etag != calculated_etag:
            raise PolicySyncError("Response ETag does not match the verified policy-set hash; retaining the current AGENTS.md.")
        section = managed_policy_section(render_policy_markdown(payload, policies))
        policy_set_changed = state.get("policySetSha256") != payload["policySetSha256"]
        # Read again after the network request to include others' latest edits.
        current = read_agents(policy_path)
        updated = replace_policy_section(current, section)
        if updated != current:
            if read_agents(policy_path) != current:
                raise PolicySyncError("AGENTS.md changed during installation; retry sync.")
            atomic_write(policy_path, updated)
        atomic_write(state_path, json.dumps({
            "schemaVersion": 2,
            "agentsMdPath": str(policy_path),
            "sectionSha256": section_hash(section),
            "agentKey": payload["agentKey"],
            "etag": response_etag or calculated_etag,
            "policySetSha256": payload["policySetSha256"],
            "installedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }, indent=2) + "\n")
        log(f"installed {len(policies)} rulepack(s); policy set {payload['policySetSha256']}")
        # The shell runner uses 10 as a successful installation with a new
        # policy-set hash. Direct callers retain the normal success code 0.
        return 10 if report_change and policy_set_changed else 0
    except PolicySyncError as error:
        log(f"ERROR {error}")
        return 1
    except Exception as error:  # Defensive guard for cron: retain current policy on all unhandled failures.
        log(f"ERROR unexpected failure: {error}")
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-change", action="store_true", help="Exit 10 after installing a changed policy set; exit 0 when unchanged.")
    sys.exit(main(report_change=parser.parse_args().report_change))
