#!/usr/bin/env bash
# Run as the same OS user and in the same filesystem namespace as OpenClaw.
set -euo pipefail
umask 077

ENV_FILE="$HOME/.openclaw/.env"

if [[ ! -r "$ENV_FILE" ]]; then
  echo "swyft-policy-sync: missing or unreadable environment file: $ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

echo "Running Swyft Sentinel Policy Sync"
sync_status=0
/usr/bin/env python3 "$HOME/sentinel-sidecar/sentinel_policy_sync.py" --report-change || sync_status=$?

case "$sync_status" in
  0)
    echo "Policy set unchanged; skipping OpenClaw Gateway restart"
    ;;
  10)
    echo "Policy set changed; restarting OpenClaw Gateway"
    exec openclaw gateway restart
    ;;
  *)
    exit "$sync_status"
    ;;
esac
