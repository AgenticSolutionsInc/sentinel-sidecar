#!/usr/bin/env bash
# Run as the same OS user and in the same filesystem namespace as OpenClaw.
set -euo pipefail
umask 077

ENV_FILE="$HOME/.openclaw/.env"

if [[ ! -r "$ENV_FILE" ]]; then
  echo "sentinel-policy-eval: missing or unreadable environment file: $ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

echo "Running Swyft Sentinel Policy Evaluation" >&2
exec /usr/bin/env python3 "$HOME/sentinel-sidecar/sentinel_policy_eval.py" "$@"
