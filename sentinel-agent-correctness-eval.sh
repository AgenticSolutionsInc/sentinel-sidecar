#!/usr/bin/env bash
set -euo pipefail
umask 077
ENV_FILE="$HOME/.openclaw/.env"
if [[ ! -r "$ENV_FILE" ]]; then echo "sentinel-agent-correctness-eval: missing environment file" >&2; exit 1; fi
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
exec /usr/bin/env python3 "$HOME/sentinel-sidecar/sentinel_agent_correctness_eval.py" "$@"
