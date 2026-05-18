#!/usr/bin/env bash
# Wrapper for calling the Devin API. Loads .env from the repo root.
# Usage: scripts/devin.sh <method> <org-relative-path> [json-body-file]
#   e.g. scripts/devin.sh GET playbooks
#        scripts/devin.sh POST playbooks ./payload.json
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
set -a; . "${REPO_ROOT}/.env"; set +a

: "${DEVIN_API_KEY:?DEVIN_API_KEY not set in .env}"
: "${DEVIN_ORG_ID:?DEVIN_ORG_ID not set in .env}"

method="${1:?method required}"
path="${2:?path required}"
body_file="${3:-}"

url="https://api.devin.ai/v3/organizations/${DEVIN_ORG_ID}/${path}"
args=(-sS -X "${method}" -H "Authorization: Bearer ${DEVIN_API_KEY}" -H "Accept: application/json")
if [[ -n "${body_file}" ]]; then
  args+=(-H "Content-Type: application/json" --data-binary "@${body_file}")
fi
args+=(-w "\nHTTP %{http_code}\n" "${url}")

/usr/bin/curl "${args[@]}"
