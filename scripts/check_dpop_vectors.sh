#!/usr/bin/env bash
set -euo pipefail
core_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
req_dir="${1:-${core_dir}/../req_dpop}"
cmp "${core_dir}/test/fixtures/dpop_htu_vectors.json" "${req_dir}/test/fixtures/dpop_htu_vectors.json"
printf '%s\n' 'DPoP HTU fixtures match.'
