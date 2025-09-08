#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 eml_safe_hash_algo_pw.py examples/sample.eml --algo sha256,md5
