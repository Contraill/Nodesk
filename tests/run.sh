#!/usr/bin/env bash
# Tüm testler (gerçek çıktılardan alınmış örneklerle):
#   tests/run.sh             -> birim + API + script testleri
#   tests/run.sh --preview   -> testler + http://localhost:8099 önizleme
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
python3 -m unittest discover -s tests 2>&1 | grep -v '^\[nodesk\]' || true
python3 -m unittest discover -s tests -q 2>/dev/null >/dev/null && echo "TÜM TESTLER GEÇTİ" || { echo "TEST BAŞARISIZ"; exit 1; }
bash -n bin/nodesk
command -v shellcheck >/dev/null && shellcheck -S warning bin/nodesk router/topo-collect
rm -rf tests/out
if [ "${1:-}" = "--preview" ]; then python3 tests/preview.py; fi
