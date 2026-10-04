#!/usr/bin/env bash
# Gate: libucl OSS pack must link on current tip (needs src/ucl_cbor.c in catalog).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

python3 - <<'PY'
import json
from pathlib import Path
t = next(x for x in json.loads(Path("upstream/oss_cve_targets.json").read_text())["targets"] if x["id"] == "libucl")
src = t.get("upstream_src") or []
assert "src/ucl_cbor.c" in src, f"libucl upstream_src missing ucl_cbor.c: {src}"
print("catalog ok: ucl_cbor.c listed")
PY

# Fresh binary name (hash includes upstream_src); force rebuild by removing matches.
rm -f "$ROOT"/.cache/oss-cve-bin/libucl-*.bin 2>/dev/null || true
TARGETS=libucl bash "$ROOT/scripts/ops/build_oss_cve_pack.sh"
test -n "$(ls "$ROOT"/.cache/oss-cve-bin/libucl-*.bin 2>/dev/null | head -1)"
echo "PASS oss_libucl_build_gate"
