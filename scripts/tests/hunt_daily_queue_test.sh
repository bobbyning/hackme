#!/usr/bin/env bash
# Gate: Hunt daily rotation queue only includes on-disk drivers.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

miss="$(python3 scripts/ops/hunt_daily_queue.py --repo "$ROOT" missing || true)"
if [[ -n "${miss// }" ]]; then
  echo "FAIL: rotation queue still has undrivable ids:" >&2
  echo "$miss" >&2
  exit 1
fi

n="$(python3 scripts/ops/hunt_daily_queue.py --repo "$ROOT" list | wc -l | tr -d ' ')"
if [[ "$n" -lt 8 ]]; then
  echo "FAIL: runnable queue too small ($n)" >&2
  exit 1
fi

day="$(date -u +%Y%m%d)"
tmp="$(mktemp)"
python3 scripts/ops/hunt_daily_queue.py --repo "$ROOT" schedule --day "$day" --out "$tmp"
python3 - "$tmp" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
assert doc.get("queue_len", 0) >= 8, doc
assert len(doc.get("slots") or []) == 24, doc
print("schedule ok queue_len=%s" % doc["queue_len"])
PY
rm -f "$tmp"

# FORCE missing driver must SKIP (exit 0) and stamp verdict (isolated day dir).
deferred="$(python3 - <<'PY'
import json
m=json.load(open("upstream/oss_cve_targets.json"))
d=(m.get("rotation") or {}).get("deferred_until_driver") or []
print(d[0] if d else "microjson_no_driver_xyz")
PY
)"
GATE_DAY="20990101"
rm -rf "$ROOT/reports/hunt-daily/$GATE_DAY"
HUNT_DAILY_DAY="$GATE_DAY" HUNT_DAILY_HOUR="00" SLOT_WALL_SEC=5 FORCE_TARGET="$deferred" \
  bash scripts/ops/hunt_daily_rotate.sh >/tmp/hunt-daily-skip-gate.out 2>&1 || {
  echo "FAIL: rotate exited non-zero on missing driver" >&2
  cat /tmp/hunt-daily-skip-gate.out >&2
  exit 1
}
slot="$ROOT/reports/hunt-daily/$GATE_DAY/0000-${deferred}"
if [[ ! -f "$slot/hunt-local.json" ]]; then
  echo "FAIL: missing SKIP hunt-local.json for $deferred" >&2
  cat /tmp/hunt-daily-skip-gate.out >&2
  exit 1
fi
python3 - "$slot/hunt-local.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
assert doc.get("verdict") == "SKIP", doc
assert doc.get("error") == "missing_driver", doc
print("SKIP path ok", doc["target"])
PY
rm -rf "$ROOT/reports/hunt-daily/$GATE_DAY"

echo "PASS hunt_daily_queue_test"
