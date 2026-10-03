#!/usr/bin/env python3
"""Shared Hunt-daily rotation queue helpers (driver-present filter)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


HOLD = {"csonh"}  # disclosure hold


def load_catalog(root: Path) -> dict:
    return json.loads((root / "upstream" / "oss_cve_targets.json").read_text())


def driver_path(root: Path, target: dict) -> Path:
    driver = (target.get("driver") or "").strip()
    if not driver:
        driver = f"{target.get('id', 'unknown')}_stdin"
    lang = (target.get("language") or "c").lower()
    ext = ".rs" if lang == "rust" else ".c"
    return root / "tasks" / "sources" / "fuzz" / "oss" / f"{driver}{ext}"


def runnable_queue(root: Path, catalog: dict | None = None) -> list[str]:
    m = catalog if catalog is not None else load_catalog(root)
    by_id = {t["id"]: t for t in (m.get("targets") or []) if t.get("id")}
    raw = (m.get("rotation") or {}).get("queue") or [t["id"] for t in m.get("targets") or []]
    out: list[str] = []
    for tid in raw:
        if not tid or tid in HOLD:
            continue
        tgt = by_id.get(tid) or {"id": tid, "driver": f"{tid}_stdin"}
        if driver_path(root, tgt).is_file():
            out.append(tid)
    return out


def pick(root: Path, day: str, hour: int) -> str:
    q = runnable_queue(root)
    if not q:
        return "cjson"
    import datetime

    doy = int(datetime.datetime.strptime(day, "%Y%m%d").strftime("%j"))
    return q[(doy * 24 + hour) % len(q)]


def day_slots(root: Path, day: str) -> list[dict]:
    q = runnable_queue(root)
    import datetime

    doy = int(datetime.datetime.strptime(day, "%Y%m%d").strftime("%j"))
    if not q:
        q = ["cjson"]
    return [{"hour_utc": f"{h:02d}", "target": q[(doy * 24 + h) % len(q)]} for h in range(24)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=".")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="print runnable queue ids")
    p_list.add_argument("--json", action="store_true")

    p_pick = sub.add_parser("pick", help="pick target for day+hour UTC")
    p_pick.add_argument("--day", required=True)
    p_pick.add_argument("--hour", type=int, required=True)

    p_sched = sub.add_parser("schedule", help="write 24h schedule json")
    p_sched.add_argument("--day", required=True)
    p_sched.add_argument("--out", required=True)

    p_miss = sub.add_parser("missing", help="catalog queue ids without driver on disk")

    args = ap.parse_args()
    root = Path(args.repo).resolve()

    if args.cmd == "list":
        q = runnable_queue(root)
        if args.json:
            print(json.dumps(q))
        else:
            print("\n".join(q))
        return 0
    if args.cmd == "pick":
        print(pick(root, args.day, args.hour))
        return 0
    if args.cmd == "schedule":
        slots = day_slots(root, args.day)
        q = runnable_queue(root)
        doc = {"day": args.day, "slots": slots, "queue_len": len(q), "queue": q}
        Path(args.out).write_text(json.dumps(doc, indent=2) + "\n")
        print(f"schedule {args.out} queue_len={len(q)}")
        return 0
    if args.cmd == "missing":
        m = load_catalog(root)
        by_id = {t["id"]: t for t in (m.get("targets") or []) if t.get("id")}
        raw = (m.get("rotation") or {}).get("queue") or []
        for tid in raw:
            if not tid or tid in HOLD:
                continue
            tgt = by_id.get(tid) or {"id": tid, "driver": f"{tid}_stdin"}
            if not driver_path(root, tgt).is_file():
                print(tid)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
