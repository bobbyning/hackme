#!/usr/bin/env python3
"""Roll reports/hunt-daily/YYYYMMDD into a weekly honesty ledger (families/signatures).

Usage:
  python3 scripts/ops/export_hunt_weekly_rollup.py
  python3 scripts/ops/export_hunt_weekly_rollup.py --end 20261004 --days 7
"""
from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path


def parse_day(s: str) -> datetime:
    return datetime.strptime(s, "%Y%m%d").replace(tzinfo=timezone.utc)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=os.environ.get("HACKME_REPO_ROOT") or ".")
    ap.add_argument("--end", default="", help="YYYYMMDD UTC end day (default today)")
    ap.add_argument("--days", type=int, default=7, help="window length (default 7)")
    args = ap.parse_args()
    root = Path(args.repo).resolve()
    end = parse_day(args.end) if args.end else datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    days = [end - timedelta(days=i) for i in range(args.days - 1, -1, -1)]
    day_ids = [d.strftime("%Y%m%d") for d in days]

    by_verdict: Counter[str] = Counter()
    sig_union: Counter[str] = Counter()
    fam_by_target: Counter[str] = Counter()
    info_rows: list[dict] = []
    total_iters = 0
    total_crash_artifacts = 0
    total_family_sum = 0
    days_present = 0

    for day in day_ids:
        roll_p = root / "reports" / "hunt-daily" / day / "ROLLUP.json"
        if not roll_p.is_file():
            continue
        days_present += 1
        doc = json.loads(roll_p.read_text())
        total_iters += int(doc.get("total_iterations") or 0)
        total_crash_artifacts += int(doc.get("total_crash_artifacts") or 0)
        total_family_sum += int(doc.get("total_finding_families") or 0)
        for k, v in (doc.get("by_verdict") or {}).items():
            by_verdict[str(k)] += int(v)
        for sig in doc.get("unique_sanitizer_signatures_union") or []:
            sig_union[str(sig)] += 1
        for r in doc.get("rows") or []:
            if (r.get("family_count") or 0) <= 0 and (r.get("verdict") or "") != "INFORMATIONAL":
                continue
            tid = str(r.get("target") or "?")
            fam_by_target[tid] += int(r.get("family_count") or 0)
            info_rows.append(
                {
                    "day": day,
                    "target": tid,
                    "verdict": r.get("verdict"),
                    "family_count": r.get("family_count") or 0,
                    "signatures": sorted((r.get("sanitizer_signatures") or {}).keys()),
                    "iterations": r.get("iterations") or 0,
                }
            )

    out_dir = root / "reports" / "hunt-weekly" / f"{day_ids[0]}-{day_ids[-1]}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Known hygiene notes (honesty — not CVE claims).
    hygiene_notes = {
        "libucl": "Known UBSan hygiene (function-pointer-cast / misaligned-pointer); upstream triage open — not bounty.",
        "tomlc17": "Often UBSan offsetof-via-NULL in page_create — noise under -fsanitize=undefined; ASAN-only typically clean.",
    }

    summary = {
        "window_start": day_ids[0],
        "window_end": day_ids[-1],
        "days_planned": len(day_ids),
        "days_with_rollup": days_present,
        "honesty_version": "2.0",
        "honesty_note": "Cite finding families / signatures, not raw crash artifact counts. INFORMATIONAL ≠ CVE.",
        "total_iterations": total_iters,
        "total_crash_artifacts": total_crash_artifacts,
        "total_finding_families_sum": total_family_sum,
        "by_verdict": dict(by_verdict),
        "signature_union": sorted(sig_union.keys()),
        "signature_days_seen": dict(sig_union),
        "family_sum_by_target": dict(fam_by_target),
        "informational_slots": info_rows,
        "hygiene_notes": {k: v for k, v in hygiene_notes.items() if k in fam_by_target},
    }
    (out_dir / "WEEKLY.json").write_text(json.dumps(summary, indent=2) + "\n")

    lines = [
        f"# Hunt weekly honesty ledger — {day_ids[0]} → {day_ids[-1]}",
        "",
        f"Days with rollup **{days_present}/{len(day_ids)}** · iters **{total_iters}** · "
        f"crash artifacts **{total_crash_artifacts}** · family-sum **{total_family_sum}** · "
        f"signature union **{len(sig_union)}**",
        "",
        "> Cite **families / signatures**, not raw crashes. INFORMATIONAL is hygiene triage, not a CVE claim.",
        "",
        f"Verdicts (slot counts): `{json.dumps(dict(by_verdict))}`",
        "",
        "## Signature union",
        "",
    ]
    if sig_union:
        for sig, n in sorted(sig_union.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"- `{sig}` — seen on **{n}** day(s)")
    else:
        lines.append("- _(none)_")
    lines += ["", "## Targets with families", ""]
    if fam_by_target:
        for tid, n in sorted(fam_by_target.items(), key=lambda kv: (-kv[1], kv[0])):
            note = hygiene_notes.get(tid, "")
            extra = f" — {note}" if note else ""
            lines.append(f"- `{tid}` family-sum **{n}**{extra}")
    else:
        lines.append("- _(all CLEAN / no families)_")
    lines += ["", "## INFORMATIONAL slots", ""]
    if info_rows:
        lines += [
            "| day | target | fam | signatures | iters |",
            "|-----|--------|----:|------------|------:|",
        ]
        for r in info_rows:
            sigs = ", ".join(f"`{s}`" for s in r["signatures"]) or "—"
            lines.append(
                f"| {r['day']} | `{r['target']}` | {r['family_count']} | {sigs} | {r['iterations']} |"
            )
    else:
        lines.append("_No INFORMATIONAL slots in window._")
    lines.append("")
    (out_dir / "WEEKLY.md").write_text("\n".join(lines) + "\n")
    print(f"wrote {out_dir}/WEEKLY.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
