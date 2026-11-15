#!/usr/bin/env python
"""Offline evaluation of the scoring engine against labelled scenarios -> docs/evaluation-report.md"""
from __future__ import annotations

import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from app.ids import normalize_cve_id  # noqa: E402
from app.scoring import PRIORITY_ORDER, rank_key, score  # noqa: E402
from tests.evaluation.scenarios import ID_CASES, S  # noqa: E402


def rank(sc):
    res = {k: score(v) for k, v in sc.items.items()}
    order = sorted(sc.items, key=lambda k: rank_key(res[k].risk_score, sc.items[k].kev_listed, sc.items[k].epss, k))
    return order, res


def evaluate():
    rows, fails = [], []
    pair_ok = pair_n = 0
    urgent_hit = urgent_n = 0
    prio_ok = prio_n = 0
    for sc in S:
        order, res = rank(sc)
        pos = {k: i for i, k in enumerate(order)}
        checks = []
        for a, b in sc.before:
            pair_n += 1
            ok = pos[a] < pos[b]
            pair_ok += ok
            checks.append(ok)
            if not ok:
                fails.append(f"{sc.sid}: expected {a} before {b} (got {order}; scores {[res[k].risk_score for k in order]})")
        for k in sc.last:
            pair_n += 1
            ok = pos[k] == len(order) - 1
            pair_ok += ok
            checks.append(ok)
            if not ok:
                fails.append(f"{sc.sid}: expected {k} last")
        for k, allowed in sc.prio.items():
            prio_n += 1
            ok = res[k].priority in allowed
            prio_ok += ok
            checks.append(ok)
            if not ok:
                fails.append(f"{sc.sid}: {k} priority {res[k].priority} not in {sorted(allowed)}")
        if sc.urgent:
            k = len(sc.urgent)
            urgent_n += 1
            top = set(order[:k])
            urgent_hit += sc.urgent <= top
            if not sc.urgent <= top:
                fails.append(f"{sc.sid}: urgent {sorted(sc.urgent)} not all in top {k}: {order[:k]}")
        rows.append((sc, order, res, all(checks)))
    # determinism: shuffle input order 5 ways -> identical ranking
    det_ok = 0
    for sc in S:
        base, _ = rank(sc)
        same = True
        for perm in itertools.islice(itertools.permutations(list(sc.items)), 5):
            sub = type(sc)(sc.sid, "", "", {k: sc.items[k] for k in perm})
            same &= rank(sub)[0] == base
        det_ok += same
    # id validation
    id_ok = 0
    for raw, accept in ID_CASES:
        try:
            normalize_cve_id(raw)
            got = True
        except ValueError:
            got = False
        id_ok += got == accept
    return rows, fails, dict(pair=(pair_ok, pair_n), urgent=(urgent_hit, urgent_n), prio=(prio_ok, prio_n),
                             det=(det_ok, len(S)), ids=(id_ok, len(ID_CASES)))


def render(rows, fails, m) -> str:
    pct = lambda t: f"{t[0]}/{t[1]} ({100 * t[0] / t[1]:.0f}%)" if t[1] else "n/a"
    out = ["# VulnRank evaluation report (score_version v1)", "",
           "Offline, deterministic: evidence snapshots are fixed inputs, so this measures the *scoring and ranking logic*, "
           "not upstream data quality or live latency. Expectations were written from security reasoning before running the engine "
           "(see `tests/evaluation/scenarios.py`). Many scenarios are parameter sweeps of the same invariants, so treat the "
           "count as breadth of coverage, not as independent samples. The scenarios are the author's, not an external benchmark.", "",
           "## Metrics", "", "| Metric | Result |", "|---|---|",
           f"| Scenarios | {len(rows)} |",
           f"| Pairwise ordering agreement with labels | {pct(m['pair'])} |",
           f"| Priority-band expectations met | {pct(m['prio'])} |",
           f"| Urgent-set recall (all must-fix items within top-k, k = size of set) | {pct(m['urgent'])} |",
           f"| Determinism (5 shuffled input orders -> identical ranking) | {pct(m['det'])} |",
           f"| CVE identifier accept/reject accuracy | {pct(m['ids'])} |", ""]
    out += ["## Failures", ""] + ([f"- {f}" for f in fails] if fails else ["None."]) + ["", "## Scenarios", ""]
    for sc, order, res, ok in rows:
        out.append(f"### {sc.sid} {'PASS' if ok else 'FAIL'} - {sc.title}")
        out.append(f"*Why:* {sc.why}\n")
        out.append("| rank | CVE | risk | priority | confidence |\n|---|---|---|---|---|")
        for i, k in enumerate(order, 1):
            r = res[k]
            out.append(f"| {i} | {k} | {r.risk_score if r.risk_score is not None else '-'} | {r.priority} | {r.confidence_label} |")
        out.append("")
    return "\n".join(out)


if __name__ == "__main__":
    rows, fails, m = evaluate()
    rep = render(rows, fails, m)
    Path(__file__).parents[1].joinpath("docs/evaluation-report.md").write_text(rep)
    print(rep.split("## Failures")[0])
    print("FAILURES:", *fails, sep="\n  " if fails else " none\n")
    sys.exit(1 if fails else 0)
