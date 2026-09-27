"""Render a ranked queue as Markdown or JSON."""
from __future__ import annotations

import json
from dataclasses import asdict

from .scoring import RankedFinding


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def to_markdown(ranked: list[RankedFinding], title: str = "Fix queue") -> str:
    lines = [f"# {title}", ""]
    if not ranked:
        return "\n".join(lines + ["No findings.", ""])
    lines += ["| # | Score | ID | Severity | CVE | Location | Title |",
              "|---:|---:|---|---|---|---|---|"]
    for r in ranked:
        f = r.finding
        loc = f"{f.file}:{f.line}" if f.file else "-"
        lines.append(f"| {r.rank} | {r.score} | {_cell(f.id)} | {f.severity} | {f.cve or '-'} | "
                     f"{_cell(loc)} | {_cell(f.title)} |")
    lines += ["", "## Why this order", ""]
    lines += [f"{r.rank}. `{_cell(r.finding.id)}`: {r.rationale}" for r in ranked]
    return "\n".join(lines) + "\n"


def to_json(ranked: list[RankedFinding]) -> str:
    return json.dumps([{"rank": r.rank, "score": r.score, "rationale": r.rationale, **asdict(r.finding)}
                       for r in ranked], indent=2) + "\n"
