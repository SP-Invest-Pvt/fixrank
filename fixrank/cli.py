"""Command line: python -m fixrank rank ...

Exit codes: 0 success, 1 a finding scored at or above --fail-above, 2 usage or configuration error.
Logs go to stderr; the queue goes to stdout unless -o is given.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import FixrankError, __version__
from .enrich import Context, load_epss, load_inventory, load_kev, load_reach
from .ingest import ingest_csv, ingest_sarif
from .render import to_json, to_markdown
from .scoring import load_config, rank


def _log(msg: str) -> None:
    print(f"fixrank: {msg}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fixrank", description="Rank security findings by what to fix first.")
    p.add_argument("--version", action="version", version=f"fixrank {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("rank", help="score and order findings",
                       description="Score findings with severity, KEV, EPSS, reachability and asset context.")
    r.add_argument("--sast", metavar="SARIF", help="SARIF 2.1.0 file")
    r.add_argument("--csv", metavar="CSV", help="CSV with columns id,rule_id,severity,cve,file,line,title")
    r.add_argument("--kev", metavar="CSV", help="CISA KEV catalog CSV (cveID column)")
    r.add_argument("--epss", metavar="CSV", help="EPSS scores CSV (cve,epss)")
    r.add_argument("--reach", metavar="CSV", help="reachability CSV (finding_id,reachability)")
    r.add_argument("--inventory", metavar="YAML", help="asset inventory YAML")
    r.add_argument("--config", metavar="YAML", help="scoring config YAML (defaults apply when omitted)")
    r.add_argument("-o", "--output", metavar="FILE", help="write the queue here instead of stdout")
    r.add_argument("--format", choices=["md", "json"], default="md", help="output format (default: md)")
    r.add_argument("--fail-above", type=float, metavar="SCORE",
                   help="exit 1 if any finding scores at or above SCORE (for CI gates)")
    return p


def cmd_rank(a: argparse.Namespace) -> int:
    if not a.sast and not a.csv:
        raise FixrankError("give at least one of --sast or --csv")
    cfg = load_config(a.config)
    findings = (ingest_sarif(a.sast) if a.sast else []) + (ingest_csv(a.csv) if a.csv else [])
    ctx = Context(
        kev=load_kev(a.kev) if a.kev else set(),
        epss=load_epss(a.epss) if a.epss else {},
        reach=load_reach(a.reach) if a.reach else {},
        assets=load_inventory(a.inventory) if a.inventory else [],
    )
    unmatched = sorted(set(ctx.reach) - {f.id for f in findings})
    if unmatched:
        _log(f"warning: {len(unmatched)} reachability verdict(s) match no finding and were ignored: "
             f"{', '.join(unmatched[:5])}{' ...' if len(unmatched) > 5 else ''}")
    ranked = rank(findings, ctx, cfg)
    out = to_json(ranked) if a.format == "json" else to_markdown(ranked)
    if a.output:
        Path(a.output).write_text(out, encoding="utf-8")
        _log(f"{len(ranked)} finding(s) ranked -> {a.output}")
    else:
        sys.stdout.write(out)
        _log(f"{len(ranked)} finding(s) ranked")
    if a.fail_above is not None:
        over = [r for r in ranked if r.score >= a.fail_above]
        if over:
            _log(f"{len(over)} finding(s) at or above {a.fail_above:g}: {', '.join(r.finding.id for r in over)}")
            return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        a = parser.parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)
    try:
        return cmd_rank(a)
    except FixrankError as e:
        _log(f"error: {e}")
        return 2
