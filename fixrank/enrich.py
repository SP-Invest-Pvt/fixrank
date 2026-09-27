"""Context that changes a finding's priority: KEV, EPSS, reachability and asset inventory."""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import FixrankError
from .ingest import _read_text

REACHABILITY = ("reachable", "suspected", "unknown")


@dataclass(frozen=True)
class Asset:
    name: str
    path_prefix: str
    prod: bool = False
    internet_facing: bool = False


@dataclass
class Context:
    kev: set[str] = field(default_factory=set)
    epss: dict[str, float] = field(default_factory=dict)
    reach: dict[str, str] = field(default_factory=dict)
    assets: list[Asset] = field(default_factory=list)

    def asset_for(self, file: str) -> Asset | None:
        """The asset whose path_prefix is the longest prefix of file, or None."""
        best = None
        for a in self.assets:
            if file.startswith(a.path_prefix) and (best is None or len(a.path_prefix) > len(best.path_prefix)):
                best = a
        return best


def _csv_rows(path: str | Path, required: tuple[str, ...]) -> list[dict]:
    # FIRST's EPSS export starts with a '#model_version:...' comment line.
    lines = [ln for ln in _read_text(path).splitlines() if ln.strip() and not ln.startswith("#")]
    reader = csv.DictReader(lines)
    if lines and not all(c in (reader.fieldnames or []) for c in required):
        found = ", ".join(reader.fieldnames or [])
        raise FixrankError(f"{path}: expected column(s) {', '.join(required)}, found {found}")
    return list(reader)


def load_kev(path: str | Path) -> set[str]:
    """CVE ids from the CISA KEV CSV (the cveID column)."""
    return {r["cveID"].strip().upper() for r in _csv_rows(path, ("cveID",)) if (r["cveID"] or "").strip()}


def load_epss(path: str | Path) -> dict[str, float]:
    """cve -> EPSS probability (0..1) from a cve,epss CSV."""
    out = {}
    for n, r in enumerate(_csv_rows(path, ("cve", "epss")), start=2):
        try:
            p = float(r["epss"])
        except (TypeError, ValueError):
            raise FixrankError(f"{path}:{n}: epss {r['epss']!r} is not a number") from None
        if not 0.0 <= p <= 1.0:
            raise FixrankError(f"{path}:{n}: epss {p} is outside 0..1")
        out[r["cve"].strip().upper()] = p
    return out


def load_reach(path: str | Path) -> dict[str, str]:
    """finding_id -> reachable | suspected | unknown."""
    out = {}
    for n, r in enumerate(_csv_rows(path, ("finding_id", "reachability")), start=2):
        value = (r["reachability"] or "").strip().lower()
        if value not in REACHABILITY:
            raise FixrankError(
                f"{path}:{n}: reachability {r['reachability']!r} is not one of {', '.join(REACHABILITY)}")
        out[r["finding_id"].strip()] = value
    return out


def load_inventory(path: str | Path) -> list[Asset]:
    """assets: [{name, path_prefix, prod, internet_facing}] from YAML."""
    try:
        doc = yaml.safe_load(_read_text(path)) or {}
    except yaml.YAMLError as e:
        raise FixrankError(f"{path}: invalid YAML ({e})") from None
    items = doc.get("assets") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        raise FixrankError(f"{path}: expected a top-level 'assets' list")
    assets = []
    for i, a in enumerate(items):
        if not isinstance(a, dict) or not a.get("name") or "path_prefix" not in a:
            raise FixrankError(f"{path}: assets[{i}] needs 'name' and 'path_prefix'")
        for flag in ("prod", "internet_facing"):
            if not isinstance(a.get(flag, False), bool):
                raise FixrankError(f"{path}: assets[{i}].{flag} must be true or false")
        assets.append(Asset(str(a["name"]), str(a["path_prefix"]), a.get("prod", False), a.get("internet_facing", False)))
    return assets
