"""The scoring formula and its configuration.

score = round((base + kev_bonus + epss_add) * reach_mult * asset_mult, 1)

Arithmetic is exact decimal with round-half-up, so a reviewer can recompute any score by hand
(81 x 1.5 x 1.3 = 157.95 -> 158.0) without binary floating-point surprises.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

import yaml

from . import FixrankError
from .enrich import REACHABILITY, Context
from .ingest import SEVERITIES, Finding, _read_text

DEFAULT_CONFIG = {
    "weights": {"critical": 40, "high": 30, "medium": 20, "low": 10},
    "kev_bonus": 25,
    "epss_factor": 20,
    "reach_mult": {"reachable": 1.5, "suspected": 1.2, "unknown": 1.0},
    "asset": {"prod_mult": 1.3, "exposed_add": 0.2},
}


@dataclass
class RankedFinding:
    rank: int
    score: float
    rationale: str
    finding: Finding


def _num(value, where: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FixrankError(f"config: {where} must be a number, got {value!r}")
    if value < 0 or (positive and value == 0):
        raise FixrankError(f"config: {where} must be {'greater than 0' if positive else '0 or more'}, got {value}")
    return value


def validate_config(raw: dict) -> dict:
    """Merge raw over the defaults and check every value. Raises FixrankError."""
    if not isinstance(raw, dict):
        raise FixrankError("config: expected a mapping at the top level")
    unknown = set(raw) - set(DEFAULT_CONFIG)
    if unknown:
        raise FixrankError(f"config: unknown key(s): {', '.join(sorted(unknown))}")
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    for key, value in raw.items():
        if isinstance(cfg[key], dict):
            if not isinstance(value, dict):
                raise FixrankError(f"config: {key} must be a mapping")
            extra = set(value) - set(cfg[key])
            if extra:
                raise FixrankError(f"config: unknown key(s) under {key}: {', '.join(sorted(extra))}")
            cfg[key].update(value)
        else:
            cfg[key] = value
    for sev in SEVERITIES:
        _num(cfg["weights"][sev], f"weights.{sev}")
    _num(cfg["kev_bonus"], "kev_bonus")
    _num(cfg["epss_factor"], "epss_factor")
    for r in REACHABILITY:
        _num(cfg["reach_mult"][r], f"reach_mult.{r}", positive=True)
    _num(cfg["asset"]["prod_mult"], "asset.prod_mult", positive=True)
    _num(cfg["asset"]["exposed_add"], "asset.exposed_add")
    return cfg


def load_config(path: str | Path | None) -> dict:
    if path is None:
        return copy.deepcopy(DEFAULT_CONFIG)
    try:
        raw = yaml.safe_load(_read_text(path))
    except yaml.YAMLError as e:
        raise FixrankError(f"{path}: invalid YAML ({e})") from None
    return validate_config(raw or {})


def _d(x: float) -> Decimal:
    return Decimal(str(x))


def _round(x: Decimal, places: str) -> Decimal:
    return x.quantize(Decimal(places), rounding=ROUND_HALF_UP)


def _g(x: float) -> str:
    """Compact number: 40 stays 40, 1.0 stays 1.0 so multipliers read as multipliers."""
    s = f"{x:g}"
    return s + ".0" if isinstance(x, float) and "." not in s and "e" not in s else s


def score_finding(f: Finding, ctx: Context, cfg: dict) -> tuple[float, str]:
    """Score one finding and return (score, rationale). The rationale shows every term."""
    base = cfg["weights"][f.severity]
    parts = [f"{f.severity} ({_g(base)})"]
    kev = cfg["kev_bonus"] if f.cve and f.cve in ctx.kev else 0
    if kev:
        parts.append(f"KEV-listed (+{_g(kev)})")
    epss = ctx.epss.get(f.cve) if f.cve else None
    epss_add = int(_round(_d(epss) * _d(cfg["epss_factor"]), "1")) if epss is not None else 0
    parts.append(f"EPSS {epss:.2f} (+{epss_add})" if epss is not None else "EPSS n/a (+0)")

    reach = ctx.reach.get(f.id, "unknown")
    reach_mult = cfg["reach_mult"][reach]

    asset = ctx.asset_for(f.file)
    prod = bool(asset and asset.prod)
    exposed = bool(asset and asset.internet_facing)
    asset_mult = (_d(cfg["asset"]["prod_mult"]) if prod else Decimal("1.0")) +         (_d(cfg["asset"]["exposed_add"]) if exposed else Decimal("0"))
    asset_label = ("prod" if prod else "non-prod") + ("+internet-facing" if exposed else "")

    score = float(_round((_d(base) + _d(kev) + epss_add) * _d(reach_mult) * asset_mult, "0.1"))
    rationale = (" + ".join(parts)
                 + f" x {reach} ({_g(reach_mult)}) x {asset_label} ({_g(float(asset_mult))}) = {score}")
    return score, rationale


def rank(findings: list[Finding], ctx: Context, cfg: dict) -> list[RankedFinding]:
    """Score every finding; order by score descending, then id ascending (stable and deterministic)."""
    scored = [(*score_finding(f, ctx, cfg), f) for f in findings]
    scored.sort(key=lambda t: (-t[0], t[2].id))
    return [RankedFinding(i, s, r, f) for i, (s, r, f) in enumerate(scored, start=1)]
