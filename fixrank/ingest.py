"""Read findings from SARIF 2.1.0 or a simple CSV into one Finding shape."""
from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path

from . import FixrankError

SEVERITIES = ("critical", "high", "medium", "low")
CSV_COLUMNS = ("id", "rule_id", "severity", "cve", "file", "line", "title")
# SARIF result.level -> severity, used only when no explicit severity is given.
LEVEL_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "low"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    id: str
    rule_id: str
    severity: str
    cve: str
    file: str
    line: int
    title: str


def _read_text(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        raise FixrankError(f"file not found: {path}") from None
    except OSError as e:
        raise FixrankError(f"cannot read {path}: {e.strerror}") from None


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _sarif_severity(result: dict, rule: dict) -> str:
    """Explicit properties.severity, else the rule's CVSS security-severity, else the SARIF level."""
    props = result.get("properties") or {}
    explicit = str(props.get("severity", "")).lower()
    if explicit in SEVERITIES:
        return explicit
    cvss = (rule.get("properties") or {}).get("security-severity")
    if cvss is not None:
        try:
            return _severity_from_cvss(float(cvss))
        except (TypeError, ValueError):
            pass
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
    return LEVEL_SEVERITY.get(level, "medium")


def _sarif_cve(result: dict, rule_id: str) -> str:
    props = result.get("properties") or {}
    for text in (props.get("cve"), rule_id, (result.get("message") or {}).get("text")):
        if text:
            m = CVE_RE.search(str(text))
            if m:
                return m.group(0).upper()
    return ""


def ingest_sarif(path: str | Path) -> list[Finding]:
    """Parse runs[].results[] from a SARIF file.

    The finding id is the result's guid, else properties.id, else rule@file:line, so a
    reachability CSV can refer to it.
    """
    try:
        doc = json.loads(_read_text(path))
    except json.JSONDecodeError as e:
        raise FixrankError(f"{path}: not valid JSON ({e.msg} at line {e.lineno})") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        raise FixrankError(f"{path}: not a SARIF log (no 'runs' array)")
    findings: list[Finding] = []
    for run in doc["runs"]:
        driver = ((run or {}).get("tool") or {}).get("driver") or {}
        rules = {r.get("id"): r for r in driver.get("rules") or [] if isinstance(r, dict)}
        for result in (run or {}).get("results") or []:
            rule_id = result.get("ruleId") or (result.get("rule") or {}).get("id") or "unknown-rule"
            rule = rules.get(rule_id, {})
            loc = ((result.get("locations") or [{}])[0] or {}).get("physicalLocation") or {}
            file = ((loc.get("artifactLocation") or {}).get("uri") or "").removeprefix("file://")
            try:
                line = int((loc.get("region") or {}).get("startLine") or 0)
            except (TypeError, ValueError):
                raise FixrankError(f"{path}: result for {rule_id} has a non-numeric startLine") from None
            props = result.get("properties") or {}
            fid = result.get("guid") or props.get("id") or f"{rule_id}@{file}:{line}"
            title = ((result.get("message") or {}).get("text")
                     or (rule.get("shortDescription") or {}).get("text") or rule_id)
            findings.append(Finding(str(fid), rule_id, _sarif_severity(result, rule), _sarif_cve(result, rule_id),
                                    file, line, title.strip().splitlines()[0] if title.strip() else rule_id))
    return findings


def ingest_csv(path: str | Path) -> list[Finding]:
    """Parse a CSV with columns id,rule_id,severity,cve,file,line,title."""
    reader = csv.DictReader(_read_text(path).splitlines())
    missing = [c for c in CSV_COLUMNS if c not in (reader.fieldnames or [])]
    if reader.fieldnames and missing:
        raise FixrankError(f"{path}: missing column(s): {', '.join(missing)}")
    findings = []
    for n, row in enumerate(reader, start=2):
        severity = (row["severity"] or "").strip().lower()
        if severity not in SEVERITIES:
            raise FixrankError(f"{path}:{n}: severity {row['severity']!r} is not one of {', '.join(SEVERITIES)}")
        try:
            line = int(row["line"] or 0)
        except ValueError:
            raise FixrankError(f"{path}:{n}: line {row['line']!r} is not a number") from None
        if not (row["id"] or "").strip():
            raise FixrankError(f"{path}:{n}: empty id")
        findings.append(Finding(row["id"].strip(), (row["rule_id"] or "").strip(), severity,
                                (row["cve"] or "").strip().upper(), (row["file"] or "").strip(), line,
                                (row["title"] or "").strip()))
    return findings
