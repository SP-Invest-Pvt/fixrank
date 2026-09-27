import json
from pathlib import Path

import pytest

from fixrank import FixrankError
from fixrank.cli import main
from fixrank.enrich import Asset, Context, load_epss, load_inventory, load_kev, load_reach
from fixrank.ingest import Finding, ingest_csv, ingest_sarif
from fixrank.render import to_json, to_markdown
from fixrank.scoring import DEFAULT_CONFIG, load_config, rank, score_finding, validate_config

FX = Path(__file__).parent / "fixtures"


def finding(id="F-1", severity="critical", cve="CVE-2021-44228", file="services/web/pom.xml"):
    return Finding(id=id, rule_id="r", severity=severity, cve=cve, file=file, line=1, title="t")


def run(capsys, *argv):
    code = main([str(a) for a in argv])
    out, err = capsys.readouterr()
    return code, out, err


# --- the six required tests --------------------------------------------------------------

def test_kev_boost():
    cfg = load_config(None)
    f = finding()
    ctx = Context(reach={"F-1": "suspected"}, assets=[Asset("web", "services/web/", prod=True)])
    without, _ = score_finding(f, ctx, cfg)
    ctx.kev = {"CVE-2021-44228"}
    with_kev, _ = score_finding(f, ctx, cfg)
    mults = 1.2 * 1.3
    assert without == pytest.approx(40 * mults)
    assert with_kev - without == pytest.approx(25 * mults)


def test_tie_order():
    ctx, cfg = Context(), load_config(None)
    ranked = rank([finding(id="B-2"), finding(id="A-9"), finding(id="B-1")], ctx, cfg)
    assert [r.score for r in ranked] == [40.0, 40.0, 40.0]
    assert [r.finding.id for r in ranked] == ["A-9", "B-1", "B-2"]
    assert [r.rank for r in ranked] == [1, 2, 3]


def test_rationale_format():
    ctx = Context(kev={"CVE-2021-44228"}, epss={"CVE-2021-44228": 0.82}, reach={"F-1": "reachable"},
                  assets=[Asset("web", "services/", prod=True)])
    score, rationale = score_finding(finding(), ctx, load_config(None))
    # 81 x 1.5 x 1.3 = 157.95 exactly; half-up rounding gives 158.0 (binary floats can give 157.9).
    assert score == 158.0
    assert "KEV-listed" in rationale
    assert str(score) in rationale
    assert rationale == ("critical (40) + KEV-listed (+25) + EPSS 0.82 (+16) x reachable (1.5) "
                         "x prod (1.3) = 158.0")


def test_empty_sarif(capsys):
    assert ingest_sarif(FX / "empty.sarif") == []
    code, out, _ = run(capsys, "rank", "--sast", FX / "empty.sarif", "--format", "json")
    assert code == 0
    assert json.loads(out) == []


def test_bad_config(capsys):
    code, out, err = run(capsys, "rank", "--sast", FX / "sample.sarif", "--config", FX / "bad_config.yaml")
    assert code == 2
    assert "weights.critical" in err and "-40" in err
    assert out == ""


def test_unknown_asset_defaults():
    ctx = Context(assets=load_inventory(FX / "assets.yaml"))
    f = finding(severity="high", cve="", file="unmapped/Thing.java")
    assert ctx.asset_for(f.file) is None
    score, rationale = score_finding(f, ctx, load_config(None))
    assert score == 30.0
    assert "non-prod (1.0)" in rationale and "unknown (1.0)" in rationale


# --- scoring ----------------------------------------------------------------------------

def test_prod_and_internet_facing_multiplier_is_1_5():
    ctx = Context(assets=[Asset("web", "services/web/", prod=True, internet_facing=True)])
    score, rationale = score_finding(finding(cve=""), ctx, load_config(None))
    assert score == 60.0
    assert "prod+internet-facing (1.5)" in rationale


def test_exposed_but_not_prod_adds_only_exposure():
    ctx = Context(assets=[Asset("demo", "services/", prod=False, internet_facing=True)])
    score, _ = score_finding(finding(cve=""), ctx, load_config(None))
    assert score == 48.0


def test_longest_prefix_wins():
    ctx = Context(assets=load_inventory(FX / "assets.yaml"))
    assert ctx.asset_for("services/web/admin/Repo.java").name == "web-admin"
    assert ctx.asset_for("services/web/pom.xml").name == "web"


def test_epss_rounds_to_whole_points_and_missing_is_zero():
    cfg = load_config(None)
    ctx = Context(epss={"CVE-2021-44228": 0.974})
    score, rationale = score_finding(finding(), ctx, cfg)
    assert score == 59.0 and "EPSS 0.97 (+19)" in rationale
    score, _ = score_finding(finding(), Context(epss={"CVE-2021-44228": 0.025}), cfg)
    assert score == 41.0  # 0.025 x 20 = 0.5 rounds half-up to 1
    score, rationale = score_finding(finding(cve="CVE-2099-0001"), ctx, cfg)
    assert score == 40.0 and "EPSS n/a (+0)" in rationale


def test_config_overrides_are_used():
    cfg = validate_config({"weights": {"critical": 50}, "kev_bonus": 0})
    assert cfg["weights"]["high"] == 30
    ctx = Context(kev={"CVE-2021-44228"})
    score, rationale = score_finding(finding(), ctx, cfg)
    assert score == 50.0 and "KEV-listed" not in rationale


@pytest.mark.parametrize("raw, message", [
    ({"weights": {"critical": "high"}}, "weights.critical must be a number"),
    ({"reach_mult": {"reachable": 0}}, "reach_mult.reachable must be greater than 0"),
    ({"asset": {"prod_mult": True}}, "asset.prod_mult must be a number"),
    ({"bonus": 1}, "unknown key(s): bonus"),
    ({"weights": {"severe": 1}}, "unknown key(s) under weights: severe"),
    ({"asset": 1.3}, "asset must be a mapping"),
    (["not", "a", "mapping"], "expected a mapping"),
])
def test_config_validation_messages(raw, message):
    with pytest.raises(FixrankError, match=message.replace("(", r"\(").replace(")", r"\)")):
        validate_config(raw)


def test_defaults_are_not_mutated():
    cfg = load_config(None)
    cfg["weights"]["critical"] = 1
    assert DEFAULT_CONFIG["weights"]["critical"] == 40


# --- ingest -----------------------------------------------------------------------------

def test_sarif_fields_and_severity_sources():
    by_id = {f.id: f for f in ingest_sarif(FX / "sample.sarif")}
    log4j = by_id["F-1"]
    assert (log4j.severity, log4j.cve, log4j.file, log4j.line, log4j.title) == \
        ("critical", "CVE-2021-44228", "services/web/pom.xml", 10, "log4j")
    xss = by_id["java.xss@services/web/View.java:7"]
    assert xss.severity == "medium" and xss.cve == ""
    custom = by_id["g-1"]
    assert custom.severity == "critical" and custom.cve == "CVE-2020-36518" and custom.file == ""


def test_malformed_sarif(capsys):
    with pytest.raises(FixrankError, match="not valid JSON"):
        ingest_sarif(FX / "malformed.sarif")
    code, _, err = run(capsys, "rank", "--sast", FX / "malformed.sarif")
    assert code == 2 and "not valid JSON" in err


def test_sarif_without_runs(tmp_path):
    p = tmp_path / "x.sarif"
    p.write_text('{"version": "2.1.0"}')
    with pytest.raises(FixrankError, match="no 'runs' array"):
        ingest_sarif(p)


def test_missing_file(capsys):
    code, _, err = run(capsys, "rank", "--sast", FX / "nope.sarif")
    assert code == 2 and "file not found" in err


def test_csv_ingest():
    rows = ingest_csv(FX / "findings.csv")
    assert [f.id for f in rows] == ["F-1", "F-2", "F-3"]
    assert rows[0].cve == "CVE-2021-44228" and rows[1].cve == "" and rows[1].line == 5


@pytest.mark.parametrize("content, message", [
    ("id,severity\nF-1,high\n", "missing column"),
    ("id,rule_id,severity,cve,file,line,title\nF-1,r,urgent,,a,1,t\n", "severity 'urgent'"),
    ("id,rule_id,severity,cve,file,line,title\nF-1,r,high,,a,ten,t\n", "line 'ten' is not a number"),
    ("id,rule_id,severity,cve,file,line,title\n,r,high,,a,1,t\n", "empty id"),
])
def test_csv_errors(tmp_path, content, message):
    p = tmp_path / "f.csv"
    p.write_text(content)
    with pytest.raises(FixrankError, match=message):
        ingest_csv(p)


def test_empty_csv(tmp_path):
    p = tmp_path / "f.csv"
    p.write_text("")
    assert ingest_csv(p) == []


# --- enrichment files -------------------------------------------------------------------

def test_real_kev_snapshot_and_epss_comment_line():
    assert "CVE-2021-44228" in load_kev(FX / "kev.csv")
    assert load_epss(FX / "epss.csv") == {"CVE-2021-44228": 0.82, "CVE-2020-36518": 0.0486}
    assert load_reach(FX / "reach.csv") == {"F-1": "reachable", "F-2": "suspected"}


@pytest.mark.parametrize("loader, content, message", [
    (load_kev, "cve,foo\nCVE-1,x\n", "expected column"),
    (load_epss, "cve,epss\nCVE-1,1.5\n", "outside 0..1"),
    (load_epss, "cve,epss\nCVE-1,high\n", "not a number"),
    (load_reach, "finding_id,reachability\nF-1,maybe\n", "reachability 'maybe'"),
])
def test_enrichment_errors(tmp_path, loader, content, message):
    p = tmp_path / "x.csv"
    p.write_text(content)
    with pytest.raises(FixrankError, match=message):
        loader(p)


@pytest.mark.parametrize("content, message", [
    ("assets: nope\n", "top-level 'assets' list"),
    ("assets:\n  - name: a\n", "needs 'name' and 'path_prefix'"),
    ("assets:\n  - {name: a, path_prefix: x/, prod: 'yes'}\n", "prod must be true or false"),
    ("assets: [\n", "invalid YAML"),
])
def test_inventory_errors(tmp_path, content, message):
    p = tmp_path / "a.yaml"
    p.write_text(content)
    with pytest.raises(FixrankError, match=message):
        load_inventory(p)


# --- CLI and rendering ------------------------------------------------------------------

def test_full_cli_json(capsys):
    code, out, err = run(capsys, "rank", "--csv", FX / "findings.csv", "--kev", FX / "kev.csv",
                         "--epss", FX / "epss.csv", "--reach", FX / "reach.csv",
                         "--inventory", FX / "assets.yaml", "--format", "json")
    assert code == 0 and "3 finding(s) ranked" in err
    rows = json.loads(out)
    assert [r["id"] for r in rows] == ["F-1", "F-2", "F-3"]
    # critical 40 + KEV 25 + EPSS 0.82 -> 16, reachable 1.5, prod+exposed 1.5
    assert rows[0]["score"] == 182.3  # 81 x 1.5 x 1.5 = 182.25, half-up
    assert rows[1]["score"] == round(30 * 1.2 * 1.3, 1)
    assert rows[2]["score"] == 10.0


def test_output_file_and_markdown(tmp_path, capsys):
    out_file = tmp_path / "queue.md"
    code, out, err = run(capsys, "rank", "--csv", FX / "findings.csv", "-o", out_file)
    assert code == 0 and out == "" and str(out_file) in err
    text = out_file.read_text()
    assert text.startswith("# Fix queue") and "## Why this order" in text and "| 1 | 40.0 | F-1 |" in text


def test_fail_above_gate(capsys):
    code, _, err = run(capsys, "rank", "--csv", FX / "findings.csv", "--kev", FX / "kev.csv",
                       "--fail-above", "60")
    assert code == 1 and "F-1" in err
    code, _, _ = run(capsys, "rank", "--csv", FX / "findings.csv", "--fail-above", "1000")
    assert code == 0


def test_no_input_is_usage_error(capsys):
    code, _, err = run(capsys, "rank")
    assert code == 2 and "--sast or --csv" in err


def test_help_and_bad_arguments(capsys):
    assert main(["--help"]) == 0
    assert "rank" in capsys.readouterr().out
    assert main(["rank", "--format", "xml", "--csv", "x"]) == 2


def test_markdown_escapes_pipes_and_empty_queue():
    ctx, cfg = Context(), load_config(None)
    f = Finding("a|b", "r", "low", "", "x.py", 1, "title | with pipe")
    md = to_markdown(rank([f], ctx, cfg))
    assert "a\\|b" in md and "title \\| with pipe" in md
    assert "No findings." in to_markdown([])
    assert json.loads(to_json([])) == []


def test_warns_about_reachability_verdicts_that_match_nothing(tmp_path, capsys):
    reach = tmp_path / "reach.csv"
    reach.write_text("finding_id,reachability\nF-1,reachable\nF-l,reachable\n")  # typo: F-l
    code, out, err = run(capsys, "rank", "--csv", FX / "findings.csv", "--reach", reach, "--format", "json")
    assert code == 0
    assert "1 reachability verdict(s) match no finding and were ignored: F-l" in err
    assert json.loads(out)[0]["id"] == "F-1"
