# fixrank

Rank security findings by what to fix first, and show the arithmetic behind every position in the queue.

[![ci](https://github.com/SP-Invest-Pvt/fixrank/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

## The problem

AppSec queues are sorted by severity. Severity says how bad a vulnerability could be in general, not what to fix on Monday morning. A critical CVE in a load-test tool and the same CVE in an internet-facing payment service get the same label. A high-severity SQL injection that an attacker can actually reach sits below a dozen unreachable criticals.

The signals that change the order already exist: CISA's Known Exploited Vulnerabilities (KEV) catalog says what attackers are using, EPSS estimates how likely exploitation is in the next 30 days, reachability analysis says whether your code calls the vulnerable path, and your asset inventory says what is in production and exposed. fixrank combines them with one fixed formula and writes the reason next to every score, so the order can be defended in a review.

## The formula

```
score = round((base + kev_bonus + epss_add) * reach_mult * asset_mult, 1)
```

| Term | Value (defaults, all configurable) |
|---|---|
| `base` | severity weight: critical 40, high 30, medium 20, low 10 |
| `kev_bonus` | 25 if the finding's CVE is in the KEV catalog, else 0 |
| `epss_add` | `round(epss * 20)`; a missing EPSS score adds 0 |
| `reach_mult` | reachable 1.5, suspected 1.2, unknown 1.0 |
| `asset_mult` | 1.3 if the asset is in production, else 1.0; plus 0.2 if it is internet-facing (so 1.5 for production and exposed) |

Arithmetic is exact decimal with round-half-up, so anyone can recompute a score by hand: `(40 + 25 + 16) x 1.5 x 1.3 = 157.95`, which rounds to `158.0`. Plain binary floating point gives 157.9 or 158.0 depending on the order of the multiplications, which is not acceptable for a number you have to defend.

Ties are broken by finding id, ascending, so the same inputs always produce the same queue.

## Demo

The `examples/` folder holds a small but realistic backlog: a dependency scan and a Semgrep run as SARIF, two pentest findings as CSV, reachability verdicts and an asset inventory. `examples/kev.csv` holds rows copied verbatim from the CISA catalog, and `examples/epss.csv` holds live EPSS scores fetched from FIRST's API on 2026-09-26.

```
$ python -m fixrank rank --sast examples/findings.sarif --csv examples/pentest.csv \
    --kev examples/kev.csv --epss examples/epss.csv --reach examples/reach.csv \
    --inventory examples/assets.yaml --config examples/config.yaml -o queue.md
fixrank: 12 finding(s) ranked -> queue.md
$ echo $?
0
```

`queue.md`:

| # | Score | ID | Severity | CVE | Location | Title |
|---:|---:|---|---|---|---|---|
| 1 | 191.3 | SCA-001 | critical | CVE-2021-44228 | services/payments-api/pom.xml:41 | log4j-core 2.14.1 is vulnerable to Log4Shell |
| 2 | 132.6 | SCA-003 | critical | CVE-2022-22965 | services/admin-portal/pom.xml:52 | spring-beans 5.3.17 is vulnerable to Spring4Shell |
| 3 | 110.5 | SCA-002 | critical | CVE-2021-44228 | services/billing-batch/pom.xml:37 | log4j-core 2.14.1 is vulnerable to Log4Shell |
| 4 | 110.5 | SCA-005 | critical | CVE-2023-46604 | services/billing-batch/pom.xml:44 | activemq-client 5.15.15 is vulnerable to CVE-2023-46604 |
| 5 | 90.0 | SCA-004 | critical | CVE-2022-42889 | services/payments-api/pom.xml:58 | commons-text 1.9 is vulnerable to Text4Shell |
| 6 | 67.5 | PT-001 | high | - | services/payments-api/src/main/java/com/acme/pay/InvoiceController.java:40 | Invoice download does not check the owning account |
| 7 | 67.5 | SAST-001 | high | - | services/payments-api/src/main/java/com/acme/pay/OrderRepository.java:88 | Order id from the request is concatenated into SQL |
| 8 | 31.2 | SAST-002 | medium | - | services/admin-portal/src/main/java/com/acme/admin/ProfileView.java:31 | Display name written to the page without escaping |
| 9 | 31.0 | SCA-006 | high | CVE-2020-36518 | tools/load-test/pom.xml:22 | jackson-databind 2.12.1 is vulnerable to CVE-2020-36518 |
| 10 | 20.0 | SAST-003 | medium | - | tools/load-test/src/Config.java:12 | Password literal in load test config |
| 11 | 13.0 | PT-002 | low | - | services/admin-portal/src/main/resources/application.yml:9 | Stack traces returned to the browser |
| 12 | 13.0 | SAST-004 | low | - | services/billing-batch/src/main/java/com/acme/billing/Export.java:64 | MD5 checksum on invoice export |

Each score comes with its working (from the same file):

```
1. `SCA-001`: critical (40) + KEV-listed (+25) + EPSS 1.00 (+20) x reachable (1.5) x prod+internet-facing (1.5) = 191.3
2. `SCA-003`: critical (40) + KEV-listed (+25) + EPSS 1.00 (+20) x suspected (1.2) x prod (1.3) = 132.6
5. `SCA-004`: critical (40) + EPSS 1.00 (+20) x unknown (1.0) x prod+internet-facing (1.5) = 90.0
9. `SCA-006`: high (30) + EPSS 0.05 (+1) x unknown (1.0) x non-prod (1.0) = 31.0
```

What changed compared with a severity sort: the same Log4Shell CVE lands at #1 in the exposed payment API and at #3 in an internal batch job. Text4Shell has a near-certain EPSS score but is not in KEV and has no reachability evidence, so it sits below four KEV-listed criticals. The jackson-databind "high" in a non-production load-test tool falls to #9, below a medium XSS in the admin portal.

JSON output for pipelines:

```
$ python -m fixrank rank --sast examples/findings.sarif --kev examples/kev.csv --epss examples/epss.csv --reach examples/reach.csv --inventory examples/assets.yaml --format json | head -12
[
  {
    "rank": 1,
    "score": 191.3,
    "rationale": "critical (40) + KEV-listed (+25) + EPSS 1.00 (+20) x reachable (1.5) x prod+internet-facing (1.5) = 191.3",
    "id": "SCA-001",
    "rule_id": "CVE-2021-44228",
    "severity": "critical",
    "cve": "CVE-2021-44228",
    "file": "services/payments-api/pom.xml",
    "line": 41,
    "title": "log4j-core 2.14.1 is vulnerable to Log4Shell"
```

As a CI gate, and what a bad config looks like:

```
$ python -m fixrank rank --sast examples/findings.sarif --kev examples/kev.csv --epss examples/epss.csv --reach examples/reach.csv --inventory examples/assets.yaml --fail-above 150 > /dev/null
fixrank: 10 finding(s) ranked
fixrank: 1 finding(s) at or above 150: SCA-001
$ echo $?
1

$ python -m fixrank rank --sast examples/findings.sarif --config tests/fixtures/bad_config.yaml
fixrank: error: config: weights.critical must be 0 or more, got -40
$ echo $?
2
```

## Install

Python 3.11 or newer. The only dependency is PyYAML, for the inventory and config files.

```bash
git clone https://github.com/SP-Invest-Pvt/fixrank && cd fixrank
pip install -e ".[test]"
pytest
python -m fixrank --help
```

## Usage

```
python -m fixrank rank --sast findings.sarif [--csv findings.csv] --kev kev.csv --epss epss.csv \
    --reach reach.csv --inventory assets.yaml --config config.yaml [-o queue.md] [--format md|json] \
    [--fail-above SCORE]
```

At least one of `--sast` or `--csv` is required. Everything else is optional: leave out a context file and that term simply contributes nothing (no KEV bonus, no EPSS points, reachability `unknown`, assets non-prod).

Exit codes: `0` ranked, `1` at least one finding scored at or above `--fail-above`, `2` usage or configuration error (bad value, malformed file, missing file). Logs go to stderr and the queue goes to stdout unless `-o` is given.

## Inputs

| Flag | Format |
|---|---|
| `--sast` | SARIF 2.1.0. Reads `runs[].results[]`: `ruleId`, `level` and `locations[0].physicalLocation`. Severity comes from `properties.severity` if set, else the rule's CVSS `security-severity`, else the level (`error` high, `warning` medium, `note` low). The CVE comes from `properties.cve`, the rule id or the message. The finding id is `guid`, else `properties.id`, else `rule@file:line`. |
| `--csv` | Columns `id,rule_id,severity,cve,file,line,title`, for pentest reports or tools without SARIF. |
| `--kev` | The CISA KEV CSV; only the `cveID` column is used. |
| `--epss` | Columns `cve,epss` with `epss` between 0 and 1. Comment lines starting with `#` (FIRST's export has one) are skipped. |
| `--reach` | Columns `finding_id,reachability` with `reachable`, `suspected` or `unknown`. |
| `--inventory` | YAML `assets: [{name, path_prefix, prod, internet_facing}]`. A finding belongs to the asset with the longest `path_prefix` that its file starts with; a file that matches nothing is non-prod and not exposed. |

### Refreshing KEV and EPSS

Both feeds change daily. Fetch them before a ranking run rather than committing them:

```bash
mkdir -p data
curl -sSfL -o data/kev.csv https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
curl -sSfL https://epss.empiricalsecurity.com/epss_scores-current.csv.gz | gunzip > data/epss.csv
python -m fixrank rank --sast findings.sarif --kev data/kev.csv --epss data/epss.csv ...
```

The full EPSS file has a `percentile` column as well; fixrank ignores extra columns. Ranking the demo against the complete feeds (379,843 EPSS rows, 1,726 KEV entries on 2026-09-26) takes under a second. `data/` is git-ignored.

## Config reference

```yaml
weights: {critical: 40, high: 30, medium: 20, low: 10}
kev_bonus: 25
epss_factor: 20
reach_mult: {reachable: 1.5, suspected: 1.2, unknown: 1.0}
asset: {prod_mult: 1.3, exposed_add: 0.2}
```

Any key you leave out keeps its default. The config is checked when it loads. Unknown keys, non-numbers, negative weights or bonuses, and multipliers of zero or less are rejected with exit code 2 and a message naming the key.

## Limitations

* **The weights are a starting point, not a calibrated model.** They encode a reasonable policy (known exploitation beats predicted exploitation, and exposure multiplies) but have not been fitted to incident data. Change them in the config and keep the file under review like any other policy.
* **Reachability is an input, not something fixrank works out.** It trusts the verdicts in `--reach`. Tools such as [reachproof](https://github.com/SP-Invest-Pvt/reachproof) produce them; without that file, every finding counts as `unknown`.
* **Asset matching is by path prefix.** That suits a monorepo. For findings from several repositories, give each `path_prefix` a repository-qualified path in both the scan and the inventory.
* **One CVE per finding.** SCA findings that bundle several CVEs should be split upstream; fixrank scores one CVE per finding.
* **EPSS is a probability, not a verdict.** A score near 1.0 for a CVE without a public exploit in your context still only adds up to 20 points, by design.

## Licence

MIT.
