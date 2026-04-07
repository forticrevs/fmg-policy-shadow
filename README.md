# FMG Policy Shadow Analyzer

A FortiManager policy-analysis tool that detects shadowed, redundant, and conflicting firewall policies across one or more FortiManager instances and one or more policy packages.

It is designed around first-match firewall semantics and aims to be conservative, explainable, and scalable:

- conservative: unresolved object dimensions are analyzed with reduced confidence, not skipped or guessed
- explainable: every finding includes why the rule is shadowed, by which higher-priority rule(s), and a weighted risk score
- scalable: package discovery, bulk object retrieval, caching, and concurrent package analysis are built in

## What it produces

For each run, the tool can generate:

- HTML report (with dark mode toggle)
- Excel workbook (`.xlsx`)
- machine-readable JSON export

The reports summarize:

- fully shadowed rules (conflict and redundant)
- partially shadowed / overlapping rules
- unsupported / indeterminate cases
- risk-scored findings with weighted severity
- security profile assignments per policy
- package-level statistics
- raw policy inventory

## Core concepts

The analyzer uses industry-standard definitions of rule shadowing under first-match policy evaluation, aligned with terminology from Tufin SecureTrack, AlgoSec, Google Cloud Firewall Insights, and PCI DSS guidelines:

- **Fully Shadowed (Conflict)**: a higher-priority rule with a *different* action completely covers the lower-priority rule's match space. The shadowed rule is unreachable. *(Industry: contradictory shadow, conflicting rule)*
- **Partially Shadowed (Conflict)**: a higher-priority rule with a *different* action covers part of the lower-priority rule's traffic. *(Industry: partial shadow)*
- **Fully Shadowed (Redundant)**: a higher-priority rule with the *same* action completely covers the lower-priority rule. The rule is redundant and can be safely removed. *(Industry: redundant rule, covered rule)*
- **Partially Overlapping (Redundant)**: a higher-priority rule with the *same* action covers part of the lower-priority rule's traffic. *(Industry: partial redundancy)*
- **Indeterminate (Unresolved Objects)**: overlap detected but unresolved objects prevent classification.

Findings are classified as one of:

- `full_conflict_shadow`
- `partial_conflict_shadow`
- `full_redundant_coverage`
- `partial_redundant_overlap`
- `indeterminate_due_to_unsupported_objects`

### Risk scoring

Each finding receives a risk score (0–10) computed from weighted factors:

| Factor | Weight | Rationale |
|--------|--------|-----------|
| Interface overlap | Minimal | Common and expected between policies |
| Address object overlap | High | Indicates significant match-space coverage |
| Address + service + schedule overlap | Highest | Represents most complete shadowing |
| Address breadth (host → /24 → /16 → /8 → any) | Multiplier (0.8x–2.0x) | Broader rules affect more traffic |
| Action conflict (deny vs accept) | Multiplier (1.3x) | Security implications |
| Fully unreachable rule | Bonus (+1.0) | Rule will never match |
| Composite shadowing | Bonus (+0.5) | Multiple rules combine to shadow |

Risk scores can upgrade severity classifications (but never downgrade):
- ≥ 9.0 → CRITICAL
- ≥ 7.0 → HIGH
- ≥ 4.0 → MEDIUM

## Project layout

```text
fmg-policy-shadow/
├── run_shadow.py                 # executable entry point
├── README.md
├── requirements.txt              # runtime dependencies (openpyxl optional)
├── requirements-dev.txt          # dev/test dependencies
├── fmg_shadow/
│   ├── __init__.py
│   ├── models.py                 # canonical data types, risk scoring, result models
│   ├── client.py                 # FMG JSON-RPC client
│   ├── discovery.py              # ADOM/package discovery
│   ├── policy_fetch.py           # policy retrieval + security profile extraction
│   ├── objects.py                # object retrieval + ISDB resolution + normalization
│   ├── analyzer.py               # pairwise + composite shadow detection + risk scoring
│   ├── reporting.py              # HTML (dark mode) / XLSX / JSON reports
│   ├── orchestrator.py           # multi-package / multi-FMG workflow
│   └── cli_app.py                # CLI parser and runtime config
└── tests/
    ├── test_models.py
    └── test_analyzer.py
```

## Architecture overview

### 1) FortiManager client

`fmg_shadow.client.FMGClient` handles:

- username/password session authentication
- API token authentication
- JSON-RPC request construction
- retry / backoff behavior
- batch requests
- SSL verification toggling for self-signed lab deployments

### 2) Discovery

`fmg_shadow.discovery` enumerates:

- ADOMs
- policy packages
- folder-nested packages
- package scope members

### 3) Object retrieval and normalization

`fmg_shadow.objects.ObjectResolver` bulk-fetches and normalizes:

- addresses (ipmask, iprange, groups, VIPs, VIP groups)
- address groups, including nested groups with exclude-member subtraction
- services and service groups
- schedules (recurring, onetime, groups)
- **Internet Service Database (ISDB) entries** — multi-step resolution:
  1. Fetch ISDB catalog from `/pm/config/adom/{adom}/_fdsdb/internet-service`
  2. Map internet-service-name objects to ISDB IDs
  3. Fetch actual IP range + port/protocol entries for each ISDB ID
  4. Convert entries to resolved AddressSet + ServiceSet for downstream analysis

Normalized internal forms include:

- IP intervals / address unions with breadth categorization
- protocol-aware service specs
- interface sets
- canonical schedule representations
- install scope sets

### 4) Policy fetch

`fmg_shadow.policy_fetch` retrieves package policies in evaluation order and:

- preserves raw references for later object resolution
- extracts **security profile assignments** (av-profile, webfilter-profile, ips-sensor, application-list, ssl-ssh-profile, dnsfilter-profile, emailfilter-profile, dlp-profile, file-filter-profile, voip-profile, casb-profile, waf-profile, profile-protocol-options, utm-status)

### 5) Analysis engine

`fmg_shadow.analyzer.ShadowAnalyzer` performs:

- pairwise higher-priority vs lower-priority comparison across 6 dimensions
- full vs partial coverage detection
- same-action vs different-action classification
- install-scope overlap enforcement
- composite / union shadow detection across multiple higher-priority rules
- **partial analysis of policies with unresolved objects** — resolved dimensions are analyzed normally, unresolved dimensions are marked indeterminate, confidence is downgraded
- **weighted risk scoring** per finding based on dimension overlap severity, address breadth, action conflict, and reachability

### 6) Reporting

`fmg_shadow.reporting` generates:

- self-contained HTML reports with **dark mode toggle** (persisted via localStorage)
- structured explanation sections with formatted findings, color-coded dimensions, and risk scores
- polished Excel workbooks using `openpyxl` (with security profile columns)
- structured JSON suitable for downstream automation or trend tracking

Reports include industry-standard terminology and compliance context (PCI DSS 1.1.7, CIS Controls, NIST SP 800-41, ISO 27001).

## Supported object handling

### Addresses

Supported directly:

- IPv4 subnet / host (`ipmask`)
- IPv4 ranges (`iprange`)
- nested address groups
- group exclusions where present
- VIPs (external IP / extip)
- VIP groups
- reserved objects like `all`

Handled conservatively / flagged as unresolved:

- FQDN objects
- wildcard FQDN / wildcard address objects
- dynamic objects
- geography-based address objects
- MAC-based, route-tag, interface-subnet addresses

### Internet Service Database (ISDB)

Policies using `internet-service` or `internet-service-src` are now resolved via multi-step ISDB lookup:

1. Internet-service-name → ISDB ID mapping
2. ISDB ID → IP ranges + port/protocol entries
3. Entries converted to AddressSet (IPs) + ServiceSet (ports/protocols)

If the ISDB entries cannot be fetched, the objects fall back to unresolved/indeterminate status.

### Services

Supported directly:

- TCP ranges
- UDP ranges
- SCTP ranges
- raw IP protocol numbers
- ICMP type / code
- nested service groups
- `ALL`

### Schedules

Supported:

- `always`
- recurring schedules
- one-time schedules
- schedule groups (conservative handling)

### Interfaces

Supported directly:

- exact interface matching
- `any`
- interface overlap / containment checks for explicit interface sets

### Install scope

Mandatory in analysis:

- package default scope
- per-policy `_scope` / install target overlap
- rules with non-overlapping targets are not compared for shadowing

### Security profiles

Captured and displayed in reports (not used in shadow analysis):

- Antivirus, Web Filter, IPS, Application Control
- SSL/SSH Inspection, DNS Filter, Email Filter
- DLP, File Filter, VoIP, CASB, WAF
- Profile Protocol Options, UTM Status

## Algorithm summary

For each lower-priority rule `Rj`, the analyzer compares it against higher-priority effective rules `Ri` where `i < j` and install scope overlaps.

The effective rule domain is compared across six dimensions:

- `srcintf`
- `dstintf`
- `srcaddr`
- `dstaddr`
- `service`
- `schedule`

### Pairwise analysis

For each higher-priority/lower-priority rule pair:

- if any mandatory dimension has no overlap, there is no shadow relationship
- if all dimensions overlap and the higher-priority rule fully contains the lower-priority rule, the finding is full shadow / full redundancy
- if overlap exists but full containment is not proven, the finding is partial shadow / partial redundancy
- if object semantics are unresolved, the tool downgrades confidence and may classify as indeterminate

### Composite shadow analysis

The analyzer also attempts to detect cases where multiple higher-priority rules together cover a lower-priority rule, even when no single rule fully contains it.

This is implemented using union / subtraction logic over normalized address space and pruned candidate sets.

### Risk score computation

After classification, each finding receives a risk score (0–10) computed as:

1. **Base score** from finding type (8.0 for full conflict, 6.0 for partial conflict, 3.0 for full redundant, 1.5 for partial redundant, 2.0 for indeterminate)
2. **Action conflict multiplier** (×1.3 when actions differ)
3. **Address breadth multiplier** (×0.8 for single host up to ×2.0 for `any`/0.0.0.0/0)
4. **Dimension overlap bonus** (+2.0 for addr+svc+schedule, +1.5 for addr+svc, +1.0 for addr only; interface overlap adds nothing — it's expected)
5. **Fully unreachable bonus** (+1.0)
6. **Composite finding bonus** (+0.5)

Score capped at 10.0. Higher scores can upgrade severity labels but never downgrade them.

## Installation

### Requirements

- Python 3.11+ recommended
- network access to target FortiManager(s)
- valid FortiManager credentials or API token

### Install dependencies

```bash
pip install -r requirements.txt
```

The core tool has **zero mandatory third-party dependencies** (stdlib only). The `requirements.txt` includes `openpyxl` for optional Excel export. If `openpyxl` is not installed, HTML and JSON still work and the tool will skip XLSX generation with a warning.

For development/testing:

```bash
pip install -r requirements-dev.txt
```

## Running the tool

### Basic examples

Analyze all packages in an ADOM:

```bash
python3 run_shadow.py \
  --fmg 10.0.0.1 \
  --adom root \
  --all-packages \
  --username admin \
  --password 'yourpassword' \
  --insecure \
  --output-dir ./reports
```

Analyze a specific package:

```bash
python3 run_shadow.py \
  --fmg 10.0.0.1 \
  --adom root \
  --package MyPolicyPackage \
  --username admin \
  --password 'yourpassword' \
  --insecure
```

Analyze packages matching a regex:

```bash
python3 run_shadow.py \
  --fmg 10.0.0.1 \
  --adom root \
  --package-regex 'edge-.*' \
  --username admin \
  --password 'yourpassword' \
  --insecure
```

Analyze multiple FortiManagers:

```bash
python3 run_shadow.py \
  --fmg 10.0.0.1,10.0.0.2 \
  --adom root \
  --all-packages \
  --token YOUR_API_TOKEN \
  --insecure
```

### Credentials via environment variables

```bash
export FMG_USER=admin
export FMG_PASSWORD='yourpassword'
python3 run_shadow.py --fmg 10.0.0.1 --adom root --all-packages --insecure
```

Or with token auth:

```bash
export FMG_TOKEN=your-api-token
python3 run_shadow.py --fmg 10.0.0.1 --adom root --all-packages --insecure
```

## CLI options

```text
--fmg               FMG host (repeatable or comma-separated)
--fmg-file          file containing one FMG per line
--adom              ADOM name (default: root)
--package           specific package name (repeatable)
--all-packages      analyze every package in the ADOM
--package-regex     filter discovered packages by regex
--username / -u     username
--password / -p     password
--token             API token
--output-dir / -o   report output directory
--format            html,xlsx,json
--workers           concurrent package workers (default: 4)
--include-disabled  include disabled rules in analysis
--strict-unsupported fail instead of flagging unresolved semantics
--insecure          disable certificate verification
--no-insecure       enforce certificate verification
--verbose           info logging
--debug             debug logging
```

## Report outputs

### HTML

Executive-friendly report with:

- **dark mode toggle** (☾/☼ button, persisted in localStorage)
- summary dashboard with risk-aware statistics
- package summaries with finding counts
- **findings grouped by shadowed policy** — each policy gets one expandable section containing:
  - summary banner with worst severity, finding type, confidence levels, relationship count, and max risk score
  - category pills (N conflicts, N redundant, N indeterminate)
  - compact relationships table with all shadow/overlap entries as rows
  - click-to-expand detail for each relationship (explanation, overlap table, risk factors)
  - composite shadow explanations render the shadowing rule list as a scrollable table instead of inline text
- severity and finding-type coloring (industry-standard labels)
- methodology section with compliance context
- limitations section

### XLSX

Workbook sheets:

- Summary
- Findings (with risk scores)
- Packages
- Unsupported Objects
- Policy Inventory (with security profiles)

Formatting includes:

- freeze panes
- autofilter
- wrapped text
- styled headers
- color-coded severity cells

### JSON

Machine-readable output including:

- run metadata
- summary counts
- package results with risk scores and risk factors
- findings with all dimension overlaps
- security profile assignments per policy
- unsupported objects
- error summary

## Testing

Run the full test suite:

```bash
python3 -m pytest tests/ -q
```

Current test coverage includes:

- model interval / set algebra
- address breadth categorization
- pairwise shadow detection
- composite shadow detection
- install-scope separation
- schedule overlap handling
- disabled-rule exclusion
- section-title exclusion
- same-action redundancy vs different-action conflict classification

## Known limitations

This tool is intentionally conservative. It does not claim certainty when object semantics cannot be proven.

Current limitations include:

- FQDN and wildcard-style address semantics are flagged as unresolved — policies containing them are still analyzed on their resolved dimensions with reduced confidence
- Internet-service (ISDB) entries are resolved where the FortiGuard database is accessible; entries that cannot be fetched remain indeterminate
- schedule algebra is conservative rather than mathematically exhaustive in all cases
- composite analysis is heuristic and pruned for performance
- policy shadowing is only evaluated within overlapping install scope
- application-layer criteria (App Control, URL filtering, etc.) are NOT considered in shadow analysis — the analysis is limited to L3/L4 match dimensions. Security profile assignments are captured and displayed for context.
- FortiManager- and version-specific response shapes may vary, especially for advanced features like `get referred`
- VIP/DNAT destination translations are resolved where possible but complex scenarios may be missed
- Central SNAT/DNAT policies are not included in the analysis

## Troubleshooting

### Error: `FMGClient.get() got an unexpected keyword argument 'range'`

This was caused by a caller using `range=` while the client API expected `range_=`. The client now tolerates the alias and the discovery layer uses the correct parameter.

### Self-signed certificate issues

Use:

```bash
--insecure
```

### No Excel file generated

Install `openpyxl`:

```bash
pip install openpyxl
```

## License

MIT
