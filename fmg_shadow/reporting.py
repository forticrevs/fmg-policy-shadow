"""
Report generation for FMG Policy Shadow Analysis.

Produces HTML, Excel (openpyxl), and JSON outputs from RunResult data.
"""

from __future__ import annotations

import json
import os
from collections import OrderedDict
from datetime import datetime
from typing import Any

from .models import (
    CanonicalPolicy,
    FindingType,
    PackageResult,
    RunResult,
    ShadowFinding,
)

# Optional openpyxl import
try:
    import openpyxl
    from openpyxl.styles import (
        Alignment,
        Border,
        Font,
        PatternFill,
        Side,
    )
    from openpyxl.utils import get_column_letter
    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107",
    "LOW": "#0d6efd",
    "INFO": "#6c757d",
}

FINDING_TYPE_LABELS = {
    "full_conflict_shadow": "Full Conflict Shadow",
    "partial_conflict_shadow": "Partial Conflict Shadow",
    "full_redundant_coverage": "Full Redundant Coverage",
    "partial_redundant_overlap": "Partial Redundant Overlap",
    "indeterminate_due_to_unsupported_objects": "Indeterminate",
}

FINDING_TYPE_COLORS = {
    "full_conflict_shadow": "#dc3545",
    "partial_conflict_shadow": "#e8747c",
    "full_redundant_coverage": "#198754",
    "partial_redundant_overlap": "#0dcaf0",
    "indeterminate_due_to_unsupported_objects": "#adb5bd",
}


# ===================================================================
# JSON Report
# ===================================================================

def generate_json_report(run_result: RunResult, output_path: str) -> str:
    """Generate a machine-readable JSON report.

    Returns the output file path.
    """
    data: dict[str, Any] = {
        "tool_version": run_result.tool_version,
        "run_timestamp": run_result.run_timestamp,
        "elapsed_seconds": run_result.elapsed_seconds,
        "summary_counts": run_result.summary_counts(),
        "package_results": [],
        "errors": run_result.errors,
    }

    for pr in run_result.package_results:
        pkg: dict[str, Any] = {
            "fmg": pr.fmg,
            "adom": pr.adom,
            "package": pr.package,
            "total_policies": pr.total_policies,
            "effective_policies": pr.effective_policies,
            "elapsed_seconds": pr.elapsed_seconds,
            "finding_counts": {
                "full_conflict_shadow": pr.full_conflict_count,
                "partial_conflict_shadow": pr.partial_conflict_count,
                "full_redundant_coverage": pr.full_redundant_count,
                "partial_redundant_overlap": pr.partial_redundant_count,
                "indeterminate": pr.indeterminate_count,
                "total": len(pr.findings),
            },
            "findings": [f.to_dict() for f in pr.findings],
            "policies": _serialize_policies(pr.policies),
            "unsupported_objects": pr.unsupported_objects,
            "errors": pr.errors,
        }
        data["package_results"].append(pkg)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)

    return output_path


def _serialize_policies(policies: list[CanonicalPolicy]) -> list[dict]:
    """Serialize a list of CanonicalPolicy to dicts for JSON."""
    result = []
    for p in policies:
        raw = p.raw_data or {}
        result.append({
            "policyid": p.policyid,
            "name": p.name,
            "seq_num": p.seq_num,
            "action": p.action.value if p.action else "",
            "status": p.status,
            "comments": p.comments,
            "package": p.package,
            "fmg": p.fmg,
            "adom": p.adom,
            "srcintf": p.srcintf.describe() if p.srcintf else "",
            "dstintf": p.dstintf.describe() if p.dstintf else "",
            "srcaddr": p.srcaddr.describe() if p.srcaddr else "",
            "dstaddr": p.dstaddr.describe() if p.dstaddr else "",
            "service": p.service.describe() if p.service else "",
            "schedule": p.schedule.describe() if p.schedule else "",
            "srcaddr_objects": raw.get("_raw_srcaddr", []),
            "dstaddr_objects": raw.get("_raw_dstaddr", []),
            "service_objects": raw.get("_raw_service", []),
            "schedule_objects": raw.get("_raw_schedule", []),
            "security_profiles": p.security_profiles,
            "has_unresolved": p.has_unresolved,
        })
    return result


# ===================================================================
# HTML Report
# ===================================================================

def generate_html_report(run_result: RunResult, output_path: str) -> str:
    """Generate a self-contained HTML report.

    Returns the output file path.
    """
    counts = run_result.summary_counts()
    timestamp = run_result.run_timestamp or datetime.now().isoformat()

    # Gather scope info
    fmgs = sorted(set(pr.fmg for pr in run_result.package_results))
    adoms = sorted(set(pr.adom for pr in run_result.package_results))
    packages = sorted(set(pr.package for pr in run_result.package_results))

    html_parts: list[str] = []
    html_parts.append(_html_head(timestamp))
    html_parts.append(_html_header(timestamp, run_result.tool_version))
    html_parts.append(_html_scope(fmgs, adoms, packages))
    html_parts.append(_html_dashboard(counts))
    html_parts.append(_html_package_cards(run_result.package_results))
    html_parts.append(_html_findings_detail(run_result.package_results))
    html_parts.append(_html_methodology())
    html_parts.append(_html_limitations())
    html_parts.append(_html_footer())

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(html_parts))

    return output_path


def _esc(text: Any) -> str:
    """Escape HTML special characters."""
    s = str(text) if text is not None else ""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#6c757d")
    text_color = "#fff" if severity != "MEDIUM" else "#212529"
    return (
        f'<span style="display:inline-block;padding:2px 8px;border-radius:4px;'
        f'font-size:0.8em;font-weight:bold;color:{text_color};'
        f'background-color:{color}">{_esc(severity)}</span>'
    )


def _finding_type_badge(ftype: str) -> str:
    color = FINDING_TYPE_COLORS.get(ftype, "#adb5bd")
    label = FINDING_TYPE_LABELS.get(ftype, ftype)
    return (
        f'<span style="display:inline-block;padding:2px 8px;border-radius:4px;'
        f'font-size:0.8em;color:#fff;background-color:{color}">{_esc(label)}</span>'
    )


def _format_explanation(text: str) -> str:
    """Convert plain-text explanation into structured HTML.

    Handles a special SHADOWING_RULES: block (generated by composite
    explanations) by rendering it as a compact, scrollable table instead
    of dumping all policy references inline.
    """
    if not text:
        return '<div class="explanation-block"><p class="intro">No explanation available.</p></div>'

    # Dimension keywords to color-code
    _DIM_KEYWORDS = {
        "srcintf": "#0d6efd",
        "dstintf": "#0d6efd",
        "srcaddr": "#198754",
        "dstaddr": "#198754",
        "service": "#6f42c1",
        "schedule": "#fd7e14",
    }

    def _highlight(line: str) -> str:
        """Bold key terms and color-code dimension names in a line."""
        esc = _esc(line)
        # Bold key phrases
        for phrase in ("FULLY SHADOWED", "FULLY COVERED", "PARTIALLY SHADOWED",
                       "PARTIALLY OVERLAPS", "INDETERMINATE", "COMPOSITE UNION",
                       "NEVER be reached", "DIFFERENT action", "SAME action",
                       "UNREACHABLE", "redundant"):
            esc = esc.replace(_esc(phrase), f"<strong>{_esc(phrase)}</strong>")
        # Color-code dimension names
        for dim, color in _DIM_KEYWORDS.items():
            esc = esc.replace(dim, f'<span style="color:{color};font-weight:600">{dim}</span>')
        return esc

    # Separate the SHADOWING_RULES block if present
    rules_html = ""
    main_text = text
    if "\nSHADOWING_RULES:" in text:
        main_text, rules_raw = text.split("\nSHADOWING_RULES:", 1)
        rule_lines = [l.strip() for l in rules_raw.strip().split("\n") if l.strip()]
        if rule_lines:
            rules_html = (
                '  <details class="rules-details" open>\n'
                '    <summary style="cursor:pointer;font-weight:600;margin:8px 0 4px 0;'
                'color:var(--text-color);font-size:0.9em;">'
                f'Shadowing Rules ({len(rule_lines)})</summary>\n'
                '    <div style="max-height:260px;overflow-y:auto;border:1px solid '
                'var(--border-color);border-radius:4px;margin-top:4px;">\n'
                '    <table style="width:100%;border-collapse:collapse;font-size:0.85em;">\n'
                '      <thead><tr style="position:sticky;top:0;'
                'background:var(--table-header-bg);z-index:1;">'
                '<th style="padding:4px 8px;text-align:left;border-bottom:1px solid '
                'var(--border-color);">Seq</th>'
                '<th style="padding:4px 8px;text-align:left;border-bottom:1px solid '
                'var(--border-color);">Policy ID</th>'
                '<th style="padding:4px 8px;text-align:left;border-bottom:1px solid '
                'var(--border-color);">Name</th>'
                '<th style="padding:4px 8px;text-align:left;border-bottom:1px solid '
                'var(--border-color);">Action</th>'
                '</tr></thead>\n<tbody>\n'
            )
            for rl in rule_lines:
                parts = rl.split("|", 3)
                if len(parts) == 4:
                    seq, pid, name, action = parts
                    action_color = "#198754" if action == "accept" else "#dc3545"
                    rules_html += (
                        f'<tr style="border-bottom:1px solid var(--border-color);">'
                        f'<td style="padding:3px 8px;">{_esc(seq)}</td>'
                        f'<td style="padding:3px 8px;font-family:monospace;">{_esc(pid)}</td>'
                        f'<td style="padding:3px 8px;">{_esc(name)}</td>'
                        f'<td style="padding:3px 8px;color:{action_color};'
                        f'font-weight:600;">{_esc(action)}</td></tr>\n'
                    )
            rules_html += '</tbody></table>\n</div>\n</details>\n'

    # Split into intro paragraph and bullet-point details
    parts = main_text.split("\n", 1)
    intro = parts[0].strip()
    html = '<div class="explanation-block">\n'
    html += f'  <p class="intro">{_highlight(intro)}</p>\n'

    if len(parts) > 1 and parts[1].strip():
        lines = parts[1].strip().split("\n")
        bullets = [l.strip().lstrip("- ").strip() for l in lines if l.strip().startswith("-") or l.strip().startswith("  -")]
        if bullets:
            html += "  <ul>\n"
            for b in bullets:
                html += f"    <li>{_highlight(b)}</li>\n"
            html += "  </ul>\n"

    if rules_html:
        html += rules_html

    html += "</div>"
    return html


def _html_head(timestamp: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FMG Policy Shadow Analysis Report - {_esc(timestamp)}</title>
<style>
  :root {{
    --bg-body: #f8f9fa;
    --text-color: #212529;
    --heading-color: #1a1a2e;
    --heading-color-2: #16213e;
    --accent-color: #0d6efd;
    --card-bg: #fff;
    --shadow-color: rgba(0,0,0,0.1);
    --table-header-bg: #e9ecef;
    --hover-bg: #f1f3f5;
    --summary-bg: #e9ecef;
    --summary-hover-bg: #dee2e6;
    --border-color: #dee2e6;
    --pre-bg: #f8f9fa;
    --methodology-bg: #eef;
    --limitations-bg: #fff3cd;
    --pill-bg: #e9ecef;
    --muted-text: #6c757d;
    --overlap-th-bg: #f0f0f0;
    --pkg-group-header-color: #16213e;
    --header-gradient-start: #1a1a2e;
    --header-gradient-end: #16213e;
    --header-subtitle-color: #adb5bd;
  }}
  body.dark {{
    --bg-body: #0d1117;
    --text-color: #e6edf3;
    --heading-color: #e6edf3;
    --heading-color-2: #adbac7;
    --accent-color: #58a6ff;
    --card-bg: #161b22;
    --shadow-color: rgba(0,0,0,0.4);
    --table-header-bg: #1a1a2e;
    --hover-bg: #1c2333;
    --summary-bg: #1a1a2e;
    --summary-hover-bg: #16213e;
    --border-color: #30363d;
    --pre-bg: #161b22;
    --methodology-bg: #1a1a2e;
    --limitations-bg: #2d2a1e;
    --pill-bg: #1a1a2e;
    --muted-text: #adbac7;
    --overlap-th-bg: #1a1a2e;
    --pkg-group-header-color: #adbac7;
    --header-gradient-start: #0d1117;
    --header-gradient-end: #161b22;
    --header-subtitle-color: #adbac7;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         line-height: 1.6; color: var(--text-color); background: var(--bg-body); padding: 20px;
         transition: background 0.3s, color 0.3s; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ color: var(--heading-color); margin-bottom: 5px; }}
  h2 {{ color: var(--heading-color-2); margin: 30px 0 15px 0; padding-bottom: 8px; border-bottom: 2px solid var(--accent-color); }}
  h3 {{ color: var(--heading-color); margin: 20px 0 10px 0; }}
  .header {{ background: linear-gradient(135deg, var(--header-gradient-start) 0%, var(--header-gradient-end) 100%);
             color: #fff; padding: 30px; border-radius: 8px; margin-bottom: 25px; position: relative; }}
  .header h1 {{ color: #fff; border: none; }}
  .header .subtitle {{ color: var(--header-subtitle-color); font-size: 0.9em; }}
  .card {{ background: var(--card-bg); border-radius: 8px; padding: 20px; margin-bottom: 20px;
           box-shadow: 0 1px 3px var(--shadow-color); transition: background 0.3s; }}
  .dashboard {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                gap: 15px; margin-bottom: 25px; }}
  .stat-box {{ background: var(--card-bg); border-radius: 8px; padding: 18px; text-align: center;
               box-shadow: 0 1px 3px var(--shadow-color); transition: background 0.3s; }}
  .stat-box .value {{ font-size: 2em; font-weight: bold; }}
  .stat-box .label {{ font-size: 0.85em; color: var(--muted-text); }}
  table {{ width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 0.9em; }}
  th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border-color); }}
  th {{ background: var(--table-header-bg); font-weight: 600; position: sticky; top: 0; }}
  tr:hover {{ background: var(--hover-bg); }}
  details {{ margin: 8px 0; }}
  summary {{ cursor: pointer; padding: 10px 14px; background: var(--summary-bg); border-radius: 6px;
             font-weight: 500; user-select: none; transition: background 0.3s; }}
  summary:hover {{ background: var(--summary-hover-bg); }}
  details[open] summary {{ border-radius: 6px 6px 0 0; }}
  details .detail-body {{ padding: 14px; border: 1px solid var(--border-color); border-top: none;
                          border-radius: 0 0 6px 6px; background: var(--card-bg); }}
  pre.explanation {{ white-space: pre-wrap; word-break: break-word; background: var(--pre-bg);
                     border: 1px solid var(--border-color); border-radius: 4px; padding: 10px 14px;
                     font-family: inherit; font-size: 0.93em; line-height: 1.6; margin: 4px 0 10px;
                     color: var(--text-color); }}
  .overlap-table th {{ background: var(--overlap-th-bg); width: 160px; }}
  .pkg-card {{ border-left: 4px solid var(--accent-color); }}
  .methodology {{ background: var(--methodology-bg); border-left: 4px solid var(--accent-color); padding: 15px; margin: 10px 0; border-radius: 4px; }}
  .limitations {{ background: var(--limitations-bg); border-left: 4px solid #ffc107; padding: 15px; margin: 10px 0; border-radius: 4px; }}
  .error-list {{ color: #dc3545; }}
  .scope-pills {{ display: flex; flex-wrap: wrap; gap: 6px; margin: 5px 0; }}
  .scope-pill {{ background: var(--pill-bg); padding: 3px 10px; border-radius: 12px; font-size: 0.85em; }}
  .fmg-group {{ margin: 20px 0; }}
  .fmg-group-header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); color: #fff;
                        padding: 12px 18px; border-radius: 8px 8px 0 0; font-size: 1.1em; }}
  .pkg-group {{ border: 1px solid var(--border-color); border-top: none; padding: 15px; margin-bottom: 0; background: var(--card-bg); }}
  .pkg-group:last-child {{ border-radius: 0 0 8px 8px; }}
  .pkg-group-header {{ font-size: 1em; color: var(--pkg-group-header-color); margin: 0 0 10px 0; padding-bottom: 6px;
                        border-bottom: 1px solid var(--border-color); }}
  .skipped-list {{ background: var(--limitations-bg); border-left: 3px solid #ffc107; padding: 8px 14px;
                   margin: 8px 0; border-radius: 4px; font-size: 0.88em; }}
  .dark-toggle {{ position: absolute; top: 20px; right: 20px; background: rgba(255,255,255,0.15);
                   border: 1px solid rgba(255,255,255,0.3); color: #fff; border-radius: 50%;
                   width: 40px; height: 40px; font-size: 1.2em; cursor: pointer;
                   display: flex; align-items: center; justify-content: center;
                   transition: background 0.3s, transform 0.2s; backdrop-filter: blur(4px); }}
  .dark-toggle:hover {{ background: rgba(255,255,255,0.25); transform: scale(1.1); }}
  .explanation-block {{ margin: 4px 0 10px; }}
  .explanation-block .intro {{ font-size: 0.95em; line-height: 1.5; margin-bottom: 8px; padding: 8px 12px;
    background: var(--pre-bg, #f8f9fa); border-left: 3px solid var(--accent-color, #0d6efd); border-radius: 4px; }}
  .explanation-block ul {{ margin: 4px 0 0 20px; font-size: 0.9em; }}
  .explanation-block li {{ margin: 3px 0; color: var(--text-color, #212529); }}
  .risk-score {{ display: inline-block; padding: 2px 10px; border-radius: 4px; font-weight: bold; font-size: 0.9em; }}
  .risk-factors {{ font-size: 0.82em; color: var(--muted-text, #6c757d); margin-top: 2px; }}
</style>
<script>
(function() {{
  if (localStorage.getItem('fmg-dark-mode') === 'true') {{
    document.documentElement.style.background = '#0d1117';
  }}
}})();
</script>
</head>
<body>
<div class="container">
"""


def _html_header(timestamp: str, version: str) -> str:
    return f"""<div class="header">
  <h1>FMG Policy Shadow Analysis Report</h1>
  <div class="subtitle">Generated: {_esc(timestamp)} &bull; Tool Version: {_esc(version)}</div>
  <button class="dark-toggle" id="darkToggle" title="Toggle dark mode" aria-label="Toggle dark mode">&#9790;</button>
</div>
"""


def _html_scope(fmgs: list[str], adoms: list[str], packages: list[str]) -> str:
    def _pills(items: list[str]) -> str:
        return "".join(f'<span class="scope-pill">{_esc(i)}</span>' for i in items)
    return f"""<div class="card">
  <h3>Analysis Scope</h3>
  <p><strong>FortiManagers ({len(fmgs)}):</strong></p>
  <div class="scope-pills">{_pills(fmgs)}</div>
  <p style="margin-top:8px"><strong>ADOMs ({len(adoms)}):</strong></p>
  <div class="scope-pills">{_pills(adoms)}</div>
  <p style="margin-top:8px"><strong>Packages ({len(packages)}):</strong></p>
  <div class="scope-pills">{_pills(packages)}</div>
</div>
"""


def _html_dashboard(counts: dict) -> str:
    items = [
        (str(counts.get("packages_analyzed", 0)), "Packages Analyzed", "#0d6efd"),
        (str(counts.get("total_policies", 0)), "Policies Analyzed", "#198754"),
        (str(counts.get("total_findings", 0)), "Total Findings", "#dc3545"),
        (str(counts.get("full_conflict_shadow", 0)), "Fully Shadowed (Conflict)", "#dc3545"),
        (str(counts.get("partial_conflict_shadow", 0)), "Partially Shadowed (Conflict)", "#fd7e14"),
        (str(counts.get("full_redundant_coverage", 0)), "Fully Shadowed (Redundant)", "#198754"),
        (str(counts.get("partial_redundant_overlap", 0)), "Partial Overlap (Redundant)", "#0dcaf0"),
        (str(counts.get("indeterminate", 0)), "Indeterminate (Unresolved)", "#6c757d"),
        (str(counts.get("errors", 0)), "Errors", "#dc3545"),
    ]
    boxes = ""
    for value, label, color in items:
        boxes += f'<div class="stat-box"><div class="value" style="color:{color}">{value}</div><div class="label">{label}</div></div>\n'
    return f"""<h2>Summary Dashboard</h2>
<div class="dashboard">
{boxes}
</div>
"""


def _html_package_cards(package_results: list[PackageResult]) -> str:
    if not package_results:
        return "<p>No packages analyzed.</p>"
    html = "<h2>Package Results</h2>\n"

    # Group by FMG instance
    fmg_groups: OrderedDict[str, list[PackageResult]] = OrderedDict()
    for pr in package_results:
        fmg_groups.setdefault(pr.fmg, []).append(pr)

    for fmg_host, prs in fmg_groups.items():
        html += f"<h3>FortiManager: {_esc(fmg_host)}</h3>\n"
        for pr in prs:
            findings_count = len(pr.findings)
            border_color = "#dc3545" if pr.full_conflict_count > 0 else (
                "#fd7e14" if pr.partial_conflict_count > 0 else "#0d6efd"
            )
            html += f"""<div class="card pkg-card" style="border-left-color:{border_color}">
  <h3>{_esc(pr.fmg)} / {_esc(pr.adom)} / {_esc(pr.package)}</h3>
  <table>
    <tr><td>Total Policies</td><td><strong>{pr.total_policies}</strong></td>
        <td>Effective Policies</td><td><strong>{pr.effective_policies}</strong></td></tr>
    <tr><td>Fully Shadowed (Conflict)</td><td><strong style="color:#dc3545">{pr.full_conflict_count}</strong></td>
        <td>Partially Shadowed (Conflict)</td><td><strong style="color:#fd7e14">{pr.partial_conflict_count}</strong></td></tr>
    <tr><td>Fully Shadowed (Redundant)</td><td><strong style="color:#198754">{pr.full_redundant_count}</strong></td>
        <td>Partial Overlap (Redundant)</td><td><strong style="color:#0dcaf0">{pr.partial_redundant_count}</strong></td></tr>
    <tr><td>Indeterminate (Unresolved)</td><td><strong style="color:#6c757d">{pr.indeterminate_count}</strong></td>
        <td>Total Findings</td><td><strong>{findings_count}</strong></td></tr>
    <tr><td>Unsupported Objects</td><td>{len(pr.unsupported_objects)}</td>
        <td>Analysis Time</td><td>{pr.elapsed_seconds:.2f}s</td></tr>
  </table>
"""
            if pr.errors:
                html += '  <div class="error-list"><strong>Errors:</strong><ul>'
                for err in pr.errors:
                    html += f"<li>{_esc(err)}</li>"
                html += "</ul></div>"
            html += "</div>\n"
    return html


def _html_findings_detail(package_results: list[PackageResult]) -> str:
    """Render findings grouped by shadowed policy.

    Instead of one collapsible per finding (which explodes when a single
    policy is involved in dozens of relationships), we create one section
    per shadowed policy and display all its shadow relationships as rows
    in a compact table.  The highest-severity finding drives the policy
    section's badge colour.
    """
    from collections import OrderedDict as OD

    total_findings = sum(len(pr.findings) for pr in package_results)

    if not total_findings:
        return "<h2>Findings Detail</h2>\n<p>No findings to display.</p>\n"

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    html = f"<h2>Findings Detail ({total_findings} total)</h2>\n"

    # Group package results by FMG instance
    fmg_groups: OrderedDict[str, list[PackageResult]] = OrderedDict()
    for pr in package_results:
        fmg_groups.setdefault(pr.fmg, []).append(pr)

    for fmg_host, prs in fmg_groups.items():
        html += f'<div class="fmg-group">\n'
        html += f'<div class="fmg-group-header">FortiManager: {_esc(fmg_host)}</div>\n'

        for pr in prs:
            html += f'<div class="pkg-group">\n'
            pkg_label = f"{_esc(pr.adom)} / {_esc(pr.package)}"
            finding_count = len(pr.findings)
            html += f'<h4 class="pkg-group-header">{pkg_label} &mdash; {finding_count} finding{"s" if finding_count != 1 else ""}</h4>\n'

            # Show policies with unresolved objects
            unresolved = [p for p in pr.policies if p.has_unresolved]
            if unresolved:
                html += (
                    f'<details class="skipped-list">\n'
                    f'<summary><strong>Policies with Unresolved Objects ({len(unresolved)})</strong>'
                    f' — analyzed with reduced confidence</summary>\n'
                    f'<ul style="margin:4px 0 0 18px">\n'
                )
                for p in unresolved:
                    notes = "; ".join(p.unresolved_notes) if p.unresolved_notes else "unknown"
                    html += f"<li>Policy #{p.seq_num+1} id={p.policyid} ({_esc(p.name or 'unnamed')}) &mdash; {_esc(notes)}</li>\n"
                html += "</ul></details>\n"

            # ── Group findings by shadowed policy ──
            policy_groups: OD[int, list] = OD()
            for f in pr.findings:
                policy_groups.setdefault(f.shadowed_policyid, []).append(f)

            # Sort policy groups by worst severity, then seq
            def _group_sort_key(item):
                pid, findings = item
                best_sev = min(severity_order.get(f.severity_label(), 5) for f in findings)
                seq = findings[0].shadowed_seq
                return (best_sev, seq)

            sorted_groups = sorted(policy_groups.items(), key=_group_sort_key)

            for shadowed_pid, findings in sorted_groups:
                f0 = findings[0]
                worst_sev = min(findings, key=lambda f: severity_order.get(f.severity_label(), 5)).severity_label()
                worst_ftype = min(findings, key=lambda f: severity_order.get(f.severity_label(), 5)).finding_type.value
                max_risk = max(f.risk_score for f in findings)
                n_conflict = sum(1 for f in findings if "conflict" in f.finding_type.value)
                n_redundant = sum(1 for f in findings if "redundant" in f.finding_type.value or "overlap" in f.finding_type.value)
                n_indeterminate = sum(1 for f in findings if "indeterminate" in f.finding_type.value)

                # Summary badges
                badges = _severity_badge(worst_sev) + " " + _finding_type_badge(worst_ftype)

                # Confidence levels present across all findings for this policy
                confidence_levels = sorted(
                    {f.confidence.value for f in findings},
                    key=lambda c: {"low": 0, "medium": 1, "high": 2}.get(c, 3),
                )
                _CONF_STYLES = {
                    "low": "background:#dc354530;color:#dc3545;border:1px solid #dc354560",
                    "medium": "background:#fd7e1430;color:#fd7e14;border:1px solid #fd7e1460",
                    "high": "background:#19875430;color:#198754;border:1px solid #19875460",
                }
                conf_badges = " ".join(
                    f'<span style="display:inline-block;padding:1px 7px;border-radius:4px;'
                    f'font-size:0.75em;font-weight:600;{_CONF_STYLES.get(c, "")}">{c}</span>'
                    for c in confidence_levels
                )

                # Reachability — fully unreachable if ANY finding says so
                any_unreachable = any(f.is_fully_unreachable for f in findings)

                html += f"""<details>
  <summary>
    {badges} {conf_badges}
    &nbsp; Policy #{f0.shadowed_seq+1} (id={f0.shadowed_policyid}) &mdash; {_esc(f0.shadowed_name or 'unnamed')}
    <span style="float:right;font-size:0.85em;color:var(--muted-text)">
      {len(findings)} relationship{"s" if len(findings) != 1 else ""}
      &bull; risk {max_risk:.1f}
    </span>
  </summary>
  <div class="detail-body">
    <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:10px;">
      <div><strong>Action:</strong> {_esc(f0.shadowed_action)}</div>
      <div><strong>Max Risk:</strong> <span class="risk-score" style="background:{'#dc3545' if max_risk >= 7 else '#fd7e14' if max_risk >= 4 else '#0d6efd'};color:#fff">{max_risk:.1f} / 10.0</span></div>
      <div><strong>Reachability:</strong> {"UNREACHABLE" if any_unreachable else "Partially Reachable"}</div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;font-size:0.85em;">
"""
                if n_conflict:
                    html += f'      <span style="background:#dc354520;color:#dc3545;padding:2px 8px;border-radius:4px;border:1px solid #dc354540">{n_conflict} conflict{"s" if n_conflict != 1 else ""}</span>\n'
                if n_redundant:
                    html += f'      <span style="background:#0dcaf020;color:#0dcaf0;padding:2px 8px;border-radius:4px;border:1px solid #0dcaf040">{n_redundant} redundant</span>\n'
                if n_indeterminate:
                    html += f'      <span style="background:#6c757d20;color:#6c757d;padding:2px 8px;border-radius:4px;border:1px solid #6c757d40">{n_indeterminate} indeterminate</span>\n'

                html += """    </div>
"""

                # ── Relationships table ──
                # Sort: severity desc, risk desc
                sorted_findings = sorted(
                    findings,
                    key=lambda f: (severity_order.get(f.severity_label(), 5), -f.risk_score),
                )

                html += """    <div style="overflow-x:auto;">
    <table class="overlap-table" style="width:100%;">
      <thead><tr>
        <th>Severity</th>
        <th>Type</th>
        <th>Shadowing Rule(s)</th>
        <th>Risk</th>
        <th>Action Conflict</th>
        <th>Confidence</th>
        <th style="width:40px;"></th>
      </tr></thead>
      <tbody>
"""
                for idx, f in enumerate(sorted_findings):
                    sev = f.severity_label()
                    ftype_label = FINDING_TYPE_LABELS.get(f.finding_type.value, f.finding_type.value)
                    ftype_color = FINDING_TYPE_COLORS.get(f.finding_type.value, "#adb5bd")

                    # Shadowing rules summary
                    if f.is_composite:
                        shad_summary = f"{len(f.shadowing_policyids)} rules (composite)"
                    else:
                        shad_summary = ", ".join(
                            f"#{s+1} id={pid}" for s, pid in zip(f.shadowing_seqs, f.shadowing_policyids)
                        )
                        # Add name for single-rule findings
                        if len(f.shadowing_names) == 1 and f.shadowing_names[0]:
                            shad_summary += f" ({_esc(f.shadowing_names[0])})"

                    action_html = (
                        f'<span style="color:#dc3545;font-weight:600">DIFFERENT</span> '
                        f'({_esc(f.shadowing_action)} vs {_esc(f.shadowed_action)})'
                        if not f.same_action else
                        f'<span style="color:#198754">Same</span> ({_esc(f.shadowed_action)})'
                    )

                    detail_id = f"detail-{shadowed_pid}-{idx}"

                    html += f"""        <tr style="cursor:pointer" onclick="var el=document.getElementById('{detail_id}');el.style.display=el.style.display==='none'?'table-row':'none'">
          <td>{_severity_badge(sev)}</td>
          <td><span style="color:{ftype_color};font-weight:600;font-size:0.85em">{_esc(ftype_label)}</span></td>
          <td style="font-size:0.9em">{shad_summary}</td>
          <td><span class="risk-score" style="background:{'#dc3545' if f.risk_score >= 7 else '#fd7e14' if f.risk_score >= 4 else '#0d6efd'};color:#fff;font-size:0.8em">{f.risk_score:.1f}</span></td>
          <td style="font-size:0.85em">{action_html}</td>
          <td style="font-size:0.85em">{_esc(f.confidence.value)}</td>
          <td style="font-size:0.8em;color:var(--muted-text)">&#9660;</td>
        </tr>
        <tr id="{detail_id}" style="display:none">
          <td colspan="7" style="padding:8px 12px;border-left:3px solid {ftype_color}">
"""
                    # Inline detail: explanation + overlap table
                    html += f"            {_format_explanation(f.explanation)}\n"

                    if hasattr(f, 'risk_factors') and f.risk_factors:
                        html += f'            <p class="risk-factors" style="font-size:0.85em;margin:6px 0"><strong>Factors:</strong> {_esc(", ".join(f.risk_factors))}</p>\n'

                    # Compact overlap details
                    html += '            <table class="overlap-table" style="font-size:0.85em;margin-top:6px">\n'
                    html += '              <tr><th>Dimension</th><th>Overlap</th></tr>\n'
                    dims = [
                        ("Source Interface", f.srcintf_overlap),
                        ("Dest Interface", f.dstintf_overlap),
                        ("Source Address", f.srcaddr_overlap),
                        ("Dest Address", f.dstaddr_overlap),
                        ("Service", f.service_overlap),
                        ("Schedule", f.schedule_overlap),
                    ]
                    for dim_name, dim_val in dims:
                        html += f"              <tr><td>{dim_name}</td><td>{_esc(dim_val)}</td></tr>\n"
                    html += "            </table>\n"

                    if f.unsupported_notes:
                        html += '            <p style="font-size:0.85em;margin-top:6px"><strong>Unresolved:</strong> ' + _esc("; ".join(f.unsupported_notes)) + '</p>\n'

                    html += """          </td>
        </tr>
"""

                html += """      </tbody>
    </table>
    </div>
  </div>
</details>
"""

            if not sorted_groups:
                html += "<p style='color:#6c757d;font-style:italic'>No findings for this package.</p>\n"

            html += "</div>\n"  # pkg-group

        html += "</div>\n"  # fmg-group

    return html


def _html_methodology() -> str:
    return '''<h2>Methodology</h2>
<div class="methodology">
  <p><strong>Policy Shadow &amp; Overlap Analysis</strong> evaluates each firewall rule against all
  higher-priority rules (rules appearing earlier in the policy order). Under first-match
  evaluation semantics, the firewall processes rules sequentially from top to bottom &mdash;
  when a rule matches, its action is applied and no further rules are checked. A lower-priority
  rule is &quot;shadowed&quot; when a higher-priority rule matches the same or broader traffic.</p>

  <h3 style="margin-top:14px;font-size:1em">Finding Classifications</h3>
  <ul style="margin:8px 0 0 20px">
    <li><strong>Fully Shadowed (Conflict)</strong> &mdash; A higher-priority rule with a <em>different</em>
        action completely covers the shadowed rule&rsquo;s match space. The shadowed rule is
        <strong>unreachable</strong> and will never match any traffic. This is the highest-risk
        finding &mdash; it may indicate a security gap where intended deny rules are being
        overridden by allow rules, or vice versa.
        <em>(Industry terms: contradictory shadow, conflicting rule)</em></li>
    <li><strong>Partially Shadowed (Conflict)</strong> &mdash; A higher-priority rule with a
        <em>different</em> action covers part of the shadowed rule&rsquo;s traffic. Some traffic
        reaches a different verdict than intended.
        <em>(Industry terms: partial shadow, partially covered rule)</em></li>
    <li><strong>Fully Shadowed (Redundant)</strong> &mdash; A higher-priority rule with the
        <em>same</em> action completely covers the shadowed rule. The rule is redundant &mdash;
        removing it would not change the security posture, but would simplify the rule base.
        <em>(Industry terms: redundant rule, covered rule)</em></li>
    <li><strong>Partially Overlapping (Redundant)</strong> &mdash; A higher-priority rule with
        the <em>same</em> action covers part of the shadowed rule&rsquo;s traffic. The overlap
        adds complexity but is not a security issue.
        <em>(Industry terms: partial redundancy, overlapping rule)</em></li>
    <li><strong>Indeterminate (Unresolved Objects)</strong> &mdash; Overlap was detected but
        unresolved objects (FQDNs, dynamic groups, geographic addresses, etc.) prevent
        definitive classification. Manual review recommended.
        <em>(Industry terms: inconclusive analysis)</em></li>
  </ul>

  <h3 style="margin-top:14px;font-size:1em">Risk Scoring</h3>
  <p>Each finding receives a risk score (0&ndash;10) based on weighted factors:</p>
  <ul style="margin:6px 0 0 20px">
    <li><strong>Interface overlaps</strong> are common and expected between policies &mdash;
        they carry minimal weight in the risk score.</li>
    <li><strong>Address object overlaps</strong> (source/destination) are more significant
        and carry higher weight.</li>
    <li><strong>Combined address + service + schedule overlaps</strong> represent the most
        complete shadowing and carry the highest weight.</li>
    <li><strong>Address breadth</strong> amplifies risk: a rule affecting all hosts (0.0.0.0/0)
        scores higher than one affecting a single host.</li>
    <li><strong>Action conflicts</strong> (deny shadowed by allow, or vice versa) receive
        a multiplier due to their security implications.</li>
  </ul>

  <h3 style="margin-top:14px;font-size:1em">Dimensions Compared</h3>
  <p style="margin-top:6px">Six match dimensions are evaluated: Source Interface, Destination Interface,
  Source Address, Destination Address, Service (protocol/ports), and Schedule. For full shadow
  detection, all six dimensions must be covered by the higher-priority rule(s).</p>

  <h3 style="margin-top:14px;font-size:1em">Compliance Context</h3>
  <p style="margin-top:6px">Regular rule base review aligns with PCI DSS Requirement 1.1.7
  (semi-annual firewall rule review), CIS Controls (configuration review), NIST SP 800-41
  (firewall policy guidelines), and ISO 27001 (access control management).</p>
</div>
'''


def _html_limitations() -> str:
    return """<h2>Limitations</h2>
<div class="limitations">
  <ul style="margin-left:20px">
    <li>FQDN-based address objects cannot be fully resolved to IP ranges and are marked indeterminate.</li>
    <li>Dynamic address groups and SDN connectors are not expanded.</li>
    <li>Geographic/country-based address objects are approximated or marked indeterminate.</li>
    <li>Schedule overlap analysis uses simplified time comparisons.</li>
    <li>Internet-service (ISDB) entries are resolved where the FortiGuard database is accessible;
        entries that cannot be fetched remain indeterminate.</li>
    <li>Application-layer criteria (App Control, URL filtering, etc.) are NOT considered in shadow
        analysis &mdash; the analysis is limited to L3/L4 match dimensions. However, security profile
        assignments are captured and displayed for context.</li>
    <li>VIP/DNAT destination translations are resolved where possible but complex scenarios may be missed.</li>
    <li>Policy sets with install-scope restrictions are compared only when scopes overlap.</li>
    <li>Central SNAT/DNAT policies are not included in the analysis.</li>
  </ul>
</div>
"""


def _html_footer() -> str:
    return """</div>
<script>
(function() {
  var toggle = document.getElementById('darkToggle');
  var body = document.body;
  // Restore saved preference
  if (localStorage.getItem('fmg-dark-mode') === 'true') {
    body.classList.add('dark');
    toggle.innerHTML = '&#9788;';  // sun
  }
  toggle.addEventListener('click', function() {
    body.classList.toggle('dark');
    var isDark = body.classList.contains('dark');
    localStorage.setItem('fmg-dark-mode', isDark);
    toggle.innerHTML = isDark ? '&#9788;' : '&#9790;';  // sun : moon
    document.documentElement.style.background = isDark ? '#0d1117' : '';
  });
})();
</script>
</body>
</html>
"""


# ===================================================================
# Excel Report
# ===================================================================

def generate_excel_report(run_result: RunResult, output_path: str) -> str | None:
    """Generate an Excel (.xlsx) report with multiple sheets.

    Returns the output file path, or None if openpyxl is unavailable.
    """
    if not HAS_OPENPYXL:
        print("[WARNING] openpyxl is not installed. Skipping Excel report generation.")
        print("  Install with: pip install openpyxl")
        return None

    wb = openpyxl.Workbook()
    # Remove default sheet
    wb.remove(wb.active)

    _excel_summary_sheet(wb, run_result)
    _excel_findings_sheet(wb, run_result)
    _excel_packages_sheet(wb, run_result)
    _excel_unsupported_sheet(wb, run_result)
    _excel_policy_inventory_sheet(wb, run_result)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    wb.save(output_path)
    return output_path


# -- Style helpers --

_HEADER_FONT = Font(bold=True, color="FFFFFF", size=11) if HAS_OPENPYXL else None
_HEADER_FILL = PatternFill(start_color="1A1A2E", end_color="1A1A2E", fill_type="solid") if HAS_OPENPYXL else None
_HEADER_ALIGNMENT = Alignment(horizontal="center", vertical="center", wrap_text=True) if HAS_OPENPYXL else None
_WRAP_ALIGNMENT = Alignment(wrap_text=True, vertical="top") if HAS_OPENPYXL else None
_THIN_BORDER = Border(
    left=Side(style="thin"), right=Side(style="thin"),
    top=Side(style="thin"), bottom=Side(style="thin"),
) if HAS_OPENPYXL else None

_SEVERITY_FILLS: dict[str, Any] = {}
if HAS_OPENPYXL:
    _SEVERITY_FILLS = {
        "CRITICAL": PatternFill(start_color="DC3545", end_color="DC3545", fill_type="solid"),
        "HIGH": PatternFill(start_color="FD7E14", end_color="FD7E14", fill_type="solid"),
        "MEDIUM": PatternFill(start_color="FFC107", end_color="FFC107", fill_type="solid"),
        "LOW": PatternFill(start_color="0D6EFD", end_color="0D6EFD", fill_type="solid"),
        "INFO": PatternFill(start_color="ADB5BD", end_color="ADB5BD", fill_type="solid"),
    }


def _apply_header_row(ws, headers: list[str], widths: list[int] | None = None):
    """Write header row with formatting."""
    for col_idx, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_idx, value=header)
        cell.font = _HEADER_FONT
        cell.fill = _HEADER_FILL
        cell.alignment = _HEADER_ALIGNMENT
        cell.border = _THIN_BORDER

    # Column widths
    if widths:
        for col_idx, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(col_idx)].width = w
    else:
        for col_idx in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col_idx)].width = 18

    # Freeze top row
    ws.freeze_panes = "A2"

    # Auto-filter
    if headers:
        last_col = get_column_letter(len(headers))
        ws.auto_filter.ref = f"A1:{last_col}1"


def _write_row(ws, row_num: int, values: list, wrap_cols: set[int] | None = None):
    """Write a data row."""
    for col_idx, val in enumerate(values, 1):
        cell = ws.cell(row=row_num, column=col_idx, value=val)
        cell.border = _THIN_BORDER
        if wrap_cols and col_idx in wrap_cols:
            cell.alignment = _WRAP_ALIGNMENT


# -- Sheet builders --

def _excel_summary_sheet(wb, run_result: RunResult):
    ws = wb.create_sheet("Summary")
    counts = run_result.summary_counts()

    # Metadata section
    meta = [
        ("Tool Version", run_result.tool_version),
        ("Run Timestamp", run_result.run_timestamp),
        ("Elapsed Seconds", run_result.elapsed_seconds),
        ("", ""),
        ("SUMMARY", ""),
        ("Packages Analyzed", counts.get("packages_analyzed", 0)),
        ("Total Policies", counts.get("total_policies", 0)),
        ("Total Findings", counts.get("total_findings", 0)),
        ("", ""),
        ("FINDINGS BY TYPE", ""),
        ("Full Conflict Shadow", counts.get("full_conflict_shadow", 0)),
        ("Partial Conflict Shadow", counts.get("partial_conflict_shadow", 0)),
        ("Full Redundant Coverage", counts.get("full_redundant_coverage", 0)),
        ("Partial Redundant Overlap", counts.get("partial_redundant_overlap", 0)),
        ("Indeterminate", counts.get("indeterminate", 0)),
        ("Errors", counts.get("errors", 0)),
    ]

    bold_font = Font(bold=True, size=11)
    section_font = Font(bold=True, size=12, color="1A1A2E")

    ws.column_dimensions["A"].width = 30
    ws.column_dimensions["B"].width = 30

    for row_idx, (label, value) in enumerate(meta, 1):
        cell_a = ws.cell(row=row_idx, column=1, value=label)
        cell_b = ws.cell(row=row_idx, column=2, value=value)
        if label in ("SUMMARY", "FINDINGS BY TYPE"):
            cell_a.font = section_font
        else:
            cell_a.font = bold_font

    # Per-package stats table below
    start_row = len(meta) + 2
    ws.cell(row=start_row, column=1, value="PER-PACKAGE STATS").font = section_font
    start_row += 1

    pkg_headers = ["FMG", "ADOM", "Package", "Total Policies", "Effective",
                   "Full Conflict", "Partial Conflict", "Full Redundant",
                   "Partial Redundant", "Indeterminate", "Total Findings", "Time (s)"]
    for col_idx, h in enumerate(pkg_headers, 1):
        cell = ws.cell(row=start_row, column=col_idx, value=h)
        cell.font = _HEADER_FONT
        cell.fill = _HEADER_FILL
        cell.alignment = _HEADER_ALIGNMENT

    for i, pr in enumerate(run_result.package_results):
        row = start_row + 1 + i
        vals = [pr.fmg, pr.adom, pr.package, pr.total_policies, pr.effective_policies,
                pr.full_conflict_count, pr.partial_conflict_count, pr.full_redundant_count,
                pr.partial_redundant_count, pr.indeterminate_count, len(pr.findings),
                round(pr.elapsed_seconds, 2)]
        for col_idx, v in enumerate(vals, 1):
            ws.cell(row=row, column=col_idx, value=v)


def _excel_findings_sheet(wb, run_result: RunResult):
    ws = wb.create_sheet("Findings")

    headers = [
        "FMG", "ADOM", "Package",
        "Shadowed Policy ID", "Shadowed Name", "Shadowed Seq",
        "Finding Type", "Severity", "Is Composite",
        "Shadowing Policy IDs", "Shadowing Names", "Shadowing Seqs",
        "SrcIntf Overlap", "DstIntf Overlap",
        "SrcAddr Overlap", "DstAddr Overlap",
        "Service Overlap", "Schedule Overlap",
        "Fully Unreachable", "Residual Description",
        "Shadowed Action", "Shadowing Action", "Same Action",
        "Confidence", "Unsupported Notes", "Explanation",
    ]
    widths = [
        14, 14, 18,
        16, 20, 12,
        28, 12, 12,
        22, 22, 18,
        20, 20,
        25, 25,
        20, 18,
        14, 30,
        14, 14, 12,
        12, 30, 50,
    ]
    wrap_cols = {15, 16, 20, 25, 26}  # long text columns

    _apply_header_row(ws, headers, widths)

    row_num = 2
    for pr in run_result.package_results:
        for f in pr.findings:
            d = f.to_dict()
            values = [
                d["fmg"], d["adom"], d["package"],
                d["shadowed_policyid"], d["shadowed_name"], d["shadowed_seq"],
                FINDING_TYPE_LABELS.get(d["finding_type"], d["finding_type"]),
                d["severity"], d["is_composite"],
                ", ".join(str(x) for x in d["shadowing_policyids"]),
                ", ".join(str(x) for x in d["shadowing_names"]),
                ", ".join(str(x) for x in d["shadowing_seqs"]),
                d["srcintf_overlap"], d["dstintf_overlap"],
                d["srcaddr_overlap"], d["dstaddr_overlap"],
                d["service_overlap"], d["schedule_overlap"],
                d["is_fully_unreachable"], d["residual_description"],
                d["shadowed_action"], d["shadowing_action"], d["same_action"],
                d["confidence"],
                "; ".join(d["unsupported_notes"]),
                d["explanation"],
            ]
            _write_row(ws, row_num, values, wrap_cols)

            # Color the severity cell
            sev = d["severity"]
            sev_cell = ws.cell(row=row_num, column=8)
            if sev in _SEVERITY_FILLS:
                sev_cell.fill = _SEVERITY_FILLS[sev]
                if sev in ("CRITICAL", "HIGH", "LOW"):
                    sev_cell.font = Font(bold=True, color="FFFFFF")
                else:
                    sev_cell.font = Font(bold=True)

            row_num += 1


def _excel_packages_sheet(wb, run_result: RunResult):
    ws = wb.create_sheet("Packages")

    headers = [
        "FMG", "ADOM", "Package",
        "Total Policies", "Effective Policies",
        "Full Conflict", "Partial Conflict",
        "Full Redundant", "Partial Redundant",
        "Indeterminate", "Total Findings",
        "Unsupported Objects", "Errors", "Time (s)",
    ]
    widths = [14, 14, 20, 14, 16, 14, 16, 14, 16, 14, 14, 18, 10, 10]

    _apply_header_row(ws, headers, widths)

    for i, pr in enumerate(run_result.package_results):
        row = i + 2
        values = [
            pr.fmg, pr.adom, pr.package,
            pr.total_policies, pr.effective_policies,
            pr.full_conflict_count, pr.partial_conflict_count,
            pr.full_redundant_count, pr.partial_redundant_count,
            pr.indeterminate_count, len(pr.findings),
            len(pr.unsupported_objects), len(pr.errors),
            round(pr.elapsed_seconds, 2),
        ]
        _write_row(ws, row, values)


def _excel_unsupported_sheet(wb, run_result: RunResult):
    ws = wb.create_sheet("Unsupported Objects")

    headers = ["FMG", "ADOM", "Package", "Object"]
    widths = [14, 14, 20, 50]

    _apply_header_row(ws, headers, widths)

    row_num = 2
    for pr in run_result.package_results:
        for obj in pr.unsupported_objects:
            _write_row(ws, row_num, [pr.fmg, pr.adom, pr.package, obj], {4})
            row_num += 1

    if row_num == 2:
        ws.cell(row=2, column=1, value="No unsupported objects found.")


def _excel_policy_inventory_sheet(wb, run_result: RunResult):
    ws = wb.create_sheet("Policy Inventory")

    headers = [
        "FMG", "ADOM", "Package",
        "Policy ID", "Name", "Seq #",
        "Action", "Status",
        "Source Interface", "Dest Interface",
        "SrcAddr Objects", "SrcAddr Resolved",
        "DstAddr Objects", "DstAddr Resolved",
        "Service Objects", "Service Resolved",
        "Schedule",
        "Comments", "Has Unresolved", "Security Profiles",
    ]
    widths = [14, 14, 18, 10, 20, 8, 10, 10, 16, 16, 25, 25, 25, 25, 20, 20, 14, 30, 14, 35]
    wrap_cols = {11, 12, 13, 14, 18, 20}

    _apply_header_row(ws, headers, widths)

    row_num = 2
    for pr in run_result.package_results:
        for p in pr.policies:
            raw = p.raw_data or {}
            values = [
                p.fmg, p.adom, p.package,
                p.policyid, p.name, p.seq_num,
                p.action.value if p.action else "",
                p.status,
                p.srcintf.describe() if p.srcintf else "",
                p.dstintf.describe() if p.dstintf else "",
                ", ".join(raw.get("_raw_srcaddr", [])),
                p.srcaddr.describe() if p.srcaddr else "",
                ", ".join(raw.get("_raw_dstaddr", [])),
                p.dstaddr.describe() if p.dstaddr else "",
                ", ".join(raw.get("_raw_service", [])),
                p.service.describe() if p.service else "",
                p.schedule.describe() if p.schedule else "",
                p.comments, p.has_unresolved,
                ', '.join(f'{k}={v}' for k, v in sorted(p.security_profiles.items())) if p.security_profiles else '',
            ]
            _write_row(ws, row_num, values, wrap_cols)
            row_num += 1


# ===================================================================
# Convenience: generate all reports
# ===================================================================

def generate_all_reports(
    run_result: RunResult,
    output_dir: str,
    formats: list[str] | None = None,
) -> dict[str, str]:
    """Generate reports in all requested formats.

    Args:
        run_result: The analysis results.
        output_dir: Directory for output files.
        formats: List of format strings: "json", "html", "excel"/"xlsx".
                 Defaults to all formats.

    Returns:
        Dict mapping format name to output file path.
    """
    if formats is None:
        formats = ["json", "html", "excel"]

    os.makedirs(output_dir, exist_ok=True)

    timestamp_slug = (run_result.run_timestamp or datetime.now().isoformat()).replace(":", "-").replace(" ", "_")[:19]
    base = f"shadow_report_{timestamp_slug}"

    results: dict[str, str] = {}

    for fmt in formats:
        fmt_lower = fmt.lower()
        if fmt_lower == "json":
            path = os.path.join(output_dir, f"{base}.json")
            generate_json_report(run_result, path)
            results["json"] = path

        elif fmt_lower == "html":
            path = os.path.join(output_dir, f"{base}.html")
            generate_html_report(run_result, path)
            results["html"] = path

        elif fmt_lower in ("excel", "xlsx"):
            path = os.path.join(output_dir, f"{base}.xlsx")
            result = generate_excel_report(run_result, path)
            if result:
                results["excel"] = path

        else:
            print(f"[WARNING] Unknown report format: {fmt}")

    return results
