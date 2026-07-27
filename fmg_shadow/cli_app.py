#!/usr/bin/env python3
"""
CLI entry point for FMG Policy Shadow Analyzer.

Parses command-line arguments and delegates to the orchestrator.
"""

import argparse
import logging
import os
import sys
from pathlib import Path

from fmg_shadow.models import __version__
from typing import List, Optional


logger = logging.getLogger("fmg_shadow")


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="fmg-policy-shadow",
        description=(
            "FortiManager Policy Shadow Analyzer -- detect shadowed, "
            "redundant, and conflicting firewall rules across FMG instances."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --fmg 10.0.0.1 -u admin --all-packages\n"
            "  %(prog)s --fmg-file hosts.txt --adom prod --package-regex 'edge-.*'\n"
            "  %(prog)s --fmg 10.0.0.1,10.0.0.2 --package main-policy --format html\n"
        ),
    )

    # ── FMG targets ──────────────────────────────────────────────────
    fmg_group = parser.add_argument_group("FMG targets")
    fmg_group.add_argument(
        "--fmg",
        action="append",
        default=None,
        help=(
            "FMG host (IP or FQDN). Repeatable or comma-separated. "
            "At least one required unless --fmg-file is used."
        ),
    )
    fmg_group.add_argument(
        "--fmg-file",
        type=str,
        default=None,
        help="File with one FMG host per line.",
    )

    # ── ADOM / Package selection ─────────────────────────────────────
    scope_group = parser.add_argument_group("ADOM and package selection")
    scope_group.add_argument(
        "--adom",
        type=str,
        default="root",
        help="ADOM name to analyze (default: root).",
    )
    scope_group.add_argument(
        "--package",
        action="append",
        default=None,
        help="Specific policy package name. Repeatable.",
    )
    scope_group.add_argument(
        "--all-packages",
        action="store_true",
        default=False,
        help="Analyze all packages in the ADOM.",
    )
    scope_group.add_argument(
        "--package-regex",
        type=str,
        default=None,
        help="Filter packages by regex pattern.",
    )

    # ── Authentication ───────────────────────────────────────────────
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "--username", "-u",
        type=str,
        default=None,
        help="FMG username (or set FMG_USER env var).",
    )
    auth_group.add_argument(
        "--password", "-p",
        type=str,
        default=None,
        help="FMG password (or set FMG_PASSWORD env var).",
    )
    auth_group.add_argument(
        "--token",
        type=str,
        default=None,
        help="FMG API token (or set FMG_TOKEN env var).",
    )

    # ── Output ───────────────────────────────────────────────────────
    out_group = parser.add_argument_group("Output")
    out_group.add_argument(
        "--output-dir", "-o",
        type=str,
        default="./shadow-report",
        help="Directory for report output (default: ./shadow-report).",
    )
    out_group.add_argument(
        "--format",
        type=str,
        default="html,xlsx,json",
        dest="formats",
        help="Comma-separated output formats: html,xlsx,json (default: html,xlsx,json).",
    )

    # ── Execution ────────────────────────────────────────────────────
    exec_group = parser.add_argument_group("Execution")
    exec_group.add_argument(
        "--workers",
        type=int,
        default=4,
        help=(
            "Compatibility option retained for existing invocations; package "
            "analysis is currently sequential and this value is ignored."
        ),
    )
    exec_group.add_argument(
        "--include-disabled",
        action="store_true",
        default=False,
        help="Include disabled policies in the analysis.",
    )
    exec_group.add_argument(
        "--strict-unsupported",
        action="store_true",
        default=False,
        help="Fail on unsupported objects instead of flagging them.",
    )
    exec_group.add_argument(
        "--no-global-policies",
        action="store_false",
        dest="include_global_policies",
        default=True,
        help=(
            "Do not factor in global header/footer policies inherited from the "
            "global database (default: included in the evaluation order)."
        ),
    )
    exec_group.add_argument(
        "--insecure",
        action="store_true",
        default=True,
        help="Skip SSL certificate verification (default: True for self-signed FMG certs).",
    )
    exec_group.add_argument(
        "--no-insecure",
        action="store_false",
        dest="insecure",
        help="Enforce SSL certificate verification.",
    )

    # ── Logging ──────────────────────────────────────────────────────
    log_group = parser.add_argument_group("Logging")
    log_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Enable verbose output.",
    )
    log_group.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Enable debug-level logging.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def _resolve_fmg_hosts(args: argparse.Namespace) -> List[str]:
    """Collect FMG hosts from --fmg and --fmg-file arguments."""
    hosts: List[str] = []

    if args.fmg:
        for entry in args.fmg:
            for host in entry.split(","):
                h = host.strip()
                if h:
                    hosts.append(h)

    if args.fmg_file:
        fmg_path = Path(args.fmg_file)
        if not fmg_path.is_file():
            print(f"Error: --fmg-file '{args.fmg_file}' not found.", file=sys.stderr)
            sys.exit(1)
        for line in fmg_path.read_text().splitlines():
            h = line.strip()
            if h and not h.startswith("#"):
                hosts.append(h)

    return hosts


def _configure_logging(verbose: bool, debug: bool) -> None:
    """Configure logging level and format."""
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Suppress noisy urllib3 warnings when --insecure is used
    logging.getLogger("urllib3").setLevel(logging.ERROR)


def main(argv: Optional[List[str]]= None) -> None:
    """Parse CLI arguments and run the shadow analysis."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # ── Logging setup ────────────────────────────────────────────────
    _configure_logging(args.verbose, args.debug)

    # ── Resolve FMG hosts ────────────────────────────────────────────
    fmg_hosts = _resolve_fmg_hosts(args)
    if not fmg_hosts:
        parser.error("At least one FMG host is required (--fmg or --fmg-file).")

    # ── Resolve authentication ───────────────────────────────────────
    username = args.username or os.environ.get("FMG_USER")
    password = args.password or os.environ.get("FMG_PASSWORD")
    token = args.token or os.environ.get("FMG_TOKEN")

    if not token and not username:
        parser.error(
            "Authentication required: provide --username/-u (or FMG_USER env) "
            "or --token (or FMG_TOKEN env)."
        )

    # ── Validate package selection ───────────────────────────────────
    if not args.package and not args.all_packages and not args.package_regex:
        parser.error(
            "Package selection required: use --package, --all-packages, "
            "or --package-regex."
        )

    # ── Validate formats ─────────────────────────────────────────────
    valid_formats = {"html", "xlsx", "json"}
    formats = [f.strip().lower() for f in args.formats.split(",")]
    invalid = set(formats) - valid_formats
    if invalid:
        parser.error(f"Invalid output format(s): {', '.join(invalid)}. Valid: html, xlsx, json.")

    # ── Build config dict ────────────────────────────────────────────
    config = {
        "fmg_hosts": fmg_hosts,
        "adom": args.adom,
        "packages": args.package or [],
        "all_packages": args.all_packages,
        "package_regex": args.package_regex,
        "username": username,
        "password": password,
        "token": token,
        "output_dir": args.output_dir,
        "workers": args.workers,
        "formats": formats,
        "include_disabled": args.include_disabled,
        "strict_unsupported": args.strict_unsupported,
        "include_global_policies": args.include_global_policies,
        "verify_ssl": not args.insecure,
        "verbose": args.verbose,
        "debug": args.debug,
    }

    # ── Run analysis ─────────────────────────────────────────────────
    from fmg_shadow.orchestrator import run_analysis

    logger.info("Starting FMG Policy Shadow Analysis v%s", __version__)
    logger.info("Targets: %s | ADOM: %s", ", ".join(fmg_hosts), args.adom)

    run_result = run_analysis(config)

    # ── Generate reports ─────────────────────────────────────────────
    output_dir = Path(config["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)

    from fmg_shadow.reporting import generate_all_reports

    generate_all_reports(run_result, str(output_dir), formats)

    # ── Summary ──────────────────────────────────────────────────────
    counts = run_result.summary_counts()
    print()
    print("=" * 60)
    print("  FMG Policy Shadow Analysis Complete")
    print("=" * 60)
    print(f"  Packages analyzed : {counts['packages_analyzed']}")
    print(f"  Total policies    : {counts['total_policies']}")
    print(f"  Total findings    : {counts['total_findings']}")
    print(f"    Full conflict   : {counts['full_conflict_shadow']}")
    print(f"    Partial conflict: {counts['partial_conflict_shadow']}")
    print(f"    Full redundant  : {counts['full_redundant_coverage']}")
    print(f"    Partial overlap : {counts['partial_redundant_overlap']}")
    print(f"    Indeterminate   : {counts['indeterminate']}")
    print(f"  Errors            : {counts['errors']}")
    print(f"  Elapsed time      : {run_result.elapsed_seconds:.1f}s")
    print(f"  Reports written to: {output_dir.resolve()}")
    print("=" * 60)

    if counts["errors"] > 0:
        sys.exit(2)
    if counts["total_findings"] > 0 and any(
        pr.full_conflict_count > 0 for pr in run_result.package_results
    ):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
