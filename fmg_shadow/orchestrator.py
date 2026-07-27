#!/usr/bin/env python3
"""
Orchestrator for FMG Policy Shadow Analysis.

Coordinates FMG client connections, package discovery, policy fetching,
object resolution, and shadow analysis across multiple FMG instances.
"""

import gc
import logging
import re
import time
from datetime import datetime, timezone

from fmg_shadow.models import PackageResult, RunResult
from typing import List, Optional, Tuple

logger = logging.getLogger("fmg_shadow.orchestrator")


def _detect_fmg_version(client) -> Optional[Tuple[int, int, int]]:
    """Read and normalize the connected FortiManager firmware version."""
    try:
        status = client.get("/sys/status")
    except Exception as exc:
        logger.warning(
            "[%s] Could not determine FortiManager version; ambiguous "
            "per-policy install scopes will be excluded: %s",
            getattr(client, "host", client),
            exc,
        )
        return None

    if isinstance(status, list):
        status = status[0] if status and isinstance(status[0], dict) else {}
    if not isinstance(status, dict):
        return None

    normalized = {
        str(key).strip().lower(): value
        for key, value in status.items()
    }
    try:
        return (
            int(normalized["major"]),
            int(normalized["minor"]),
            int(normalized["patch"]),
        )
    except (KeyError, TypeError, ValueError):
        version_text = str(normalized.get("version", ""))
        match = re.search(r"v?(\d+)\.(\d+)\.(\d+)", version_text)
        if match:
            return tuple(int(part) for part in match.groups())
    return None


def analyze_single_package(
    client,
    adom: str,
    package_name: str,
    config: dict,
    group_map: Optional[dict]= None,
    shared_resolver=None,
    modern_scope_semantics: Optional[bool] = None,
) -> PackageResult:
    """
    Analyze a single policy package for shadow/redundancy issues.

    Args:
        client: An authenticated FMGClient instance.
        adom: ADOM name.
        package_name: Policy package name.
        config: Run configuration dict.
        group_map: Optional device group mapping.
        shared_resolver: Optional pre-populated ObjectResolver to reuse
            across packages in the same ADOM (avoids re-fetching all objects).

    Returns:
        PackageResult with findings, policies, and any errors.
    """
    from fmg_shadow.analyzer import ShadowAnalyzer
    from fmg_shadow.objects import ObjectResolver
    from fmg_shadow.policy_fetch import fetch_global_policies, fetch_policies

    fmg_host = client.host if hasattr(client, "host") else str(client)
    result = PackageResult(
        fmg=fmg_host,
        adom=adom,
        package=package_name,
    )

    t0 = time.monotonic()
    try:
        # 1. Fetch raw policies
        logger.info("[%s] Fetching policies from %s/%s ...", fmg_host, adom, package_name)
        include_disabled = config.get("include_disabled", False)
        local_policies = fetch_policies(
            client,
            adom,
            package_name,
            include_disabled,
            group_map=group_map,
            modern_scope_semantics=modern_scope_semantics,
        )

        # 1b. Fetch global header/footer policies inherited from the global
        #     database.  On the FortiGate these are evaluated as:
        #       global headers -> package-defined rules -> global footers
        #     so we splice them into a single ordered list and renumber the
        #     evaluation sequence to match.  This lets a global header shadow a
        #     package rule, and a package rule (or header) shadow a global
        #     footer.
        header_policies = []
        footer_policies = []
        if config.get("include_global_policies", True):
            header_policies = fetch_global_policies(
                client,
                adom,
                package_name,
                "global-header",
                group_map=group_map,
                modern_scope_semantics=modern_scope_semantics,
            )
            footer_policies = fetch_global_policies(
                client,
                adom,
                package_name,
                "global-footer",
                group_map=group_map,
                modern_scope_semantics=modern_scope_semantics,
            )

        policies = header_policies + local_policies + footer_policies
        # Renumber to reflect the combined top-to-bottom evaluation order.
        for idx, p in enumerate(policies):
            p.fmg = fmg_host
            p.seq_num = idx

        result.total_policies = len(policies)
        result.global_header_policies = len(header_policies)
        result.global_footer_policies = len(footer_policies)
        if header_policies or footer_policies:
            logger.info(
                "[%s] %s/%s: %d global header + %d local + %d global footer policies",
                fmg_host, adom, package_name,
                len(header_policies), len(local_policies), len(footer_policies),
            )

        if not policies:
            logger.warning("[%s] No policies found in %s/%s", fmg_host, adom, package_name)
            result.elapsed_seconds = time.monotonic() - t0
            return result

        # 2. Resolve objects — reuse shared resolver if available
        logger.info(
            "[%s] Resolving objects for %s/%s (%d policies) ...",
            fmg_host, adom, package_name, len(policies),
        )
        if shared_resolver is not None:
            resolver = shared_resolver
        else:
            resolver = ObjectResolver(client, adom)
            resolver.fetch_all()
        resolved_policies = resolver.resolve_policies(policies)

        result.effective_policies = sum(
            1 for p in resolved_policies if p.is_effective(include_disabled)
        )

        # Collect unsupported object notes
        for p in resolved_policies:
            if p.has_unresolved:
                for note in p.unresolved_notes:
                    if note not in result.unsupported_objects:
                        result.unsupported_objects.append(note)

        # Check strict mode
        if config.get("strict_unsupported", False) and result.unsupported_objects:
            raise RuntimeError(
                f"Strict mode: {len(result.unsupported_objects)} unsupported/unresolved "
                f"objects found in {package_name}: {'; '.join(result.unsupported_objects[:5])}"
            )

        # 3. Run shadow analysis
        logger.info(
            "[%s] Running shadow analysis on %s/%s (%d effective policies) ...",
            fmg_host, adom, package_name, result.effective_policies,
        )
        analyzer = ShadowAnalyzer()
        findings = analyzer.analyze_package(resolved_policies, include_disabled)

        result.findings = findings
        result.policies = resolved_policies

        # 4. Strip bulky raw_data from policies to reduce memory footprint.
        #    We preserve only the lightweight _raw_* fields needed for reporting;
        #    the full FMG response dict is no longer needed after resolution.
        _slim_raw_data(resolved_policies)

        logger.info(
            "[%s] %s/%s: %d findings from %d policies",
            fmg_host, adom, package_name, len(findings), result.total_policies,
        )

    except Exception as exc:
        err_msg = f"Error analyzing {adom}/{package_name} on {fmg_host}: {exc}"
        logger.error(err_msg, exc_info=True)
        result.errors.append(err_msg)

    result.elapsed_seconds = time.monotonic() - t0
    return result


def _slim_raw_data(policies) -> None:
    """Replace full raw_data dicts with only the fields needed for reporting.

    After object resolution, the large FMG response payloads inside raw_data
    are no longer useful.  We keep only the _raw_* name lists, internet-service
    flags, and a few metadata fields needed by the report.
    """
    _KEEP_KEYS = {
        "_raw_srcintf", "_raw_dstintf", "_raw_srcaddr", "_raw_dstaddr",
        "_raw_service", "_raw_schedule", "_raw_scope",
        "internet-service", "internet-service-src",
        "internet-service-name", "internet-service-id",
        "internet-service-src-name", "internet-service-src-id",
        "uuid",
    }
    for p in policies:
        if not p.raw_data:
            continue
        slim = {k: v for k, v in p.raw_data.items() if k in _KEEP_KEYS}
        p.raw_data = slim


def _discover_packages(client, adom: str, config: dict) -> List[str]:
    """
    Discover and filter packages based on config.

    Returns a list of package names to analyze.
    """
    from fmg_shadow.discovery import filter_packages, get_packages

    fmg_host = client.host if hasattr(client, "host") else str(client)
    explicit_packages = config.get("packages", [])

    if explicit_packages and not config.get("all_packages", False) and not config.get("package_regex"):
        # User specified exact packages -- use them directly
        logger.info("[%s] Using %d explicitly specified package(s)", fmg_host, len(explicit_packages))
        return list(explicit_packages)

    # Discover all packages in ADOM
    logger.info("[%s] Discovering packages in ADOM '%s' ...", fmg_host, adom)
    all_packages = get_packages(client, adom)
    logger.info("[%s] Found %d package(s) in ADOM '%s'", fmg_host, len(all_packages), adom)

    if config.get("all_packages", False):
        package_names = [p if isinstance(p, str) else p.get("name", "") for p in all_packages]
    elif config.get("package_regex"):
        package_names = filter_packages(
            all_packages,
            pattern=None,
            regex=config["package_regex"],
        )
    else:
        # Explicit packages + possible regex
        package_names = list(explicit_packages)

    if not package_names:
        logger.warning("[%s] No packages matched the selection criteria in ADOM '%s'", fmg_host, adom)

    return package_names


def run_analysis(config: dict) -> RunResult:
    """
    Run the full shadow analysis across all configured FMG instances.

    Memory-efficient: creates ONE ObjectResolver per ADOM and shares it
    across all packages.  After each package is analyzed, bulky raw FMG
    response data is stripped from policies to free memory.

    Args:
        config: Configuration dict from cli_app with keys:
            fmg_hosts, adom, packages, all_packages, package_regex,
            username, password, token, output_dir, workers,
            formats, include_disabled, strict_unsupported, verify_ssl

    Returns:
        RunResult with all package results and aggregate stats.
    """
    from fmg_shadow.client import FMGClient
    from fmg_shadow.objects import ObjectResolver

    run_start = time.monotonic()
    run_result = RunResult(
        run_timestamp=datetime.now(timezone.utc).isoformat(),
    )

    fmg_hosts = config.get("fmg_hosts", [])
    adom = config.get("adom", "root")

    for fmg_host in fmg_hosts:
        logger.info("=" * 60)
        logger.info("Connecting to FMG: %s", fmg_host)
        logger.info("=" * 60)

        fmg_start = time.monotonic()

        try:
            client = FMGClient(
                host=fmg_host,
                username=config.get("username"),
                password=config.get("password"),
                token=config.get("token"),
                verify_ssl=config.get("verify_ssl", False),
                timeout=config.get("timeout", 120),
            )

            with client:
                from fmg_shadow.policy_fetch import (
                    _scope_response_uses_explicit_empty,
                )

                fmg_version = _detect_fmg_version(client)
                modern_scope_semantics = (
                    _scope_response_uses_explicit_empty(fmg_version)
                )
                if fmg_version is not None:
                    logger.info(
                        "[%s] FortiManager version: %d.%d.%d",
                        fmg_host,
                        *fmg_version
                    )

                # Discover packages
                package_names = _discover_packages(client, adom, config)

                if not package_names:
                    run_result.errors.append(
                        f"No packages found/matched on {fmg_host} ADOM '{adom}'"
                    )
                    continue

                # Resolve device groups once for the entire ADOM
                from fmg_shadow.discovery import get_device_groups
                group_map = get_device_groups(client, adom)

                # Create ONE shared ObjectResolver for the entire ADOM.
                # All packages in the same ADOM reference the same objects,
                # so fetching them once saves significant memory and API calls.
                logger.info(
                    "[%s] Pre-fetching all objects for ADOM '%s' ...",
                    fmg_host, adom,
                )
                shared_resolver = ObjectResolver(client, adom)
                shared_resolver.fetch_all()

                logger.info(
                    "[%s] Analyzing %d package(s) sequentially ...",
                    fmg_host, len(package_names),
                )

                # Analyze packages sequentially to minimize peak memory.
                # Concurrent execution is removed — the bottleneck is
                # API latency (already amortized by the shared resolver)
                # and memory, not CPU.
                package_results: List[PackageResult] = []

                for i, pkg_name in enumerate(package_names, 1):
                    logger.info(
                        "[%s] Package %d/%d: %s",
                        fmg_host, i, len(package_names), pkg_name,
                    )
                    result = analyze_single_package(
                        client, adom, pkg_name, config,
                        group_map=group_map,
                        shared_resolver=shared_resolver,
                        modern_scope_semantics=modern_scope_semantics,
                    )
                    package_results.append(result)

                    # Periodic GC to release fragmented memory
                    if i % 5 == 0:
                        gc.collect()

                # Release the shared resolver now that analysis is done
                del shared_resolver
                gc.collect()

                run_result.package_results.extend(package_results)

                fmg_elapsed = time.monotonic() - fmg_start
                total_findings = sum(len(pr.findings) for pr in package_results)
                total_policies = sum(pr.total_policies for pr in package_results)
                total_errors = sum(len(pr.errors) for pr in package_results)

                logger.info(
                    "[%s] Finished: %d packages, %d policies, %d findings, %d errors (%.1fs)",
                    fmg_host, len(package_results), total_policies,
                    total_findings, total_errors, fmg_elapsed,
                )

        except Exception as exc:
            err_msg = f"Failed to connect/analyze FMG {fmg_host}: {exc}"
            logger.error(err_msg, exc_info=True)
            run_result.errors.append(err_msg)

    run_result.elapsed_seconds = time.monotonic() - run_start

    logger.info(
        "Analysis complete: %d packages, %d total findings, %.1fs elapsed",
        len(run_result.package_results),
        run_result.total_findings,
        run_result.elapsed_seconds,
    )

    return run_result
