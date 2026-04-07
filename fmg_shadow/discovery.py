"""
ADOM and policy package discovery for FortiManager.

Handles enumeration of ADOMs, policy packages (with pagination and
folder nesting), scope member retrieval, and package filtering.
"""

from __future__ import annotations

import fnmatch
import logging
import re
from typing import Optional

log = logging.getLogger(__name__)

# Default page size for paginated requests
_PAGE_SIZE = 100


# ---------------------------------------------------------------------------
# ADOM enumeration
# ---------------------------------------------------------------------------

def get_adoms(client) -> list[dict]:
    """
    List available ADOMs on the FortiManager.

    Returns a list of ADOM dicts as returned by the API, each containing
    at minimum a 'name' key.
    """
    result = client.get("/dvmdb/adom")
    if not isinstance(result, list):
        log.warning("Unexpected ADOM response type: %s", type(result))
        return []
    return result


# ---------------------------------------------------------------------------
# Package enumeration (recursive, paginated)
# ---------------------------------------------------------------------------

def _flatten_packages(items: list[dict], prefix: str = "") -> list[str]:
    """
    Recursively extract package paths from a list of package/folder dicts.

    Folders have a 'subobj' key containing nested items.
    Packages have type == 'pkg' (or lack 'subobj').
    Returns a flat list of slash-separated package paths.
    """
    paths: list[str] = []
    for item in items:
        name = item.get("name", "")
        if not name:
            continue
        full_path = f"{prefix}/{name}" if prefix else name

        # Check if this is a folder (has subobj with children)
        subobj = item.get("subobj")
        if subobj and isinstance(subobj, list):
            # It's a folder — recurse into children
            paths.extend(_flatten_packages(subobj, prefix=full_path))
        else:
            # It's a policy package (type == 'pkg' or leaf node)
            item_type = item.get("type", "pkg")
            if item_type == "folder":
                # Empty folder, skip
                continue
            paths.append(full_path)
    return paths


def get_packages(client, adom: str) -> list[str]:
    """
    List all policy packages in an ADOM, handling pagination and folder
    nesting.  Returns a flat list of package paths (e.g. 'folder/pkg').

    Uses /pm/pkg/adom/{adom} with range=[offset, page_size] pagination.
    """
    url = f"/pm/pkg/adom/{adom}"
    all_items: list[dict] = []
    offset = 0

    while True:
        result = client.get(url, range_=[offset, _PAGE_SIZE])

        if not isinstance(result, list):
            # Could be a single dict or error — handle gracefully
            if isinstance(result, dict):
                all_items.append(result)
            break

        if not result:
            break

        all_items.extend(result)

        # If we got fewer than a full page, we're done
        if len(result) < _PAGE_SIZE:
            break
        offset += len(result)

    log.debug("Fetched %d raw package items from ADOM '%s'", len(all_items), adom)
    return _flatten_packages(all_items)


# ---------------------------------------------------------------------------
# Package scope members
# ---------------------------------------------------------------------------

def get_device_groups(client, adom: str) -> dict[str, set[tuple[str, str]]]:
    """
    Fetch device groups for an ADOM and return a mapping of
    group_name (lowered) → set of (device_name, vdom) tuples (lowered).

    Each group is fetched from /dvmdb/adom/{adom}/group with its
    object members expanded.
    """
    url = f"/dvmdb/adom/{adom}/group"
    try:
        result = client.get(url, option=["object member"])
    except Exception as exc:
        log.warning("Failed to fetch device groups for ADOM '%s': %s", adom, exc)
        return {}

    if not isinstance(result, list):
        return {}

    group_map: dict[str, set[tuple[str, str]]] = {}
    for grp in result:
        if not isinstance(grp, dict):
            continue
        gname = grp.get("name", "")
        if not gname:
            continue
        members = grp.get("object member", [])
        if not isinstance(members, list):
            continue
        devices: set[tuple[str, str]] = set()
        for m in members:
            if not isinstance(m, dict):
                continue
            dname = m.get("name", "")
            vdom = m.get("vdom", "root")
            if dname:
                devices.add((dname.lower(), vdom.lower()))
        group_map[gname.lower()] = devices
        log.debug("Device group '%s': %d member(s)", gname, len(devices))

    log.info("Fetched %d device group(s) for ADOM '%s'", len(group_map), adom)
    return group_map


def get_package_scope(client, adom: str, package: str) -> list[dict]:
    """
    Get the scope members (install targets) for a policy package.

    Returns a list of dicts with 'name' and 'vdom' keys, or an empty list
    if the package has global scope.
    """
    url = f"/pm/pkg/adom/{adom}/{package}"
    result = client.get(url, option=["scope member"])

    if isinstance(result, list) and len(result) > 0:
        result = result[0]

    if not isinstance(result, dict):
        log.warning("Unexpected scope response for %s/%s: %s", adom, package, type(result))
        return []

    scope_members = result.get("scope member", [])
    if not isinstance(scope_members, list):
        return []

    return scope_members


# ---------------------------------------------------------------------------
# Package filtering
# ---------------------------------------------------------------------------

def filter_packages(
    packages: list[str],
    pattern: Optional[str] = None,
    regex: Optional[str] = None,
) -> list[str]:
    """
    Filter a list of package paths by glob pattern or regex.

    Args:
        packages: list of package paths (e.g. ['default', 'prod/fw-east'])
        pattern: glob/fnmatch pattern (e.g. 'prod/*', '*east*')
        regex: regex pattern (e.g. r'prod/fw-\\w+')

    Returns filtered list.  If neither pattern nor regex is specified,
    returns the full list unchanged.
    """
    if not pattern and not regex:
        return list(packages)

    result: list[str] = []
    compiled_re = re.compile(regex) if regex else None

    for pkg in packages:
        if pattern and fnmatch.fnmatch(pkg, pattern):
            result.append(pkg)
        elif compiled_re and compiled_re.search(pkg):
            result.append(pkg)

    return result
