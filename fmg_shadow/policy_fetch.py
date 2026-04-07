"""
Policy fetching and normalization from FortiManager.

Retrieves firewall policies from FMG policy packages and converts them
into CanonicalPolicy objects for shadow analysis.
"""

from __future__ import annotations

import logging
from typing import Optional

from .models import (
    CanonicalPolicy,
    InstallScope,
    PolicyAction,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Action / status mapping
# ---------------------------------------------------------------------------

_ACTION_MAP = {
    0: PolicyAction.DENY,
    1: PolicyAction.ACCEPT,
    2: PolicyAction.IPSEC,
    "deny": PolicyAction.DENY,
    "accept": PolicyAction.ACCEPT,
    "ipsec": PolicyAction.IPSEC,
}

_STATUS_MAP = {
    0: "disable",
    1: "enable",
    "disable": "disable",
    "enable": "enable",
}


# ---------------------------------------------------------------------------
# Field extraction helpers
# ---------------------------------------------------------------------------

def _extract_name_list(value) -> list[str]:
    """
    Normalize a field that may be a list of strings, list of dicts with
    'name' key, a single string, or None.

    Returns a list of name strings.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        result = []
        for item in value:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, dict):
                name = item.get("name", "")
                if name:
                    result.append(name)
            else:
                result.append(str(item))
        return result
    return [str(value)]


def _is_section_title(policy_data: dict) -> bool:
    """
    Detect section-title pseudo-rules.

    These have a global-label but no real policy content (no policyid,
    or policyid == 0, and typically lack srcintf/dstintf/srcaddr/dstaddr).
    """
    # FMG uses 'global-label' entries that act as section dividers
    # They typically have policyid=0 or missing, and no real match criteria
    policyid = policy_data.get("policyid", 0)
    has_label = bool(policy_data.get("global-label", ""))

    # A real section title has no meaningful policy fields
    has_srcintf = bool(policy_data.get("srcintf"))
    has_dstintf = bool(policy_data.get("dstintf"))
    has_srcaddr = bool(policy_data.get("srcaddr"))
    has_dstaddr = bool(policy_data.get("dstaddr"))

    if has_label and policyid == 0 and not (has_srcintf or has_dstintf):
        return True

    # Some FMG versions mark section titles with _is_section_title or
    # have action missing entirely
    if policy_data.get("_is_section_title"):
        return True

    return False


def _extract_scope(policy_data: dict) -> list[dict]:
    """
    Extract per-policy install scope (_scope or install-on).

    Returns list of {'name': ..., 'vdom': ...} dicts, or empty list for
    global scope.
    """
    # _scope is the primary field
    scope = policy_data.get("_scope")
    if scope and isinstance(scope, list):
        return scope

    # install-on is an alternative representation
    install_on = policy_data.get("install-on")
    if install_on and isinstance(install_on, list):
        return install_on

    return []


# ---------------------------------------------------------------------------
# Core policy fetch
# ---------------------------------------------------------------------------

def fetch_policies(
    client,
    adom: str,
    package: str,
    include_disabled: bool = False,
    group_map: Optional[dict[str, set[tuple[str, str]]]] = None,
) -> list[CanonicalPolicy]:
    """
    Fetch firewall policies from a FortiManager policy package.

    Retrieves policies via /pm/config/adom/{adom}/pkg/{package}/firewall/policy
    and converts them into CanonicalPolicy objects.

    Return order IS the evaluation order — list index is used as seq_num.
    Raw field names are preserved; object resolution happens later in
    objects.py.

    Args:
        client: FMGClient instance with .get() method
        adom: ADOM name
        package: policy package path
        include_disabled: if False, disabled policies are still returned
            but marked with status='disable'

    Returns:
        List of CanonicalPolicy in evaluation order.
    """
    url = f"/pm/config/adom/{adom}/pkg/{package}/firewall/policy"
    result = client.get(url, loadsub=0)

    if not isinstance(result, list):
        if result is None:
            log.warning("No policies found in %s/%s", adom, package)
            return []
        log.warning(
            "Unexpected policy response for %s/%s: %s", adom, package, type(result)
        )
        return []

    policies: list[CanonicalPolicy] = []

    for seq_num, raw in enumerate(result):
        if not isinstance(raw, dict):
            log.debug("Skipping non-dict policy entry at seq %d", seq_num)
            continue

        section_title = _is_section_title(raw)

        # Extract basic fields
        policyid = raw.get("policyid", 0)
        name = raw.get("name", "")
        comments = raw.get("comments", "")
        global_label = raw.get("global-label", "")

        # Map action
        raw_action = raw.get("action", 1)
        action = _ACTION_MAP.get(raw_action, PolicyAction.UNKNOWN)

        # Map status
        raw_status = raw.get("status", 1)
        status = _STATUS_MAP.get(raw_status, "enable")

        # Extract list-type fields (raw names, not yet resolved)
        srcintf = _extract_name_list(raw.get("srcintf"))
        dstintf = _extract_name_list(raw.get("dstintf"))
        srcaddr = _extract_name_list(raw.get("srcaddr"))
        dstaddr = _extract_name_list(raw.get("dstaddr"))
        service = _extract_name_list(raw.get("service"))
        schedule = _extract_name_list(raw.get("schedule"))

        # Extract per-policy scope
        scope_members = _extract_scope(raw)
        install_scope = InstallScope.from_scope_members(scope_members, group_map=group_map)

        # obj seq (FMG internal ordering field)
        obj_seq = raw.get("obj seq", raw.get("obj_seq"))

        # Extract security/UTM profile references
        security_profiles = {}
        profile_fields = [
            'av-profile', 'webfilter-profile', 'ips-sensor',
            'application-list', 'ssl-ssh-profile', 'dnsfilter-profile',
            'emailfilter-profile', 'dlp-profile', 'file-filter-profile',
            'voip-profile', 'casb-profile', 'waf-profile',
            'profile-protocol-options', 'utm-status',
        ]
        for pf in profile_fields:
            val = raw.get(pf)
            if val and val not in (0, '0', '', 'none', None, [], ['']):
                if isinstance(val, list):
                    names = []
                    for item in val:
                        if isinstance(item, str):
                            names.append(item)
                        elif isinstance(item, dict):
                            n = item.get('name', '')
                            if n:
                                names.append(n)
                    if names:
                        security_profiles[pf] = ', '.join(names)
                elif isinstance(val, str):
                    security_profiles[pf] = val
                elif isinstance(val, (int, float)):
                    security_profiles[pf] = str(val)

        # Negation flags
        srcaddr_negate = raw.get("srcaddr-negate", 0) in ("enable", 1, "1")
        dstaddr_negate = raw.get("dstaddr-negate", 0) in ("enable", 1, "1")
        service_negate = raw.get("service-negate", 0) in ("enable", 1, "1")

        policy = CanonicalPolicy(
            adom=adom,
            package=package,
            policyid=policyid,
            name=name,
            seq_num=seq_num,
            obj_seq=obj_seq,
            action=action,
            status=status,
            install_scope=install_scope,
            is_section_title=section_title,
            global_label=global_label,
            comments=comments,
            raw_data=raw,
            security_profiles=security_profiles,
            srcaddr_negate=srcaddr_negate,
            dstaddr_negate=dstaddr_negate,
            service_negate=service_negate,
        )

        # Store raw name lists in raw_data for later resolution by objects.py
        # The CanonicalPolicy match dimensions (srcintf, srcaddr, etc.) start
        # as defaults (any) and get properly resolved by objects.py.
        # We augment raw_data so the resolver can find the raw names easily.
        policy.raw_data["_raw_srcintf"] = srcintf
        policy.raw_data["_raw_dstintf"] = dstintf
        policy.raw_data["_raw_srcaddr"] = srcaddr
        policy.raw_data["_raw_dstaddr"] = dstaddr
        policy.raw_data["_raw_service"] = service
        policy.raw_data["_raw_schedule"] = schedule
        policy.raw_data["_raw_scope"] = scope_members

        policies.append(policy)

    log.info(
        "Fetched %d policies from %s/%s (%d section titles)",
        len(policies),
        adom,
        package,
        sum(1 for p in policies if p.is_section_title),
    )

    return policies


# ---------------------------------------------------------------------------
# Bulk fetch with referenced objects
# ---------------------------------------------------------------------------

def fetch_policies_with_objects(
    client,
    adom: str,
    package: str,
) -> tuple[list[CanonicalPolicy], Optional[dict]]:
    """
    Fetch policies AND attempt to bulk-fetch all referenced objects.

    Tries the FMG 'get referred' option first to pull all referenced
    address/service/schedule objects in a single API call.  Falls back
    to 'expand datasrc' or returns None for the objects dict if neither
    is supported.

    Args:
        client: FMGClient instance
        adom: ADOM name
        package: policy package path

    Returns:
        Tuple of (policies, referred_objects).
        referred_objects is a dict keyed by object type (e.g.
        'firewall address', 'firewall service custom') or None if bulk
        fetch failed.
    """
    # First, fetch the policies normally
    policies = fetch_policies(client, adom, package, include_disabled=True)

    if not policies:
        return policies, None

    # Attempt 1: 'option': ['get referred'] on the policy endpoint
    referred_objects = _try_get_referred(client, adom, package)
    if referred_objects is not None:
        return policies, referred_objects

    # Attempt 2: 'expand datasrc' option
    referred_objects = _try_expand_datasrc(client, adom, package)
    if referred_objects is not None:
        return policies, referred_objects

    # Attempt 3: Collect unique object names and fetch individually by type
    referred_objects = _fetch_objects_by_name(client, adom, policies)

    return policies, referred_objects


def _try_get_referred(client, adom: str, package: str) -> Optional[dict]:
    """
    Try to use 'get referred' option to bulk-fetch referenced objects.
    """
    url = f"/pm/config/adom/{adom}/pkg/{package}/firewall/policy"
    try:
        result = client.get(
            url,
            get_referred=[
                {
                    "datasrc": [
                        {"obj type": "firewall address"},
                        {"obj type": "firewall addrgrp"},
                        {"obj type": "firewall service custom"},
                        {"obj type": "firewall service group"},
                        {"obj type": "firewall schedule recurring"},
                        {"obj type": "firewall schedule onetime"},
                        {"obj type": "firewall schedule group"},
                    ]
                }
            ],
        )
        if isinstance(result, dict) and any(k.startswith("firewall") for k in result):
            log.info("Successfully used 'get referred' for %s/%s", adom, package)
            return result
        # Some FMG versions return referred data nested under each policy entry.
        if isinstance(result, list) and result:
            collected: dict[str, dict] = {}
            for entry in result:
                if not isinstance(entry, dict):
                    continue
                referred = entry.get("get referred", [])
                if not isinstance(referred, list):
                    continue
                for block in referred:
                    for datasrc in block.get("datasrc", []):
                        obj_type = datasrc.get("obj type")
                        objs = datasrc.get("objs", [])
                        if not obj_type or not isinstance(objs, list):
                            continue
                        obj_map = collected.setdefault(obj_type, {})
                        for obj in objs:
                            if isinstance(obj, dict) and obj.get("name"):
                                obj_map[obj["name"]] = obj
            if collected:
                log.info("Successfully used 'get referred' for %s/%s", adom, package)
                return collected
    except Exception as exc:
        log.debug("'get referred' not available: %s", exc)

    return None


def _try_expand_datasrc(client, adom: str, package: str) -> Optional[dict]:
    """
    Try to use 'expand datasrc' to get object details alongside policies.
    """
    url = f"/pm/config/adom/{adom}/pkg/{package}/firewall/policy"
    try:
        result = client.get(
            url,
            expand_datasrc=[
                {
                    "datasrc": [
                        {"obj type": "firewall address", "name": "srcaddr"},
                        {"obj type": "firewall address", "name": "dstaddr"},
                        {"obj type": "firewall service custom", "name": "service"},
                    ]
                }
            ],
        )
        if isinstance(result, list) and result:
            # With expand datasrc, referenced object details are returned under
            # the "expand datasrc" key for each policy entry.
            objects: dict[str, dict] = {}
            for entry in result:
                if not isinstance(entry, dict):
                    continue
                expanded = entry.get("expand datasrc", [])
                if not isinstance(expanded, list):
                    continue
                for block in expanded:
                    for datasrc in block.get("datasrc", []):
                        obj_type = datasrc.get("obj type")
                        objs = datasrc.get("objs", [])
                        if not obj_type or not isinstance(objs, list):
                            continue
                        obj_map = objects.setdefault(obj_type, {})
                        for obj in objs:
                            if isinstance(obj, dict) and obj.get("name"):
                                obj_map[obj["name"]] = obj
            if objects:
                log.info(
                    "Used 'expand datasrc' for %s/%s, got %d object types",
                    adom, package, len(objects),
                )
                return objects
    except Exception as exc:
        log.debug("'expand datasrc' not available: %s", exc)

    return None


def _fetch_objects_by_name(
    client, adom: str, policies: list[CanonicalPolicy]
) -> Optional[dict]:
    """
    Collect all unique object names from policies and fetch them
    individually by object type.
    """
    # Collect unique names per field
    addr_names: set[str] = set()
    svc_names: set[str] = set()
    schedule_names: set[str] = set()

    for p in policies:
        raw = p.raw_data
        for name in raw.get("_raw_srcaddr", []):
            if name.lower() not in ("all", "none"):
                addr_names.add(name)
        for name in raw.get("_raw_dstaddr", []):
            if name.lower() not in ("all", "none"):
                addr_names.add(name)
        for name in raw.get("_raw_service", []):
            if name.lower() not in ("all",):
                svc_names.add(name)
        for name in raw.get("_raw_schedule", []):
            if name.lower() not in ("always",):
                schedule_names.add(name)

    objects: dict = {}

    # Fetch addresses
    if addr_names:
        try:
            url = f"/pm/config/adom/{adom}/obj/firewall/address"
            result = client.get(url)
            if isinstance(result, list):
                addr_map = {}
                for obj in result:
                    if isinstance(obj, dict):
                        obj_name = obj.get("name", "")
                        if obj_name in addr_names:
                            addr_map[obj_name] = obj
                if addr_map:
                    objects["firewall address"] = addr_map
        except Exception as exc:
            log.debug("Failed to fetch addresses: %s", exc)

        # Also try address groups
        try:
            url = f"/pm/config/adom/{adom}/obj/firewall/addrgrp"
            result = client.get(url)
            if isinstance(result, list):
                grp_map = {}
                for obj in result:
                    if isinstance(obj, dict):
                        obj_name = obj.get("name", "")
                        if obj_name in addr_names:
                            grp_map[obj_name] = obj
                if grp_map:
                    objects["firewall addrgrp"] = grp_map
        except Exception as exc:
            log.debug("Failed to fetch address groups: %s", exc)

    # Fetch services
    if svc_names:
        try:
            url = f"/pm/config/adom/{adom}/obj/firewall/service/custom"
            result = client.get(url)
            if isinstance(result, list):
                svc_map = {}
                for obj in result:
                    if isinstance(obj, dict):
                        obj_name = obj.get("name", "")
                        if obj_name in svc_names:
                            svc_map[obj_name] = obj
                if svc_map:
                    objects["firewall service custom"] = svc_map
        except Exception as exc:
            log.debug("Failed to fetch services: %s", exc)

        # Service groups
        try:
            url = f"/pm/config/adom/{adom}/obj/firewall/service/group"
            result = client.get(url)
            if isinstance(result, list):
                grp_map = {}
                for obj in result:
                    if isinstance(obj, dict):
                        obj_name = obj.get("name", "")
                        if obj_name in svc_names:
                            grp_map[obj_name] = obj
                if grp_map:
                    objects["firewall service group"] = grp_map
        except Exception as exc:
            log.debug("Failed to fetch service groups: %s", exc)

    # Fetch schedules
    if schedule_names:
        for sched_type in ("onetime", "recurring", "group"):
            try:
                url = f"/pm/config/adom/{adom}/obj/firewall/schedule/{sched_type}"
                result = client.get(url)
                if isinstance(result, list):
                    sched_map = {}
                    for obj in result:
                        if isinstance(obj, dict):
                            obj_name = obj.get("name", "")
                            if obj_name in schedule_names:
                                sched_map[obj_name] = obj
                    if sched_map:
                        objects[f"firewall schedule {sched_type}"] = sched_map
            except Exception as exc:
                log.debug("Failed to fetch schedule %s: %s", sched_type, exc)

    if objects:
        total = sum(len(v) for v in objects.values())
        log.info(
            "Fetched %d referenced objects across %d types for %s",
            total, len(objects), adom,
        )
        return objects

    return None


def _field_to_object_type(field_name: str) -> str:
    """Map a policy field name to its FMG object type category."""
    mapping = {
        "srcaddr": "firewall address",
        "dstaddr": "firewall address",
        "service": "firewall service custom",
        "srcintf": "system interface",
        "dstintf": "system interface",
    }
    return mapping.get(field_name, field_name)
