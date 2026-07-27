"""
Policy fetching and normalization from FortiManager.

Retrieves firewall policies from FMG policy packages and converts them
into CanonicalPolicy objects for shadow analysis.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple

from .models import (
    CanonicalPolicy,
    InstallScope,
    InterfaceSet,
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

# Match criteria that the analyzer does not currently model.  A policy with
# one of these configured must not receive a definitive full-shadow result or
# become eligible for a generated disable script.
_UNMODELED_MATCH_FIELDS = {
    "groups": "identity user groups",
    "users": "identity users",
    "fsso-groups": "FSSO groups",
    "devices": "legacy source devices",
    "fsso": "FSSO identity matching",
    "rsso": "RSSO identity matching",
    "wsso": "WSSO identity matching",
    "sgt": "security group tags",
    "sgt-check": "security group tag checks",
    "srcaddr6": "IPv6 source addresses",
    "srcaddr6-negate": "negated IPv6 source addresses",
    "dstaddr6": "IPv6 destination addresses",
    "dstaddr6-negate": "negated IPv6 destination addresses",
    "src-vendor-mac": "source vendor MAC",
    "src-device": "source device",
    "dst-device": "destination device",
    "src-device-type": "source device type",
    "dst-device-type": "destination device type",
    "src-device-category": "source device category",
    "dst-device-category": "destination device category",
    "ztna-ems-tag": "ZTNA EMS tags",
    "ztna-ems-tag-secondary": "secondary ZTNA EMS tags",
    "ztna-ems-tag-negate": "negated ZTNA EMS tags",
    "ztna-ems-tag6": "IPv6 ZTNA EMS tags",
    "ztna-geo-tag": "ZTNA geography tags",
    "ztna-destination": "ZTNA destination",
    "ztna-device-ownership": "ZTNA device ownership",
    "ztna-status": "ZTNA status",
    "application": "application criteria",
    "app-category": "application categories",
    "app-group": "application groups",
    "url-category": "URL categories",
    "url-category-unitary": "unitary URL categories",
    "tos": "type-of-service criteria",
    "tos-mask": "type-of-service mask",
    "tos-negate": "negated type-of-service criteria",
    "vlan-filter": "VLAN filter",
    "network-service-dynamic": "dynamic destination network service",
    "network-service-src-dynamic": "dynamic source network service",
    "match-vip-only": "VIP-only matching",
    "policy-expiry": "policy expiry",
    "reputation-minimum": "minimum IPv4 reputation",
    "reputation-minimum6": "minimum IPv6 reputation",
    "rtp-nat": "RTP NAT matching",
    "rtp-addr": "RTP address matching",
    "nat46": "NAT46 policy evaluation",
    "nat64": "NAT64 policy evaluation",
}


# ---------------------------------------------------------------------------
# Field extraction helpers
# ---------------------------------------------------------------------------

def _is_configured_match_value(value) -> bool:
    """Return whether an unmodeled policy field has meaningful configuration."""
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized.startswith("0x"):
            try:
                return int(normalized, 16) != 0
            except ValueError:
                return True
        return normalized not in {
            "", "0", "disable", "disabled", "none", "off",
            "00", "0000-00-00", "0000-00-00 00:00:00",
        }
    if isinstance(value, (list, tuple, set)):
        return any(_is_configured_match_value(item) for item in value)
    if isinstance(value, dict):
        return any(_is_configured_match_value(item) for item in value.values())
    return True


def _unmodeled_match_descriptions(
    raw: dict,
    action: PolicyAction,
) -> List[str]:
    """List configured match dimensions not represented by the analyzer."""
    descriptions = []
    for field, description in _UNMODELED_MATCH_FIELDS.items():
        if _is_configured_match_value(raw.get(field)):
            descriptions.append(description)

    # ``match-vip`` changes VIP policy selection/priority and its defaults
    # changed across FortiOS releases.  Enabled values on any rule, and any
    # explicit value on a deny rule, are review-only until that priority is a
    # modeled dimension.
    match_vip = raw.get("match-vip")
    if _is_configured_match_value(match_vip) or (
        action == PolicyAction.DENY and "match-vip" in raw
    ):
        descriptions.append("VIP matching priority")

    # Cover version-specific IPv4/IPv6 ISDB selectors, custom services,
    # groups, names, and negations.  Empty/disabled defaults are ignored.
    for field, value in raw.items():
        if not isinstance(field, str):
            continue
        if (
            field.startswith("internet-service")
            or field.startswith("internet-service6")
        ) and _is_configured_match_value(value):
            descriptions.append("internet service criteria")
            break

    return descriptions


def _contains_dynamic_mapping(value) -> bool:
    """Detect embedded FortiManager per-device/per-platform mappings."""
    if isinstance(value, dict):
        for key, item in value.items():
            normalized_key = str(key).replace("-", "_").lower()
            if normalized_key in {
                "dynamic_mapping",
                "platform_mapping",
            } and _is_configured_match_value(item):
                return True
            if _contains_dynamic_mapping(item):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_dynamic_mapping(item) for item in value)
    return False


def _extract_name_list(value) -> List[str]:
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

    if has_label and policyid == 0 and not (has_srcintf or has_dstintf):
        return True

    # Some FMG versions mark section titles with _is_section_title or
    # have action missing entirely
    if policy_data.get("_is_section_title"):
        return True

    return False


def _parse_obj_flags(value) -> Optional[int]:
    """Normalize FortiManager ``obj flags`` from common response encodings."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            try:
                return int(text, 10)
            except ValueError:
                return None
    return None


def _scope_response_uses_explicit_empty(
    version: Optional[Tuple[int, int, int]],
) -> Optional[bool]:
    """Return the install-scope response behavior for an FMG version.

    FortiManager fixed the legacy ambiguity in 7.0.11, 7.2.5, and 7.4.3.
    Newer release trains return an explicit empty ``scope member`` for
    ``Install On: None``.  Unknown or unusual release trains stay unknown so
    the remediation path can fail closed.
    """
    if version is None:
        return None
    major, minor, patch = version
    if major < 7:
        return False
    if major > 7:
        return True
    fixed_patches = {
        0: 11,
        2: 5,
        4: 3,
    }
    if minor in fixed_patches:
        return patch >= fixed_patches[minor]
    if minor >= 6 and minor % 2 == 0:
        return True
    return None


def _extract_scope(
    policy_data: dict,
    modern_scope_semantics: Optional[bool] = None,
) -> Tuple[str, List[dict]]:
    """
    Extract per-policy install scope.

    FMG returns per-policy installation targets under "scope member" when
    the request includes option=["scope member"].  Falls back to "_scope"
    and "install-on" for compatibility.

    Returns ``(state, members)`` where state is ``specific``, ``none``,
    ``default``, or ``unknown``.  FortiManager 6 can omit ``scope member`` for
    both Default and None; in that response shape, bit 16 of ``obj flags``
    confirms Default.  Unknown version/flag combinations never default to a
    package-wide scope.
    """
    # "scope member" is the primary field when option=["scope member"]
    # is used in the API request.
    if "scope member" in policy_data:
        scope_member = policy_data.get("scope member")
        if not isinstance(scope_member, list):
            return "unknown", []
        if not scope_member:
            return "none", []
        return "specific", scope_member

    # _scope is a legacy/alternative field
    if "_scope" in policy_data:
        scope = policy_data.get("_scope")
        if not isinstance(scope, list):
            return "unknown", []
        if not scope:
            return "none", []
        return "specific", scope

    # install-on is another alternative representation
    if "install-on" in policy_data:
        install_on = policy_data.get("install-on")
        if not isinstance(install_on, list):
            return "unknown", []
        if not install_on:
            return "none", []
        return "specific", install_on

    obj_flags = _parse_obj_flags(
        policy_data.get("obj flags", policy_data.get("obj_flags"))
    )
    if obj_flags is not None and obj_flags & 16:
        return "default", []
    if modern_scope_semantics is True:
        return "default", []
    if modern_scope_semantics is False:
        return "none", []

    return "unknown", []


# ---------------------------------------------------------------------------
# Per-policy normalization
# ---------------------------------------------------------------------------

def _build_policy(
    raw: dict,
    adom: str,
    package: str,
    seq_num: int,
    group_map: Optional[Dict[str, Set[Tuple[str, str]]]] = None,
    section: str = "local",
    modern_scope_semantics: Optional[bool] = None,
) -> CanonicalPolicy:
    """Normalize a single raw FMG policy dict into a CanonicalPolicy.

    Raw object names are preserved under ``raw_data["_raw_*"]`` for later
    resolution by objects.py.  ``section`` records the policy's origin in the
    effective evaluation order ("local", "global-header", "global-footer").
    """
    section_title = _is_section_title(raw)

    # Basic fields
    policyid = raw.get("policyid", 0)
    name = raw.get("name", "")
    comments = raw.get("comments", "")
    global_label = raw.get("global-label", "")

    # Map action / status
    action = _ACTION_MAP.get(raw.get("action"), PolicyAction.UNKNOWN)
    status = _STATUS_MAP.get(raw.get("status"), "unknown")

    # List-type fields (raw names, not yet resolved)
    srcintf = _extract_name_list(raw.get("srcintf"))
    dstintf = _extract_name_list(raw.get("dstintf"))
    srcaddr = _extract_name_list(raw.get("srcaddr"))
    dstaddr = _extract_name_list(raw.get("dstaddr"))
    service = _extract_name_list(raw.get("service"))
    schedule = _extract_name_list(raw.get("schedule"))

    # Per-policy install scope
    scope_state, scope_members = _extract_scope(
        raw,
        modern_scope_semantics=modern_scope_semantics,
    )
    if scope_state == "default":
        install_scope = InstallScope.global_scope()
    elif scope_state in {"none", "unknown"}:
        install_scope = InstallScope.no_targets()
    else:
        install_scope = InstallScope.from_scope_members(
            scope_members,
            group_map=group_map,
        )

    # obj seq (FMG internal ordering field)
    obj_seq = raw.get("obj seq", raw.get("obj_seq"))

    # Security/UTM profile references
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
        srcintf=(
            InterfaceSet.from_names(srcintf)
            if srcintf
            else InterfaceSet.any()
        ),
        dstintf=(
            InterfaceSet.from_names(dstintf)
            if dstintf
            else InterfaceSet.any()
        ),
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
        policy_section=section,
    )

    for description in _unmodeled_match_descriptions(raw, action):
        policy.has_unresolved = True
        policy.unresolved_notes.append(
            "unsupported match criterion:{}".format(description)
        )
    if _contains_dynamic_mapping(raw):
        policy.has_unresolved = True
        policy.unresolved_notes.append(
            "unsupported per-device/per-platform dynamic mapping"
        )
    if action == PolicyAction.IPSEC:
        policy.has_unresolved = True
        policy.unresolved_notes.append(
            "unsupported action semantics:policy-based IPsec"
        )
    elif action == PolicyAction.UNKNOWN:
        policy.has_unresolved = True
        policy.unresolved_notes.append("unsupported policy action")
    if status == "unknown":
        policy.has_unresolved = True
        policy.unresolved_notes.append("unsupported policy status")
    if scope_state == "unknown":
        policy.has_unresolved = True
        policy.unresolved_notes.append(
            "ambiguous per-policy install scope in FortiManager response"
        )
    for field, values in (
        ("source interface", srcintf),
        ("destination interface", dstintf),
        ("source address", srcaddr),
        ("destination address", dstaddr),
        ("service", service),
        ("schedule", schedule),
    ):
        if not values:
            policy.has_unresolved = True
            policy.unresolved_notes.append(
                "missing core match field:{}".format(field)
            )

    # Store raw name lists in raw_data for later resolution by objects.py.
    policy.raw_data["_raw_srcintf"] = srcintf
    policy.raw_data["_raw_dstintf"] = dstintf
    policy.raw_data["_raw_srcaddr"] = srcaddr
    policy.raw_data["_raw_dstaddr"] = dstaddr
    policy.raw_data["_raw_service"] = service
    policy.raw_data["_raw_schedule"] = schedule
    policy.raw_data["_raw_scope"] = scope_members or []

    return policy


# ---------------------------------------------------------------------------
# Core policy fetch
# ---------------------------------------------------------------------------

def fetch_policies(
    client,
    adom: str,
    package: str,
    include_disabled: bool = False,
    group_map: Optional[Dict[str, Set[Tuple[str, str]]]] = None,
    modern_scope_semantics: Optional[bool] = None,
) -> List[CanonicalPolicy]:
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
    # Per-policy installation targets ("Install On") are NOT included in
    # the default response — not even with loadsub=1.  They are returned
    # under the "scope member" key only when option=["scope member"] is
    # explicitly requested.  Without this, every policy appears to have
    # global scope, causing rules that target different device groups to
    # be compared against each other incorrectly.
    result = client.get(url, option=["scope member"])

    if not isinstance(result, list):
        if result is None:
            log.warning("No policies found in %s/%s", adom, package)
            return []
        log.warning(
            "Unexpected policy response for %s/%s: %s", adom, package, type(result)
        )
        return []

    policies: List[CanonicalPolicy] = []

    for seq_num, raw in enumerate(result):
        if not isinstance(raw, dict):
            log.debug("Skipping non-dict policy entry at seq %d", seq_num)
            continue

        policy = _build_policy(
            raw,
            adom,
            package,
            seq_num,
            group_map=group_map,
            section="local",
            modern_scope_semantics=modern_scope_semantics,
        )
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
# Global header / footer policy fetch
# ---------------------------------------------------------------------------

def fetch_global_policies(
    client,
    adom: str,
    package: str,
    section: str,
    group_map: Optional[Dict[str, Set[Tuple[str, str]]]] = None,
    modern_scope_semantics: Optional[bool] = None,
) -> List[CanonicalPolicy]:
    """
    Fetch the global header or footer policies inherited by an ADOM package.

    When a global-database policy package is assigned to an ADOM policy
    package, its header policies are evaluated before all package-defined
    rules and its footer policies after. FMG exposes the per-package view of
    these via:

        /pm/config/adom/{adom}/pkg/{package}/global/header/policy
        /pm/config/adom/{adom}/pkg/{package}/global/footer/policy

    The object references in these policies (e.g. ``gall``, ``galways``) are
    mirrored into the ADOM object database, so the standard ADOM ObjectResolver
    resolves them — no separate global-scope resolver is required.

    Args:
        client: FMGClient instance.
        adom: ADOM name.
        package: policy package path.
        section: "global-header" or "global-footer".
        group_map: optional device-group expansion map for install scope.

    Returns:
        List of CanonicalPolicy in evaluation order.  Empty if the package has
        no global policies assigned, or if the request fails (logged, not
        raised — global policies are supplemental and must not abort analysis).
    """
    kind = "header" if section == "global-header" else "footer"
    url = f"/pm/config/adom/{adom}/pkg/{package}/global/{kind}/policy"

    # Per-policy install targets are returned under "scope member" only when
    # the option is explicitly requested (same as package-defined rules).
    try:
        result = client.get(url, option=["scope member"])
    except Exception as exc:
        log.warning(
            "Could not fetch global %s policies for %s/%s: %s",
            kind, adom, package, exc,
        )
        return []

    if not isinstance(result, list):
        if result is not None:
            log.debug(
                "Unexpected global %s policy response for %s/%s: %s",
                kind, adom, package, type(result),
            )
        return []

    policies: List[CanonicalPolicy] = []
    for seq_num, raw in enumerate(result):
        if not isinstance(raw, dict):
            continue
        policies.append(
            _build_policy(
                raw,
                adom,
                package,
                seq_num,
                group_map=group_map,
                section=section,
                modern_scope_semantics=modern_scope_semantics,
            )
        )

    if policies:
        log.info(
            "Fetched %d global %s policies for %s/%s",
            len(policies), kind, adom, package,
        )

    return policies


# ---------------------------------------------------------------------------
# Bulk fetch with referenced objects
# ---------------------------------------------------------------------------

def fetch_policies_with_objects(
    client,
    adom: str,
    package: str,
) -> Tuple[List[CanonicalPolicy], Optional[dict]]:
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
            collected: Dict[str, dict] = {}
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
            objects: Dict[str, dict] = {}
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
    client, adom: str, policies: List[CanonicalPolicy]
) -> Optional[dict]:
    """
    Collect all unique object names from policies and fetch them
    individually by object type.
    """
    # Collect unique names per field
    addr_names: Set[str] = set()
    svc_names: Set[str] = set()
    schedule_names: Set[str] = set()

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
