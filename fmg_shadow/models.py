"""
Canonical internal data models for policy shadow analysis.

All FMG objects are normalized into these representations for
accurate, vendor-agnostic comparison.
"""

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

__version__ = "1.3.0"


# ---------------------------------------------------------------------------
# IP / Network interval representation
# ---------------------------------------------------------------------------

@dataclass(frozen=True, order=True)
class IPInterval:
    """A contiguous range of IPv4 addresses [start, end] inclusive."""
    start: int  # 32-bit integer
    end: int    # 32-bit integer

    @classmethod
    def from_subnet(cls, ip_str: str, mask_str: str) -> "IPInterval":
        """Create from ip + netmask strings (FMG ipmask format)."""
        net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
        return cls(int(net.network_address), int(net.broadcast_address))

    @classmethod
    def from_cidr(cls, cidr: str) -> "IPInterval":
        net = ipaddress.IPv4Network(cidr, strict=False)
        return cls(int(net.network_address), int(net.broadcast_address))

    @classmethod
    def from_range(cls, start_ip: str, end_ip: str) -> "IPInterval":
        return cls(int(ipaddress.IPv4Address(start_ip)),
                   int(ipaddress.IPv4Address(end_ip)))

    @classmethod
    def from_host(cls, ip_str: str) -> "IPInterval":
        addr = int(ipaddress.IPv4Address(ip_str))
        return cls(addr, addr)

    @classmethod
    def any(cls) -> "IPInterval":
        return cls(0, 0xFFFFFFFF)

    def contains(self, other: "IPInterval") -> bool:
        return self.start <= other.start and self.end >= other.end

    def overlaps(self, other: "IPInterval") -> bool:
        return self.start <= other.end and self.end >= other.start

    def intersection(self, other: "IPInterval") -> Optional["IPInterval"]:
        lo = max(self.start, other.start)
        hi = min(self.end, other.end)
        if lo <= hi:
            return IPInterval(lo, hi)
        return None

    def size(self) -> int:
        return self.end - self.start + 1

    def __repr__(self):
        s = str(ipaddress.IPv4Address(self.start))
        e = str(ipaddress.IPv4Address(self.end))
        if s == e:
            return s
        return f"{s}-{e}"


# ---------------------------------------------------------------------------
# Port interval
# ---------------------------------------------------------------------------

@dataclass(frozen=True, order=True)
class PortInterval:
    """A contiguous range of ports [start, end] inclusive."""
    start: int
    end: int

    @classmethod
    def any(cls) -> "PortInterval":
        return cls(0, 65535)

    @classmethod
    def single(cls, port: int) -> "PortInterval":
        return cls(port, port)

    def contains(self, other: "PortInterval") -> bool:
        return self.start <= other.start and self.end >= other.end

    def overlaps(self, other: "PortInterval") -> bool:
        return self.start <= other.end and self.end >= other.start

    def intersection(self, other: "PortInterval") -> Optional["PortInterval"]:
        lo = max(self.start, other.start)
        hi = min(self.end, other.end)
        if lo <= hi:
            return PortInterval(lo, hi)
        return None

    def size(self) -> int:
        return self.end - self.start + 1

    def __repr__(self):
        if self.start == self.end:
            return str(self.start)
        return f"{self.start}-{self.end}"


# ---------------------------------------------------------------------------
# Protocol-aware service spec
# ---------------------------------------------------------------------------

class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"
    ICMP = "icmp"
    IP = "ip"          # raw protocol number
    ANY = "any"        # ALL services


@dataclass(frozen=True)
class ServiceSpec:
    """
    A single protocol+port spec.
    For TCP/UDP/SCTP: protocol + src port range + dst port range.
    For ICMP: protocol + type + code.
    For IP: protocol number.
    For ANY: matches everything.
    """
    protocol: Protocol
    dst_ports: Optional[PortInterval] = None   # TCP/UDP/SCTP
    src_ports: Optional[PortInterval] = None   # TCP/UDP/SCTP (rarely used)
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    ip_protocol: Optional[int] = None          # raw protocol number

    @classmethod
    def any(cls) -> "ServiceSpec":
        return cls(protocol=Protocol.ANY)

    def is_any(self) -> bool:
        return self.protocol == Protocol.ANY

    def contains(self, other: "ServiceSpec") -> bool:
        """Does self fully contain other's match space?"""
        if self.is_any():
            return True
        if other.is_any():
            return False
        if self.protocol != other.protocol:
            return False
        if self.protocol in (Protocol.TCP, Protocol.UDP, Protocol.SCTP):
            dst_ok = (self.dst_ports or PortInterval.any()).contains(
                other.dst_ports or PortInterval.any())
            src_ok = (self.src_ports or PortInterval.any()).contains(
                other.src_ports or PortInterval.any())
            return dst_ok and src_ok
        if self.protocol == Protocol.ICMP:
            type_ok = (self.icmp_type is None or self.icmp_type == other.icmp_type)
            code_ok = (self.icmp_code is None or self.icmp_code == other.icmp_code)
            return type_ok and code_ok
        if self.protocol == Protocol.IP:
            return self.ip_protocol == other.ip_protocol
        return False

    def overlaps(self, other: "ServiceSpec") -> bool:
        if self.is_any() or other.is_any():
            return True
        if self.protocol != other.protocol:
            return False
        if self.protocol in (Protocol.TCP, Protocol.UDP, Protocol.SCTP):
            dst_ovlp = (self.dst_ports or PortInterval.any()).overlaps(
                other.dst_ports or PortInterval.any())
            src_ovlp = (self.src_ports or PortInterval.any()).overlaps(
                other.src_ports or PortInterval.any())
            return dst_ovlp and src_ovlp
        if self.protocol == Protocol.ICMP:
            type_ok = (self.icmp_type is None or other.icmp_type is None or
                       self.icmp_type == other.icmp_type)
            code_ok = (self.icmp_code is None or other.icmp_code is None or
                       self.icmp_code == other.icmp_code)
            return type_ok and code_ok
        if self.protocol == Protocol.IP:
            return self.ip_protocol == other.ip_protocol
        return False


# ---------------------------------------------------------------------------
# Address set — a union of IP intervals
# ---------------------------------------------------------------------------

@dataclass
class AddressSet:
    """
    A set of IP intervals representing the union of address space.
    Supports set operations for shadow analysis.
    """
    intervals: List[IPInterval] = field(default_factory=list)
    is_any: bool = False
    # Track unresolvable components
    unresolved_names: List[str] = field(default_factory=list)

    @classmethod
    def any(cls) -> "AddressSet":
        return cls(intervals=[IPInterval.any()], is_any=True)

    @classmethod
    def empty(cls) -> "AddressSet":
        return cls(intervals=[])

    @classmethod
    def from_intervals(cls, intervals: List[IPInterval]) -> "AddressSet":
        s = cls(intervals=sorted(intervals))
        s._merge()
        return s

    def _merge(self):
        """Merge overlapping/adjacent intervals."""
        if len(self.intervals) <= 1:
            return
        self.intervals.sort()
        merged = [self.intervals[0]]
        for iv in self.intervals[1:]:
            if iv.start <= merged[-1].end + 1:
                merged[-1] = IPInterval(merged[-1].start, max(merged[-1].end, iv.end))
            else:
                merged.append(iv)
        self.intervals = merged

    def total_size(self) -> int:
        return sum(iv.size() for iv in self.intervals)

    def contains(self, other: "AddressSet") -> bool:
        """Does self fully contain other?"""
        if self.is_any:
            return True
        if other.is_any:
            return False
        if other.unresolved_names:
            return False  # conservative
        for oiv in other.intervals:
            covered = False
            for siv in self.intervals:
                if siv.contains(oiv):
                    covered = True
                    break
            if not covered:
                return False
        return True

    def overlaps(self, other: "AddressSet") -> bool:
        if self.is_any or other.is_any:
            return True
        for siv in self.intervals:
            for oiv in other.intervals:
                if siv.overlaps(oiv):
                    return True
        return False

    def intersection(self, other: "AddressSet") -> "AddressSet":
        if self.is_any:
            return AddressSet(intervals=list(other.intervals),
                              unresolved_names=list(other.unresolved_names))
        if other.is_any:
            return AddressSet(intervals=list(self.intervals),
                              unresolved_names=list(self.unresolved_names))
        result = []
        for siv in self.intervals:
            for oiv in other.intervals:
                inter = siv.intersection(oiv)
                if inter:
                    result.append(inter)
        unresolved = list(set(self.unresolved_names + other.unresolved_names))
        return AddressSet.from_intervals(result) if not unresolved else \
            AddressSet(intervals=sorted(result), unresolved_names=unresolved)

    def union(self, other: "AddressSet") -> "AddressSet":
        if self.is_any or other.is_any:
            result = AddressSet.any()
            # Preserve semantic uncertainty even when the interval union is
            # mathematically ANY.  Some unresolved objects (notably VIPs)
            # also carry policy-priority semantics outside address algebra.
            result.unresolved_names = list(set(
                self.unresolved_names + other.unresolved_names
            ))
            return result
        combined = list(self.intervals) + list(other.intervals)
        unresolved = list(set(self.unresolved_names + other.unresolved_names))
        result = AddressSet.from_intervals(combined)
        result.unresolved_names = unresolved
        return result

    def subtract(self, other: "AddressSet") -> "AddressSet":
        """Return self - other (intervals in self not covered by other)."""
        if other.is_any:
            return AddressSet.empty()
        if self.is_any:
            # Can't subtract from ANY precisely, return ANY minus other's intervals
            # For practical purposes, we work with concrete intervals
            remaining = [IPInterval.any()]
        else:
            remaining = list(self.intervals)

        for sub_iv in other.intervals:
            new_remaining = []
            for iv in remaining:
                # subtract sub_iv from iv
                if not iv.overlaps(sub_iv):
                    new_remaining.append(iv)
                else:
                    # left portion
                    if iv.start < sub_iv.start:
                        new_remaining.append(IPInterval(iv.start, sub_iv.start - 1))
                    # right portion
                    if iv.end > sub_iv.end:
                        new_remaining.append(IPInterval(sub_iv.end + 1, iv.end))
            remaining = new_remaining

        result = AddressSet.from_intervals(remaining)
        result.unresolved_names = list(self.unresolved_names)
        return result

    def is_empty(self) -> bool:
        return not self.intervals and not self.unresolved_names

    def describe(self) -> str:
        if self.is_any:
            return "any"
        if not self.intervals and not self.unresolved_names:
            return "empty"
        parts = [repr(iv) for iv in self.intervals[:5]]
        if len(self.intervals) > 5:
            parts.append(f"...+{len(self.intervals)-5} more")
        if self.unresolved_names:
            parts.append(f"[unresolved: {', '.join(self.unresolved_names)}]")
        return ", ".join(parts)

    def breadth_category(self) -> str:
        """Categorize the breadth of the address space."""
        if self.is_any:
            return "any"  # 0.0.0.0/0 - all traffic
        total = self.total_size()
        if total == 0:
            return "empty"
        if total == 1:
            return "host"  # single host
        if total <= 256:
            return "small"  # /24 or smaller
        if total <= 65536:
            return "medium"  # /16 or smaller
        if total <= 16777216:
            return "large"  # /8 or smaller
        return "massive"  # larger than /8


# ---------------------------------------------------------------------------
# Service set
# ---------------------------------------------------------------------------

@dataclass
class ServiceSet:
    """A set of service specs."""
    specs: List[ServiceSpec] = field(default_factory=list)
    is_any: bool = False
    unresolved_names: List[str] = field(default_factory=list)

    @classmethod
    def any(cls) -> "ServiceSet":
        return cls(specs=[ServiceSpec.any()], is_any=True)

    @classmethod
    def empty(cls) -> "ServiceSet":
        return cls(specs=[])

    def contains(self, other: "ServiceSet") -> bool:
        if self.is_any:
            return True
        if other.is_any:
            return False
        if other.unresolved_names:
            return False
        # Each spec in other must be contained by at least one spec in self
        for ospec in other.specs:
            covered = any(sspec.contains(ospec) for sspec in self.specs)
            if not covered:
                return False
        return True

    def overlaps(self, other: "ServiceSet") -> bool:
        if self.is_any or other.is_any:
            return True
        for sspec in self.specs:
            for ospec in other.specs:
                if sspec.overlaps(ospec):
                    return True
        return False

    def describe(self) -> str:
        if self.is_any:
            return "ALL"
        if not self.specs:
            return "empty"
        parts = []
        for s in self.specs[:5]:
            if s.protocol in (Protocol.TCP, Protocol.UDP, Protocol.SCTP):
                p = f"{s.protocol.value}/{s.dst_ports}" if s.dst_ports else s.protocol.value
                parts.append(p)
            elif s.protocol == Protocol.ICMP:
                parts.append(f"icmp/{s.icmp_type or '*'}/{s.icmp_code or '*'}")
            elif s.protocol == Protocol.IP:
                parts.append(f"ip/{s.ip_protocol}")
            else:
                parts.append(str(s.protocol.value))
        if len(self.specs) > 5:
            parts.append(f"...+{len(self.specs)-5}")
        if self.unresolved_names:
            parts.append(f"[unresolved: {', '.join(self.unresolved_names)}]")
        return ", ".join(parts)


# ---------------------------------------------------------------------------
# Interface set
# ---------------------------------------------------------------------------

@dataclass
class InterfaceSet:
    """A set of interface names. 'any' means all interfaces."""
    names: Set[str] = field(default_factory=set)
    is_any: bool = False

    @classmethod
    def any(cls) -> "InterfaceSet":
        return cls(names=set(), is_any=True)

    @classmethod
    def from_names(cls, names: List[str]) -> "InterfaceSet":
        normalized = set()
        for n in names:
            n = n.strip().lower()
            if n == "any":
                return cls.any()
            normalized.add(n)
        return cls(names=normalized)

    def contains(self, other: "InterfaceSet") -> bool:
        if self.is_any:
            return True
        if other.is_any:
            return False
        return other.names.issubset(self.names)

    def overlaps(self, other: "InterfaceSet") -> bool:
        if self.is_any or other.is_any:
            return True
        return bool(self.names & other.names)

    def intersection(self, other: "InterfaceSet") -> "InterfaceSet":
        if self.is_any:
            return InterfaceSet(names=set(other.names), is_any=other.is_any)
        if other.is_any:
            return InterfaceSet(names=set(self.names), is_any=self.is_any)
        return InterfaceSet(names=self.names & other.names)

    def describe(self) -> str:
        if self.is_any:
            return "any"
        return ", ".join(sorted(self.names)) or "none"


# ---------------------------------------------------------------------------
# Schedule
# ---------------------------------------------------------------------------

@dataclass
class ScheduleSpec:
    """
    Canonical schedule representation.
    For simplicity in v1, we track:
    - always (covers all time)
    - recurring: weekday set + time range
    - onetime: start/end datetime
    - unresolved: name we couldn't expand
    """
    is_always: bool = False
    # Recurring
    weekdays: Optional[Set[int]] = None  # 0=Sunday...6=Saturday
    start_time: Optional[str] = None     # "HH:MM"
    end_time: Optional[str] = None       # "HH:MM"
    # Onetime
    start_datetime: Optional[str] = None
    end_datetime: Optional[str] = None
    # Fallback
    unresolved_name: Optional[str] = None
    raw_name: str = "always"

    @classmethod
    def always(cls) -> "ScheduleSpec":
        return cls(is_always=True, raw_name="always")

    def contains(self, other: "ScheduleSpec") -> bool:
        """Does self fully contain other's time window?"""
        if self.is_always:
            return True
        if other.is_always:
            return False
        if self.unresolved_name or other.unresolved_name:
            return False  # conservative
        # Same recurring schedule comparison
        if self.weekdays is not None and other.weekdays is not None:
            if not other.weekdays.issubset(self.weekdays):
                return False
            # Time range comparison (simplified: HH:MM string compare works for same-day)
            if self.start_time and other.start_time:
                if other.start_time < self.start_time:
                    return False
            if self.end_time and other.end_time:
                if other.end_time > self.end_time:
                    return False
            return True
        return False

    def overlaps(self, other: "ScheduleSpec") -> bool:
        if self.is_always or other.is_always:
            return True
        if self.unresolved_name or other.unresolved_name:
            return True  # conservative: assume overlap when uncertain
        if self.weekdays is not None and other.weekdays is not None:
            if not (self.weekdays & other.weekdays):
                return False
            # Check time overlap on shared weekdays
            if self.start_time and self.end_time and other.start_time and other.end_time:
                return self.start_time <= other.end_time and self.end_time >= other.start_time
            return True  # partial info => assume overlap
        return True  # different schedule types => assume overlap (conservative)

    def describe(self) -> str:
        if self.is_always:
            return "always"
        if self.unresolved_name:
            return f"[unresolved: {self.unresolved_name}]"
        if self.weekdays is not None:
            day_names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
            days = ", ".join(day_names[d] for d in sorted(self.weekdays))
            time_str = ""
            if self.start_time and self.end_time:
                time_str = f" {self.start_time}-{self.end_time}"
            return f"recurring({days}{time_str})"
        if self.start_datetime and self.end_datetime:
            return f"onetime({self.start_datetime} to {self.end_datetime})"
        return self.raw_name


# ---------------------------------------------------------------------------
# Install Scope
# ---------------------------------------------------------------------------

@dataclass
class InstallScope:
    """
    Represents the installation target scope of a policy or package.
    If is_global is True, applies to all targets in the package.
    Otherwise, targets is a set of (device_name, vdom) tuples.
    """
    is_global: bool = True
    targets: Set[Tuple[str, str]] = field(default_factory=set)

    @classmethod
    def global_scope(cls) -> "InstallScope":
        return cls(is_global=True)

    @classmethod
    def no_targets(cls) -> "InstallScope":
        """A policy explicitly configured with ``Install On: None``."""
        return cls(is_global=False, targets=set())

    @classmethod
    def from_scope_members(
        cls,
        members: List[dict],
        group_map: Optional[Dict[str, Set[Tuple[str, str]]]] = None,
    ) -> "InstallScope":
        if not members:
            return cls.global_scope()
        targets = set()
        for m in members:
            name = m.get("name", "")
            vdom = m.get("vdom", "")
            if not name:
                continue
            key = name.lower()

            # Determine if this scope entry refers to a device group.
            # FMG signals this in two ways:
            #   1. Explicit "is group" flag (true / 1)
            #   2. Absence of "vdom" key — per FMG API docs, a name
            #      without a vdom is treated as a device group name.
            is_group_flag = m.get("is group", m.get("is_group", False))
            is_group = bool(is_group_flag) or ("vdom" not in m)

            if is_group and group_map and key in group_map:
                # Expand device group to its individual member devices
                expanded = group_map[key]
                if expanded:
                    targets.update(expanded)
                else:
                    # Group exists but has no members — use opaque ID
                    # so it still overlaps with the same group name.
                    targets.add((f"__group__{key}", "__group__"))
            elif not is_group and group_map and key in group_map:
                # Name happens to match a group but has vdom set —
                # still expand (defensive: FMG isn't always consistent)
                expanded = group_map[key]
                if expanded:
                    targets.update(expanded)
                else:
                    targets.add((f"__group__{key}", "__group__"))
            elif is_group and group_map is not None and key not in group_map:
                # Known to be a group but not in our group_map — treat
                # as an opaque group identifier so it only overlaps with
                # itself (never with real device names).
                targets.add((f"__group__{key}", "__group__"))
            else:
                # Individual device
                targets.add((key, (vdom or "root").lower()))
        return cls(is_global=False, targets=targets)

    def overlaps(self, other: "InstallScope") -> bool:
        if (not self.is_global and not self.targets) or (
            not other.is_global and not other.targets
        ):
            return False
        if self.is_global or other.is_global:
            return True
        return bool(self.targets & other.targets)

    def contains(self, other: "InstallScope") -> bool:
        """Return whether this scope covers every target in *other*.

        A package-wide (global) scope contains every specific scope.  A
        specific scope cannot contain a package-wide scope, and two specific
        scopes use normal set containment.  An empty non-global scope means
        that a policy has no installation targets, so it never proves
        containment.
        """
        if (not self.is_global and not self.targets) or (
            not other.is_global and not other.targets
        ):
            return False
        if self.is_global:
            return True
        if other.is_global:
            return False
        return self.targets.issuperset(other.targets)

    def describe(self) -> str:
        if self.is_global:
            return "all targets"
        if not self.targets:
            return "no targets"
        return ", ".join(f"{n}/{v}" for n, v in sorted(self.targets))


# ---------------------------------------------------------------------------
# Policy action
# ---------------------------------------------------------------------------

class PolicyAction(Enum):
    DENY = "deny"
    ACCEPT = "accept"
    IPSEC = "ipsec"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Canonical Policy
# ---------------------------------------------------------------------------

@dataclass
class CanonicalPolicy:
    """A fully resolved, normalized firewall policy."""
    # Identity
    fmg: str = ""
    adom: str = ""
    package: str = ""
    policyid: int = 0
    name: str = ""
    seq_num: int = 0          # position in evaluation order (0-indexed)
    obj_seq: Optional[int] = None

    # Match dimensions
    srcintf: InterfaceSet = field(default_factory=InterfaceSet.any)
    dstintf: InterfaceSet = field(default_factory=InterfaceSet.any)
    srcaddr: AddressSet = field(default_factory=AddressSet.any)
    dstaddr: AddressSet = field(default_factory=AddressSet.any)
    service: ServiceSet = field(default_factory=ServiceSet.any)
    schedule: ScheduleSpec = field(default_factory=ScheduleSpec.always)

    # Negation flags — when True the dimension matches everything EXCEPT the set
    srcaddr_negate: bool = False
    dstaddr_negate: bool = False
    service_negate: bool = False

    # Decision
    action: PolicyAction = PolicyAction.ACCEPT
    status: str = "enable"    # enable / disable

    # Install scope
    install_scope: InstallScope = field(default_factory=InstallScope.global_scope)

    # Metadata
    is_section_title: bool = False
    global_label: str = ""
    comments: str = ""
    raw_data: dict = field(default_factory=dict)

    # Origin within the effective evaluation order. Rules defined directly in
    # the ADOM policy package use the internal value "local"; inherited global
    # policies are "global-header" (evaluated first) or "global-footer"
    # (evaluated last).
    policy_section: str = "local"

    # Security profiles (UTM inspection profiles)
    security_profiles: Dict[str, str] = field(default_factory=dict)

    # Flags for unresolved/unsupported elements
    has_unresolved: bool = False
    unresolved_notes: List[str] = field(default_factory=list)

    def is_effective(self, include_disabled: bool = False) -> bool:
        """Is this policy part of the active evaluation chain?"""
        if self.is_section_title:
            return False
        if not self.install_scope.is_global and not self.install_scope.targets:
            return False
        if not include_disabled and self.status == "disable":
            return False
        return True

    def label(self) -> str:
        """Human-readable label for this policy."""
        name_part = f" ({self.name})" if self.name else ""
        section_part = ""
        if self.policy_section == "global-header":
            section_part = "[global-header] "
        elif self.policy_section == "global-footer":
            section_part = "[global-footer] "
        return f"{section_part}#{self.seq_num+1} policyid={self.policyid}{name_part}"


# ---------------------------------------------------------------------------
# Finding types
# ---------------------------------------------------------------------------

class FindingType(Enum):
    FULL_CONFLICT_SHADOW = "full_conflict_shadow"
    PARTIAL_CONFLICT_SHADOW = "partial_conflict_shadow"
    FULL_REDUNDANT_COVERAGE = "full_redundant_coverage"
    PARTIAL_REDUNDANT_OVERLAP = "partial_redundant_overlap"
    INDETERMINATE = "indeterminate_due_to_unsupported_objects"


class Confidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ---------------------------------------------------------------------------
# Shadow Finding
# ---------------------------------------------------------------------------

@dataclass
class ShadowFinding:
    """A single shadow analysis finding."""
    # Context
    fmg: str = ""
    adom: str = ""
    package: str = ""

    # Shadowed rule
    shadowed_policyid: int = 0
    shadowed_name: str = ""
    shadowed_seq: int = 0
    shadowed_section: str = "local"  # local / global-header / global-footer

    # Classification
    finding_type: FindingType = FindingType.INDETERMINATE
    is_composite: bool = False  # multiple earlier rules needed

    # Shadowing rule(s)
    shadowing_policyids: List[int] = field(default_factory=list)
    shadowing_names: List[str] = field(default_factory=list)
    shadowing_seqs: List[int] = field(default_factory=list)
    shadowing_sections: List[str] = field(default_factory=list)

    # Dimension overlap details
    srcintf_overlap: str = ""
    dstintf_overlap: str = ""
    srcaddr_overlap: str = ""
    dstaddr_overlap: str = ""
    service_overlap: str = ""
    schedule_overlap: str = ""

    # Reachability
    is_fully_unreachable: bool = False
    residual_description: str = ""

    # Action comparison
    shadowed_action: str = ""
    shadowing_action: str = ""
    same_action: bool = False

    # Confidence
    confidence: Confidence = Confidence.HIGH
    unsupported_notes: List[str] = field(default_factory=list)

    # Explanation
    explanation: str = ""

    # Risk scoring
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)

    def severity_label(self) -> str:
        # Base severity from finding type (industry-aligned classifications)
        # Fully Shadowed (Conflict) = CRITICAL, Partially Shadowed (Conflict) = HIGH,
        # Fully Shadowed (Redundant) = MEDIUM, Partially Overlapping (Redundant) = LOW,
        # Indeterminate (Unresolved Objects) = INFO
        base_severity_map = {
            FindingType.FULL_CONFLICT_SHADOW: "CRITICAL",
            FindingType.PARTIAL_CONFLICT_SHADOW: "HIGH",
            FindingType.FULL_REDUNDANT_COVERAGE: "MEDIUM",
            FindingType.PARTIAL_REDUNDANT_OVERLAP: "LOW",
            FindingType.INDETERMINATE: "INFO",
        }
        base = base_severity_map.get(self.finding_type, "INFO")

        # Risk-score-based upgrade (never downgrade)
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        base_idx = severity_order.index(base)

        if self.risk_score >= 9.0:
            upgraded_idx = severity_order.index("CRITICAL")
        elif self.risk_score >= 7.0:
            upgraded_idx = severity_order.index("HIGH")
        elif self.risk_score >= 4.0:
            upgraded_idx = severity_order.index("MEDIUM")
        else:
            upgraded_idx = 0  # no upgrade

        final_idx = max(base_idx, upgraded_idx)
        return severity_order[final_idx]

    def to_dict(self) -> dict:
        return {
            "fmg": self.fmg,
            "adom": self.adom,
            "package": self.package,
            "shadowed_policyid": self.shadowed_policyid,
            "shadowed_name": self.shadowed_name,
            "shadowed_seq": self.shadowed_seq,
            "shadowed_section": self.shadowed_section,
            "finding_type": self.finding_type.value,
            "is_composite": self.is_composite,
            "shadowing_policyids": self.shadowing_policyids,
            "shadowing_names": self.shadowing_names,
            "shadowing_seqs": self.shadowing_seqs,
            "shadowing_sections": self.shadowing_sections,
            "srcintf_overlap": self.srcintf_overlap,
            "dstintf_overlap": self.dstintf_overlap,
            "srcaddr_overlap": self.srcaddr_overlap,
            "dstaddr_overlap": self.dstaddr_overlap,
            "service_overlap": self.service_overlap,
            "schedule_overlap": self.schedule_overlap,
            "is_fully_unreachable": self.is_fully_unreachable,
            "residual_description": self.residual_description,
            "shadowed_action": self.shadowed_action,
            "shadowing_action": self.shadowing_action,
            "same_action": self.same_action,
            "confidence": self.confidence.value,
            "unsupported_notes": self.unsupported_notes,
            "explanation": self.explanation,
            "severity": self.severity_label(),
            "risk_score": self.risk_score,
            "risk_factors": self.risk_factors,
        }


# ---------------------------------------------------------------------------
# Package result
# ---------------------------------------------------------------------------

@dataclass
class PackageResult:
    """Results for a single policy package analysis."""
    fmg: str = ""
    adom: str = ""
    package: str = ""
    total_policies: int = 0
    effective_policies: int = 0
    # Breakdown of where the analyzed policies came from.  total_policies
    # includes global header + local + global footer; local can be derived as
    # total - global_header_policies - global_footer_policies.
    global_header_policies: int = 0
    global_footer_policies: int = 0
    findings: List[ShadowFinding] = field(default_factory=list)
    policies: List[CanonicalPolicy] = field(default_factory=list)
    unsupported_objects: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    @property
    def full_conflict_count(self) -> int:
        return sum(1 for f in self.findings if f.finding_type == FindingType.FULL_CONFLICT_SHADOW)

    @property
    def partial_conflict_count(self) -> int:
        return sum(1 for f in self.findings if f.finding_type == FindingType.PARTIAL_CONFLICT_SHADOW)

    @property
    def full_redundant_count(self) -> int:
        return sum(1 for f in self.findings if f.finding_type == FindingType.FULL_REDUNDANT_COVERAGE)

    @property
    def partial_redundant_count(self) -> int:
        return sum(1 for f in self.findings if f.finding_type == FindingType.PARTIAL_REDUNDANT_OVERLAP)

    @property
    def indeterminate_count(self) -> int:
        return sum(1 for f in self.findings if f.finding_type == FindingType.INDETERMINATE)


# ---------------------------------------------------------------------------
# Run result
# ---------------------------------------------------------------------------

@dataclass
class RunResult:
    """Aggregate results for the entire analysis run."""
    tool_version: str = __version__
    run_timestamp: str = ""
    package_results: List[PackageResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    @property
    def total_findings(self) -> int:
        return sum(len(pr.findings) for pr in self.package_results)

    @property
    def total_policies(self) -> int:
        return sum(pr.total_policies for pr in self.package_results)

    def summary_counts(self) -> dict:
        return {
            "packages_analyzed": len(self.package_results),
            "total_policies": self.total_policies,
            "total_findings": self.total_findings,
            "full_conflict_shadow": sum(pr.full_conflict_count for pr in self.package_results),
            "partial_conflict_shadow": sum(pr.partial_conflict_count for pr in self.package_results),
            "full_redundant_coverage": sum(pr.full_redundant_count for pr in self.package_results),
            "partial_redundant_overlap": sum(pr.partial_redundant_count for pr in self.package_results),
            "indeterminate": sum(pr.indeterminate_count for pr in self.package_results),
            "errors": len(self.errors) + sum(len(pr.errors) for pr in self.package_results),
        }
