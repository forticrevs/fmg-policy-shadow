"""
Object retrieval, expansion, and canonical normalization for FMG objects.

Fetches address, service, and schedule objects from FortiManager,
resolves groups recursively, and normalizes everything into the
canonical model types defined in models.py.
"""

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import (
    AddressSet,
    CanonicalPolicy,
    IPInterval,
    PortInterval,
    Protocol,
    ScheduleSpec,
    ServiceSet,
    ServiceSpec,
)

logger = logging.getLogger(__name__)

# Pagination page size for bulk fetches
_PAGE_SIZE = 5000

# Maximum recursion depth for group resolution
_MAX_DEPTH = 10

# Weekday name -> index mapping (FMG uses lowercase weekday names)
_WEEKDAY_MAP = {
    "sunday": 0,
    "monday": 1,
    "tuesday": 2,
    "wednesday": 3,
    "thursday": 4,
    "friday": 5,
    "saturday": 6,
}


def _parse_port_range(spec: str) -> Tuple[PortInterval, Optional[PortInterval]]:
    """Parse FMG port range string like '80', '80-443', '80:1024-65535'.

    Returns (dst_ports, src_ports). src_ports is None if not specified.
    Format: dst or dst-dst or dst:src-src or dst-dst:src-src
    """
    src_ports = None
    dst_part = spec
    if ":" in spec:
        dst_part, src_part = spec.split(":", 1)
        if "-" in src_part:
            lo, hi = src_part.split("-", 1)
            src_ports = PortInterval(int(lo), int(hi))
        else:
            src_ports = PortInterval.single(int(src_part))

    if "-" in dst_part:
        lo, hi = dst_part.split("-", 1)
        dst_ports = PortInterval(int(lo), int(hi))
    else:
        dst_ports = PortInterval.single(int(dst_part))

    return dst_ports, src_ports


def _paginated_fetch(
    client: Any,
    url: str,
    option: Optional[List[str]] = None,
) -> List[dict]:
    """Fetch all records from an FMG API endpoint with pagination."""
    all_records: List[dict] = []
    offset = 0
    while True:
        range_ = [offset, _PAGE_SIZE]
        try:
            data = client.get(url, option=option, range_=range_)
        except Exception as exc:
            logger.warning("Fetch failed for %s offset=%d: %s", url, offset, exc)
            break
        if not data:
            break
        if isinstance(data, list):
            all_records.extend(data)
            if len(data) < _PAGE_SIZE:
                break
            offset += len(data)
        else:
            # Single object returned (unexpected for bulk)
            all_records.append(data)
            break
    return all_records


def _to_dict_by_name(records: List[dict]) -> Dict[str, dict]:
    """Index a list of FMG objects by their 'name' field."""
    result: Dict[str, dict] = {}
    for rec in records:
        name = rec.get("name")
        if name:
            result[name] = rec
    return result


class ObjectResolver:
    """Fetches FMG objects and resolves them to canonical model types."""

    def __init__(self, client: Any, adom: str) -> None:
        self.client = client
        self.adom = adom

        # Object caches (populated on first access)
        self._addresses: Optional[Dict[str, dict]] = None
        self._addrgroups: Optional[Dict[str, dict]] = None
        self._vips: Optional[Dict[str, dict]] = None
        self._vipgroups: Optional[Dict[str, dict]] = None
        self._services: Optional[Dict[str, dict]] = None
        self._service_groups: Optional[Dict[str, dict]] = None
        self._sched_onetime: Optional[Dict[str, dict]] = None
        self._sched_recurring: Optional[Dict[str, dict]] = None
        self._sched_groups: Optional[Dict[str, dict]] = None
        self._internet_service_names: Optional[Dict[str, dict]] = None
        self._isdb_services: Optional[Dict[int, dict]] = None  # id -> {name, entry_count, ...}

        # Resolution caches (memoize resolved objects)
        self._addr_cache: Dict[str, AddressSet] = {}
        self._svc_cache: Dict[str, ServiceSet] = {}
        self._sched_cache: Dict[str, ScheduleSpec] = {}

    # ------------------------------------------------------------------
    # Bulk fetch methods
    # ------------------------------------------------------------------

    def fetch_all_addresses(self, adom: Optional[str] = None) -> Dict[str, dict]:
        """Bulk fetch all firewall address objects."""
        adom = adom or self.adom
        url = f"/pm/config/adom/{adom}/obj/firewall/address"
        records = _paginated_fetch(self.client, url, option=["get reserved"])
        self._addresses = _to_dict_by_name(records)
        logger.info("Fetched %d address objects for adom=%s", len(self._addresses), adom)
        return self._addresses

    def fetch_all_addrgroups(self, adom: Optional[str] = None) -> Dict[str, dict]:
        """Bulk fetch all firewall address group objects."""
        adom = adom or self.adom
        url = f"/pm/config/adom/{adom}/obj/firewall/addrgrp"
        records = _paginated_fetch(self.client, url)
        self._addrgroups = _to_dict_by_name(records)
        logger.info("Fetched %d address groups for adom=%s", len(self._addrgroups), adom)
        return self._addrgroups

    def fetch_all_vips(self, adom: Optional[str] = None) -> Dict[str, dict]:
        """Bulk fetch all firewall VIP objects."""
        adom = adom or self.adom
        url = f"/pm/config/adom/{adom}/obj/firewall/vip"
        records = _paginated_fetch(self.client, url)
        self._vips = _to_dict_by_name(records)
        logger.info("Fetched %d VIP objects for adom=%s", len(self._vips), adom)
        return self._vips

    def fetch_all_vipgroups(self, adom: Optional[str] = None) -> Dict[str, dict]:
        """Bulk fetch all firewall VIP group objects."""
        adom = adom or self.adom
        url = f"/pm/config/adom/{adom}/obj/firewall/vipgrp"
        records = _paginated_fetch(self.client, url)
        self._vipgroups = _to_dict_by_name(records)
        logger.info("Fetched %d VIP groups for adom=%s", len(self._vipgroups), adom)
        return self._vipgroups

    def fetch_all_internet_service_names(self, adom: Optional[str] = None) -> Dict[str, dict]:
        """Bulk fetch all internet-service-name (ISDB) objects."""
        adom = adom or self.adom
        url = f"/pm/config/adom/{adom}/obj/firewall/internet-service-name"
        records = _paginated_fetch(self.client, url)
        self._internet_service_names = _to_dict_by_name(records)
        logger.info(
            "Fetched %d internet-service-name objects for adom=%s",
            len(self._internet_service_names), adom,
        )
        return self._internet_service_names

    def fetch_internet_service_db(self, adom: Optional[str] = None) -> Dict[int, dict]:
        """Fetch the internet-service database (ID -> name/metadata mapping)."""
        adom = adom or self.adom
        url = f"/pm/config/adom/{adom}/_fdsdb/internet-service"
        records = _paginated_fetch(self.client, url)
        self._isdb_services = {}
        for rec in records:
            svc_id = rec.get("id")
            if svc_id is not None:
                self._isdb_services[int(svc_id)] = rec
        logger.info(
            "Fetched %d internet-service DB entries for adom=%s",
            len(self._isdb_services), adom,
        )
        return self._isdb_services

    def fetch_all_services(self, adom: Optional[str] = None) -> Dict[str, dict]:
        """Bulk fetch all firewall service/custom objects."""
        adom = adom or self.adom
        url = f"/pm/config/adom/{adom}/obj/firewall/service/custom"
        records = _paginated_fetch(self.client, url, option=["get reserved"])
        self._services = _to_dict_by_name(records)
        logger.info("Fetched %d service objects for adom=%s", len(self._services), adom)
        return self._services

    def fetch_all_service_groups(self, adom: Optional[str] = None) -> Dict[str, dict]:
        """Bulk fetch all firewall service group objects."""
        adom = adom or self.adom
        url = f"/pm/config/adom/{adom}/obj/firewall/service/group"
        records = _paginated_fetch(self.client, url)
        self._service_groups = _to_dict_by_name(records)
        logger.info("Fetched %d service groups for adom=%s", len(self._service_groups), adom)
        return self._service_groups

    def fetch_all_schedules(self, adom: Optional[str] = None) -> Dict[str, dict]:
        """Bulk fetch all schedule objects (onetime + recurring + group)."""
        adom = adom or self.adom

        url_onetime = f"/pm/config/adom/{adom}/obj/firewall/schedule/onetime"
        self._sched_onetime = _to_dict_by_name(
            _paginated_fetch(self.client, url_onetime)
        )

        url_recurring = f"/pm/config/adom/{adom}/obj/firewall/schedule/recurring"
        self._sched_recurring = _to_dict_by_name(
            _paginated_fetch(self.client, url_recurring)
        )

        url_group = f"/pm/config/adom/{adom}/obj/firewall/schedule/group"
        self._sched_groups = _to_dict_by_name(
            _paginated_fetch(self.client, url_group)
        )

        total = len(self._sched_onetime) + len(self._sched_recurring) + len(self._sched_groups)
        logger.info("Fetched %d schedule objects for adom=%s", total, adom)

        # Return a merged dict for convenience
        merged: Dict[str, dict] = {}
        merged.update(self._sched_onetime)
        merged.update(self._sched_recurring)
        merged.update(self._sched_groups)
        return merged

    def fetch_all(self) -> None:
        """Fetch all object types for the configured ADOM."""
        self.fetch_all_addresses()
        self.fetch_all_addrgroups()
        self.fetch_all_vips()
        self.fetch_all_vipgroups()
        self.fetch_all_internet_service_names()
        self.fetch_internet_service_db()
        self.fetch_all_services()
        self.fetch_all_service_groups()
        self.fetch_all_schedules()

    # ------------------------------------------------------------------
    # Ensure caches are populated
    # ------------------------------------------------------------------

    def _ensure_addresses(self) -> None:
        if self._addresses is None:
            self.fetch_all_addresses()
        if self._addrgroups is None:
            self.fetch_all_addrgroups()
        if self._vips is None:
            self.fetch_all_vips()
        if self._vipgroups is None:
            self.fetch_all_vipgroups()

    def _ensure_services(self) -> None:
        if self._services is None:
            self.fetch_all_services()
        if self._service_groups is None:
            self.fetch_all_service_groups()

    def _ensure_schedules(self) -> None:
        if self._sched_onetime is None or self._sched_recurring is None or self._sched_groups is None:
            self.fetch_all_schedules()

    def _ensure_internet_service_names(self) -> None:
        if self._internet_service_names is None:
            self.fetch_all_internet_service_names()

    def _ensure_isdb(self) -> None:
        if self._isdb_services is None:
            self.fetch_internet_service_db()

    # ------------------------------------------------------------------
    # Address resolution
    # ------------------------------------------------------------------

    def resolve_address(self, name: str, _depth: int = 0) -> AddressSet:
        """Resolve a single address name to an AddressSet."""
        if _depth > _MAX_DEPTH:
            logger.warning("Max recursion depth resolving address '%s'", name)
            result = AddressSet.empty()
            result.unresolved_names.append(name)
            return result

        # Check cache
        if name in self._addr_cache:
            return self._addr_cache[name]

        # Handle 'all'
        if name.lower() == "all":
            result = AddressSet.any()
            self._addr_cache[name] = result
            return result

        self._ensure_addresses()
        assert self._addresses is not None
        assert self._addrgroups is not None
        assert self._vips is not None
        assert self._vipgroups is not None

        # Try as individual address first
        addr_obj = self._addresses.get(name)
        if addr_obj is not None:
            result = self._resolve_address_obj(addr_obj)
            self._addr_cache[name] = result
            return result

        # Try as address group
        grp_obj = self._addrgroups.get(name)
        if grp_obj is not None:
            result = self._resolve_addrgroup(grp_obj, _depth)
            self._addr_cache[name] = result
            return result

        # Try as VIP (destination NAT object)
        vip_obj = self._vips.get(name)
        if vip_obj is not None:
            result = self._resolve_vip(vip_obj)
            self._addr_cache[name] = result
            return result

        # Try as VIP group
        vipgrp_obj = self._vipgroups.get(name)
        if vipgrp_obj is not None:
            result = self._resolve_vipgroup(vipgrp_obj, _depth)
            self._addr_cache[name] = result
            return result

        # Not found
        logger.warning("Address object '%s' not found in adom=%s", name, self.adom)
        result = AddressSet.empty()
        result.unresolved_names.append(name)
        self._addr_cache[name] = result
        return result

    def _resolve_address_obj(self, obj: dict) -> AddressSet:
        """Resolve a single FMG address object to an AddressSet."""
        addr_type = obj.get("type", 0)
        name = obj.get("name", "unknown")

        # type 0 / 'ipmask': subnet
        if addr_type in (0, "ipmask"):
            return self._resolve_ipmask(obj)

        # type 3 / 'iprange': start-ip / end-ip
        if addr_type in (3, "iprange"):
            start_ip = obj.get("start-ip", "")
            end_ip = obj.get("end-ip", "")
            if start_ip and end_ip:
                try:
                    iv = IPInterval.from_range(start_ip, end_ip)
                    return AddressSet.from_intervals([iv])
                except (ValueError, TypeError) as exc:
                    logger.warning("Bad iprange in '%s': %s", name, exc)

            result = AddressSet.empty()
            result.unresolved_names.append(name)
            return result

        # type 1 / 'fqdn': cannot resolve to IP intervals — name-only comparison
        if addr_type in (1, "fqdn"):
            result = AddressSet.empty()
            result.unresolved_names.append(name)
            return result

        # type 2 / 'wildcard': wildcard subnet — name-only comparison
        if addr_type in (2, "wildcard"):
            result = AddressSet.empty()
            result.unresolved_names.append(name)
            return result

        # 'wildcard-fqdn': wildcard FQDN like *.example.com — name-only
        if addr_type in ("wildcard-fqdn",):
            result = AddressSet.empty()
            result.unresolved_names.append(name)
            return result

        # type 6 / 'geography': country-based — name-only comparison
        if addr_type in (6, "geography"):
            result = AddressSet.empty()
            result.unresolved_names.append(name)
            return result

        # type 7 / 'dynamic': external connector / threat feed — name-only
        if addr_type in (7, "dynamic"):
            result = AddressSet.empty()
            result.unresolved_names.append(name)
            return result

        # 'interface-subnet': derived from interface IP — name-only
        if addr_type in (8, "interface-subnet"):
            result = AddressSet.empty()
            result.unresolved_names.append(name)
            return result

        # 'mac': MAC-based address — name-only
        if addr_type in ("mac",):
            result = AddressSet.empty()
            result.unresolved_names.append(name)
            return result

        # 'route-tag': route-tag based — name-only
        if addr_type in ("route-tag",):
            result = AddressSet.empty()
            result.unresolved_names.append(name)
            return result

        # Other/unknown types — fall through gracefully
        logger.debug("Unknown address type %s for '%s'", addr_type, name)
        result = AddressSet.empty()
        result.unresolved_names.append(name)
        return result

    def _resolve_ipmask(self, obj: dict) -> AddressSet:
        """Resolve an ipmask address object."""
        subnet = obj.get("subnet")
        name = obj.get("name", "unknown")

        if subnet is None:
            result = AddressSet.empty()
            result.unresolved_names.append(name)
            return result

        try:
            # FMG can return subnet as [ip_str, mask_str] array
            if isinstance(subnet, list) and len(subnet) >= 2:
                ip_str, mask_str = str(subnet[0]), str(subnet[1])
                iv = IPInterval.from_subnet(ip_str, mask_str)
                return AddressSet.from_intervals([iv])

            # Or as a string like "10.0.0.0/24" or "10.0.0.0 255.255.255.0"
            if isinstance(subnet, str):
                subnet = subnet.strip()
                if "/" in subnet:
                    iv = IPInterval.from_cidr(subnet)
                    return AddressSet.from_intervals([iv])
                if " " in subnet:
                    parts = subnet.split()
                    iv = IPInterval.from_subnet(parts[0], parts[1])
                    return AddressSet.from_intervals([iv])
                # Single IP
                iv = IPInterval.from_host(subnet)
                return AddressSet.from_intervals([iv])

        except (ValueError, TypeError, IndexError) as exc:
            logger.warning("Bad subnet in address '%s': %s (raw=%r)", name, exc, subnet)

        result = AddressSet.empty()
        result.unresolved_names.append(name)
        return result

    def _resolve_addrgroup(self, grp_obj: dict, _depth: int) -> AddressSet:
        """Resolve an address group to the union of its members."""
        members = grp_obj.get("member", [])
        if isinstance(members, str):
            members = [members]

        result = AddressSet.empty()
        for member_name in members:
            if isinstance(member_name, str):
                member_set = self.resolve_address(member_name, _depth + 1)
                result = result.union(member_set)

        # Handle exclude-member
        exclude = grp_obj.get("exclude", 0)
        exclude_members = grp_obj.get("exclude-member", [])
        if exclude and exclude_members:
            if isinstance(exclude_members, str):
                exclude_members = [exclude_members]
            for excl_name in exclude_members:
                if isinstance(excl_name, str):
                    excl_set = self.resolve_address(excl_name, _depth + 1)
                    result = result.subtract(excl_set)

        return result

    def _resolve_vip(self, vip_obj: dict) -> AddressSet:
        """Resolve a VIP object using its extip (pre-NAT external address).

        For shadow analysis we care about the address the firewall matches
        on — that is the external / published IP (``extip``), not the
        internal ``mappedip``.  VIP types that cannot be resolved to IP
        intervals (e.g. FQDN VIPs, access-proxy) fall back to name-only.
        """
        name = vip_obj.get("name", "unknown")
        vip_type = vip_obj.get("type", "static-nat")

        # FQDN and access-proxy VIPs cannot be resolved to intervals
        if vip_type in ("fqdn", "access-proxy"):
            result = AddressSet.empty()
            result.unresolved_names.append(name)
            return result

        extip = vip_obj.get("extip")
        if not extip:
            result = AddressSet.empty()
            result.unresolved_names.append(name)
            return result

        # extip is an array of "IPv4 range" strings, e.g. ["1.2.3.4"] or
        # ["10.0.0.1-10.0.0.5"]
        if isinstance(extip, str):
            extip = [extip]

        intervals: List[IPInterval] = []
        for entry in extip:
            entry = entry.strip()
            if not entry:
                continue
            try:
                if "-" in entry:
                    parts = entry.split("-", 1)
                    intervals.append(IPInterval.from_range(parts[0].strip(), parts[1].strip()))
                elif "/" in entry:
                    intervals.append(IPInterval.from_cidr(entry))
                else:
                    intervals.append(IPInterval.from_host(entry))
            except (ValueError, TypeError) as exc:
                logger.warning("Bad extip in VIP '%s': %s (raw=%r)", name, exc, entry)

        if intervals:
            return AddressSet.from_intervals(intervals)

        result = AddressSet.empty()
        result.unresolved_names.append(name)
        return result

    def _resolve_vipgroup(self, grp_obj: dict, _depth: int) -> AddressSet:
        """Resolve a VIP group to the union of its member VIPs."""
        members = grp_obj.get("member", [])
        if isinstance(members, str):
            members = [members]

        result = AddressSet.empty()
        for member_name in members:
            if isinstance(member_name, str):
                member_set = self.resolve_address(member_name, _depth + 1)
                result = result.union(member_set)
        return result

    def resolve_address_list(self, names: List[str]) -> AddressSet:
        """Resolve a list of address names and union the results."""
        if not names:
            return AddressSet.empty()

        result = AddressSet.empty()
        for name in names:
            if isinstance(name, str):
                addr_set = self.resolve_address(name)
                result = result.union(addr_set)
        return result

    # ------------------------------------------------------------------
    # Service resolution
    # ------------------------------------------------------------------

    def resolve_service(self, name: str, _depth: int = 0) -> ServiceSet:
        """Resolve a single service name to a ServiceSet."""
        if _depth > _MAX_DEPTH:
            logger.warning("Max recursion depth resolving service '%s'", name)
            result = ServiceSet.empty()
            result.unresolved_names.append(name)
            return result

        # Check cache
        if name in self._svc_cache:
            return self._svc_cache[name]

        # Handle 'ALL'
        if name.upper() == "ALL":
            result = ServiceSet.any()
            self._svc_cache[name] = result
            return result

        self._ensure_services()
        assert self._services is not None
        assert self._service_groups is not None

        # Try as individual service
        svc_obj = self._services.get(name)
        if svc_obj is not None:
            result = self._resolve_service_obj(svc_obj)
            self._svc_cache[name] = result
            return result

        # Try as service group
        grp_obj = self._service_groups.get(name)
        if grp_obj is not None:
            result = self._resolve_service_group(grp_obj, _depth)
            self._svc_cache[name] = result
            return result

        # Not found
        logger.warning("Service object '%s' not found in adom=%s", name, self.adom)
        result = ServiceSet.empty()
        result.unresolved_names.append(name)
        self._svc_cache[name] = result
        return result

    def _resolve_service_obj(self, obj: dict) -> ServiceSet:
        """Resolve a single FMG service object to a ServiceSet."""
        protocol = obj.get("protocol", "")
        specs: List[ServiceSpec] = []
        name = obj.get("name", "unknown")

        # protocol 5 = TCP/UDP/SCTP
        if protocol in (5, "TCP/UDP/SCTP"):
            for proto, field_name in [
                (Protocol.TCP, "tcp-portrange"),
                (Protocol.UDP, "udp-portrange"),
                (Protocol.SCTP, "sctp-portrange"),
            ]:
                port_ranges = obj.get(field_name)
                if not port_ranges:
                    continue
                # Can be a single string or a list of strings
                if isinstance(port_ranges, str):
                    port_ranges = port_ranges.split()
                elif not isinstance(port_ranges, list):
                    port_ranges = [str(port_ranges)]

                for pr in port_ranges:
                    pr = str(pr).strip()
                    if not pr:
                        continue
                    try:
                        dst_ports, src_ports = _parse_port_range(pr)
                        specs.append(ServiceSpec(
                            protocol=proto,
                            dst_ports=dst_ports,
                            src_ports=src_ports,
                        ))
                    except (ValueError, TypeError) as exc:
                        logger.warning("Bad port range '%s' in service '%s': %s", pr, name, exc)

        # protocol 0 = IP (raw protocol number)
        elif protocol in (0, "IP"):
            proto_num = obj.get("protocol-number", 0)
            if isinstance(proto_num, str):
                try:
                    proto_num = int(proto_num)
                except ValueError:
                    proto_num = 0
            specs.append(ServiceSpec(
                protocol=Protocol.IP,
                ip_protocol=proto_num,
            ))

        # protocol 1 = ICMP/ICMP6
        elif protocol in (1, "ICMP"):
            icmp_type = obj.get("icmptype")
            icmp_code = obj.get("icmpcode")
            # Convert to int if present
            if icmp_type is not None:
                try:
                    icmp_type = int(icmp_type)
                except (ValueError, TypeError):
                    icmp_type = None
            if icmp_code is not None:
                try:
                    icmp_code = int(icmp_code)
                except (ValueError, TypeError):
                    icmp_code = None
            specs.append(ServiceSpec(
                protocol=Protocol.ICMP,
                icmp_type=icmp_type,
                icmp_code=icmp_code,
            ))

        else:
            # Unknown protocol type - try to parse port ranges anyway
            logger.debug("Unknown protocol type %r for service '%s'", protocol, name)
            # Check if there are tcp/udp port ranges regardless
            has_ports = False
            for proto, field_name in [
                (Protocol.TCP, "tcp-portrange"),
                (Protocol.UDP, "udp-portrange"),
                (Protocol.SCTP, "sctp-portrange"),
            ]:
                port_ranges = obj.get(field_name)
                if not port_ranges:
                    continue
                has_ports = True
                if isinstance(port_ranges, str):
                    port_ranges = port_ranges.split()
                elif not isinstance(port_ranges, list):
                    port_ranges = [str(port_ranges)]
                for pr in port_ranges:
                    pr = str(pr).strip()
                    if not pr:
                        continue
                    try:
                        dst_ports, src_ports = _parse_port_range(pr)
                        specs.append(ServiceSpec(
                            protocol=proto,
                            dst_ports=dst_ports,
                            src_ports=src_ports,
                        ))
                    except (ValueError, TypeError):
                        pass
            if not has_ports:
                result = ServiceSet.empty()
                result.unresolved_names.append(name)
                return result

        if not specs:
            result = ServiceSet.empty()
            result.unresolved_names.append(name)
            return result

        return ServiceSet(specs=specs)

    def _resolve_service_group(self, grp_obj: dict, _depth: int) -> ServiceSet:
        """Resolve a service group to the union of its members."""
        members = grp_obj.get("member", [])
        if isinstance(members, str):
            members = [members]

        all_specs: List[ServiceSpec] = []
        unresolved: List[str] = []
        is_any = False

        for member_name in members:
            if isinstance(member_name, str):
                member_set = self.resolve_service(member_name, _depth + 1)
                if member_set.is_any:
                    is_any = True
                all_specs.extend(member_set.specs)
                unresolved.extend(member_set.unresolved_names)

        if is_any:
            return ServiceSet.any()

        result = ServiceSet(specs=all_specs)
        result.unresolved_names = list(set(unresolved))
        return result

    def resolve_service_list(self, names: List[str]) -> ServiceSet:
        """Resolve a list of service names and union the results."""
        if not names:
            return ServiceSet.empty()

        all_specs: List[ServiceSpec] = []
        unresolved: List[str] = []
        is_any = False

        for name in names:
            if isinstance(name, str):
                svc_set = self.resolve_service(name)
                if svc_set.is_any:
                    is_any = True
                all_specs.extend(svc_set.specs)
                unresolved.extend(svc_set.unresolved_names)

        if is_any:
            return ServiceSet.any()

        result = ServiceSet(specs=all_specs)
        result.unresolved_names = list(set(unresolved))
        return result

    # ------------------------------------------------------------------
    # Schedule resolution
    # ------------------------------------------------------------------

    def resolve_schedule(self, name: str, _depth: int = 0) -> ScheduleSpec:
        """Resolve a schedule name to a ScheduleSpec."""
        if _depth > _MAX_DEPTH:
            logger.warning("Max recursion depth resolving schedule '%s'", name)
            return ScheduleSpec(unresolved_name=name, raw_name=name)

        # Check cache
        if name in self._sched_cache:
            return self._sched_cache[name]

        # Handle 'always'
        if name.lower() == "always":
            result = ScheduleSpec.always()
            self._sched_cache[name] = result
            return result

        self._ensure_schedules()
        assert self._sched_onetime is not None
        assert self._sched_recurring is not None
        assert self._sched_groups is not None

        # Try recurring
        rec_obj = self._sched_recurring.get(name)
        if rec_obj is not None:
            result = self._resolve_recurring_schedule(rec_obj)
            self._sched_cache[name] = result
            return result

        # Try onetime
        ot_obj = self._sched_onetime.get(name)
        if ot_obj is not None:
            result = self._resolve_onetime_schedule(ot_obj)
            self._sched_cache[name] = result
            return result

        # Try group
        grp_obj = self._sched_groups.get(name)
        if grp_obj is not None:
            result = self._resolve_schedule_group(grp_obj, _depth)
            self._sched_cache[name] = result
            return result

        # Not found
        logger.warning("Schedule object '%s' not found in adom=%s", name, self.adom)
        result = ScheduleSpec(unresolved_name=name, raw_name=name)
        self._sched_cache[name] = result
        return result

    def _resolve_recurring_schedule(self, obj: dict) -> ScheduleSpec:
        """Resolve a recurring schedule object."""
        name = obj.get("name", "unknown")
        day_field = obj.get("day", [])

        # day can be a list of weekday name strings or a single string
        if isinstance(day_field, str):
            day_field = [day_field]

        weekdays: Set[int] = set()
        for d in day_field:
            if isinstance(d, str):
                idx = _WEEKDAY_MAP.get(d.lower())
                if idx is not None:
                    weekdays.add(idx)
                elif d.lower() == "none":
                    pass  # no specific day
                else:
                    logger.debug("Unknown weekday '%s' in schedule '%s'", d, name)

        start_time = obj.get("start", "")
        end_time = obj.get("end", "")

        # Normalize time strings - FMG may include seconds
        if isinstance(start_time, str) and len(start_time) > 5:
            start_time = start_time[:5]  # "HH:MM:SS" -> "HH:MM"
        if isinstance(end_time, str) and len(end_time) > 5:
            end_time = end_time[:5]

        # If no weekdays specified, treat as always-on-recurring (all days)
        if not weekdays:
            weekdays = set(range(7))

        return ScheduleSpec(
            weekdays=weekdays,
            start_time=start_time if start_time else None,
            end_time=end_time if end_time else None,
            raw_name=name,
        )

    def _resolve_onetime_schedule(self, obj: dict) -> ScheduleSpec:
        """Resolve a onetime schedule object."""
        name = obj.get("name", "unknown")
        start_dt = obj.get("start", "")
        end_dt = obj.get("end", "")

        return ScheduleSpec(
            start_datetime=start_dt if start_dt else None,
            end_datetime=end_dt if end_dt else None,
            raw_name=name,
        )

    def _resolve_schedule_group(self, grp_obj: dict, _depth: int) -> ScheduleSpec:
        """Resolve a schedule group.

        Conservative approach: if any member is always, result is always.
        Otherwise, return the first member's spec (schedule groups are rare
        and complex to truly merge).
        """
        members = grp_obj.get("member", [])
        if isinstance(members, str):
            members = [members]

        name = grp_obj.get("name", "unknown")
        resolved_members: List[ScheduleSpec] = []

        for member_name in members:
            if isinstance(member_name, str):
                member_spec = self.resolve_schedule(member_name, _depth + 1)
                if member_spec.is_always:
                    return ScheduleSpec.always()
                resolved_members.append(member_spec)

        if not resolved_members:
            return ScheduleSpec(unresolved_name=name, raw_name=name)

        # Return the first member as a conservative approximation
        # (schedule groups are an OR of schedules, so any active member
        # makes the schedule active - the first is a reasonable approx)
        result = resolved_members[0]
        # Override raw_name to the group name
        result = ScheduleSpec(
            is_always=result.is_always,
            weekdays=result.weekdays,
            start_time=result.start_time,
            end_time=result.end_time,
            start_datetime=result.start_datetime,
            end_datetime=result.end_datetime,
            unresolved_name=result.unresolved_name,
            raw_name=name,
        )
        return result

    # ------------------------------------------------------------------
    # Bulk policy resolution
    # ------------------------------------------------------------------

    def resolve_policies(self, policies: List[CanonicalPolicy]) -> List[CanonicalPolicy]:
        """Resolve all object references in a list of policies in-place.

        Assumes raw_data on each policy contains the original FMG fields:
        srcaddr, dstaddr, service, schedule (as lists of name strings).

        Returns the same list for convenience (policies are mutated in-place).
        """
        # Pre-fetch all objects
        self.fetch_all()

        for policy in policies:
            try:
                self._resolve_policy(policy)
            except Exception as exc:
                logger.error(
                    "Error resolving policy %d '%s': %s",
                    policy.policyid, policy.name, exc,
                )
                policy.has_unresolved = True
                policy.unresolved_notes.append(f"Resolution error: {exc}")

        return policies

    def resolve_internet_service_name(self, name: str) -> str:
        """Resolve an internet-service reference to a human-readable label.

        ISDB entries can contain millions of IP/port rows per service (e.g.
        Google-Web has 24K+ entries).  Expanding them to IP intervals is
        impractical — it would consume gigabytes of RAM and produce unusable
        AddressSets.  Instead, we resolve the *name* for display purposes and
        mark the policy as using an ISDB object (treated as unresolved for
        shadow analysis, similar to FQDNs and geographic objects).

        Returns:
            A human-readable label like "ISDB:Google-Web" or the original
            name if no catalog match is found.
        """
        self._ensure_isdb()
        self._ensure_internet_service_names()

        # Try internet-service-name object -> ISDB ID -> catalog name
        isdb_id: Optional[int] = None

        # Direct numeric ID
        try:
            isdb_id = int(name)
        except (ValueError, TypeError):
            pass

        # internet-service-name object lookup
        if isdb_id is None and self._internet_service_names:
            isdb_obj = self._internet_service_names.get(name)
            if isdb_obj:
                raw_id = isdb_obj.get("internet-service-id")
                if raw_id is not None:
                    try:
                        isdb_id = int(raw_id)
                    except (ValueError, TypeError):
                        pass

        # ISDB catalog name match
        if isdb_id is None and self._isdb_services:
            for sid, svc in self._isdb_services.items():
                if svc.get("name", "") == name:
                    isdb_id = sid
                    break

        # Build a readable label
        if isdb_id is not None and self._isdb_services:
            svc_info = self._isdb_services.get(isdb_id)
            if svc_info:
                svc_name = svc_info.get("name", name)
                return f"ISDB:{svc_name}"

        return f"ISDB:{name}"

    @staticmethod
    def _extract_isdb_names(raw: dict, src: bool = False) -> List[str]:
        """Extract internet-service-name entries from raw policy data.

        Returns a list of ISDB entry name strings.
        """
        if src:
            field = raw.get("internet-service-src-name", raw.get("internet-service-src-id", []))
        else:
            field = raw.get("internet-service-name", raw.get("internet-service-id", []))

        if field is None:
            return []
        if isinstance(field, str):
            return [field] if field else []
        if isinstance(field, (int, float)):
            return [str(int(field))]
        if isinstance(field, list):
            names: List[str] = []
            for item in field:
                if isinstance(item, str):
                    if item:
                        names.append(item)
                elif isinstance(item, dict):
                    name = item.get("name", "")
                    if name:
                        names.append(name)
                elif isinstance(item, (int, float)):
                    names.append(str(int(item)))
            return names
        return []

    def _resolve_policy(self, policy: CanonicalPolicy) -> None:
        """Resolve object references for a single policy in-place."""
        raw = policy.raw_data

        # ------------------------------------------------------------------
        # Internet-service handling
        # When internet-service is enabled the ISDB entry defines BOTH the
        # destination addresses AND the service — dstaddr/service fields in the
        # raw policy are ignored by FortiOS.
        # When internet-service-src is enabled, the ISDB replaces srcaddr.
        # ------------------------------------------------------------------
        inet_svc = raw.get("internet-service", 0)
        inet_svc_enabled = inet_svc in ("enable", 1, "1")

        inet_svc_src = raw.get("internet-service-src", 0)
        inet_svc_src_enabled = inet_svc_src in ("enable", 1, "1")

        # Source addresses
        if inet_svc_src_enabled:
            isdb_src_names = self._extract_isdb_names(raw, src=True)
            # ISDB entries are too large to expand (millions of IP/port rows).
            # Mark as unresolved with a readable ISDB label for the report.
            labels = [self.resolve_internet_service_name(n) for n in isdb_src_names] if isdb_src_names else []
            policy.srcaddr = AddressSet.empty()
            policy.srcaddr.unresolved_names.extend(labels or ["ISDB:unknown"])
        else:
            srcaddr_names = raw.get("_raw_srcaddr", [])
            if srcaddr_names:
                policy.srcaddr = self.resolve_address_list(srcaddr_names)
            else:
                policy.srcaddr = AddressSet.any()

        # Destination addresses
        if inet_svc_enabled:
            isdb_names = self._extract_isdb_names(raw, src=False)
            # ISDB entries are too large to expand — mark as unresolved with labels.
            labels = [self.resolve_internet_service_name(n) for n in isdb_names] if isdb_names else []
            policy.dstaddr = AddressSet.empty()
            policy.dstaddr.unresolved_names.extend(labels or ["ISDB:unknown"])
            policy.service = ServiceSet.empty()
            policy.service.unresolved_names.extend(labels or ["ISDB:unknown"])
        else:
            dstaddr_names = raw.get("_raw_dstaddr", [])
            if dstaddr_names:
                policy.dstaddr = self.resolve_address_list(dstaddr_names)
            else:
                policy.dstaddr = AddressSet.any()

            # Services (only resolved when internet-service is NOT used)
            svc_names = raw.get("_raw_service", [])
            if svc_names:
                policy.service = self.resolve_service_list(svc_names)
            else:
                policy.service = ServiceSet.any()

        # Schedule
        sched_names = raw.get("_raw_schedule", [])
        sched_name = sched_names[0] if sched_names else "always"
        policy.schedule = self.resolve_schedule(sched_name)

        # Track unresolved state
        unresolved_parts: List[str] = []
        if policy.srcaddr.unresolved_names:
            unresolved_parts.extend(
                f"srcaddr:{n}" for n in policy.srcaddr.unresolved_names
            )
        if policy.dstaddr.unresolved_names:
            unresolved_parts.extend(
                f"dstaddr:{n}" for n in policy.dstaddr.unresolved_names
            )
        if policy.service.unresolved_names:
            unresolved_parts.extend(
                f"service:{n}" for n in policy.service.unresolved_names
            )
        if policy.schedule.unresolved_name:
            unresolved_parts.append(f"schedule:{policy.schedule.unresolved_name}")

        if unresolved_parts:
            policy.has_unresolved = True
            policy.unresolved_notes.extend(unresolved_parts)
