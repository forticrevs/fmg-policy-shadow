"""Unit tests for fmg_shadow.models data models."""

from fmg_shadow.models import (
    IPInterval,
    PortInterval,
    Protocol,
    ServiceSpec,
    AddressSet,
    ServiceSet,
    InterfaceSet,
    ScheduleSpec,
    InstallScope,
)


# =========================================================================
# IPInterval
# =========================================================================

class TestIPInterval:

    def test_from_subnet_24(self):
        iv = IPInterval.from_subnet("192.168.1.0", "255.255.255.0")
        assert iv.size() == 256
        assert iv.start == 0xC0A80100
        assert iv.end == 0xC0A801FF

    def test_from_subnet_non_aligned(self):
        # Host IP with /24 mask should snap to network boundary
        iv = IPInterval.from_subnet("192.168.1.55", "255.255.255.0")
        assert iv.start == 0xC0A80100

    def test_from_cidr_32(self):
        iv = IPInterval.from_cidr("10.0.0.1/32")
        assert iv.start == iv.end
        assert iv.size() == 1

    def test_from_cidr_16(self):
        iv = IPInterval.from_cidr("172.16.0.0/16")
        assert iv.size() == 65536

    def test_from_range(self):
        iv = IPInterval.from_range("10.0.0.10", "10.0.0.20")
        assert iv.size() == 11

    def test_from_host(self):
        iv = IPInterval.from_host("1.2.3.4")
        assert iv.start == iv.end
        assert iv.size() == 1

    def test_any(self):
        iv = IPInterval.any()
        assert iv.start == 0
        assert iv.end == 0xFFFFFFFF
        assert iv.size() == 2**32

    def test_contains_subset(self):
        big = IPInterval.from_cidr("10.0.0.0/8")
        small = IPInterval.from_cidr("10.1.2.0/24")
        assert big.contains(small)
        assert not small.contains(big)

    def test_contains_self(self):
        iv = IPInterval.from_cidr("10.0.0.0/24")
        assert iv.contains(iv)

    def test_contains_host_in_range(self):
        rng = IPInterval.from_range("10.0.0.1", "10.0.0.100")
        host = IPInterval.from_host("10.0.0.50")
        assert rng.contains(host)
        host_out = IPInterval.from_host("10.0.0.200")
        assert not rng.contains(host_out)

    def test_overlaps_partial(self):
        a = IPInterval.from_range("10.0.0.1", "10.0.0.100")
        b = IPInterval.from_range("10.0.0.50", "10.0.0.200")
        assert a.overlaps(b)
        assert b.overlaps(a)

    def test_overlaps_disjoint(self):
        a = IPInterval.from_range("10.0.0.1", "10.0.0.10")
        b = IPInterval.from_range("10.0.0.20", "10.0.0.30")
        assert not a.overlaps(b)

    def test_overlaps_adjacent_not_overlapping(self):
        # Adjacent ranges: end of a == start of b - 1 => no overlap
        a = IPInterval.from_range("10.0.0.1", "10.0.0.10")
        b = IPInterval.from_range("10.0.0.11", "10.0.0.20")
        assert not a.overlaps(b)

    def test_overlaps_touching(self):
        # Ranges that share exactly one IP
        a = IPInterval.from_range("10.0.0.1", "10.0.0.10")
        b = IPInterval.from_range("10.0.0.10", "10.0.0.20")
        assert a.overlaps(b)

    def test_intersection_partial(self):
        a = IPInterval.from_range("10.0.0.1", "10.0.0.100")
        b = IPInterval.from_range("10.0.0.50", "10.0.0.200")
        inter = a.intersection(b)
        assert inter is not None
        assert inter.start == IPInterval.from_host("10.0.0.50").start
        assert inter.end == IPInterval.from_host("10.0.0.100").start

    def test_intersection_disjoint(self):
        a = IPInterval.from_range("10.0.0.1", "10.0.0.10")
        b = IPInterval.from_range("10.0.0.20", "10.0.0.30")
        assert a.intersection(b) is None

    def test_intersection_full_containment(self):
        big = IPInterval.from_cidr("10.0.0.0/24")
        small = IPInterval.from_cidr("10.0.0.128/25")
        inter = big.intersection(small)
        assert inter == small

    def test_repr_single_host(self):
        iv = IPInterval.from_host("1.2.3.4")
        assert repr(iv) == "1.2.3.4"

    def test_repr_range(self):
        iv = IPInterval.from_range("1.2.3.4", "1.2.3.10")
        assert repr(iv) == "1.2.3.4-1.2.3.10"


# =========================================================================
# AddressSet
# =========================================================================

class TestAddressSet:

    def test_any(self):
        s = AddressSet.any()
        assert s.is_any
        assert s.total_size() == 2**32

    def test_empty(self):
        s = AddressSet.empty()
        assert s.is_empty()
        assert s.total_size() == 0

    def test_from_intervals_merges_overlapping(self):
        a = IPInterval.from_range("10.0.0.1", "10.0.0.100")
        b = IPInterval.from_range("10.0.0.50", "10.0.0.200")
        s = AddressSet.from_intervals([a, b])
        assert len(s.intervals) == 1
        assert s.intervals[0].start == a.start
        assert s.intervals[0].end == b.end

    def test_from_intervals_merges_adjacent(self):
        a = IPInterval.from_range("10.0.0.1", "10.0.0.10")
        b = IPInterval.from_range("10.0.0.11", "10.0.0.20")
        s = AddressSet.from_intervals([a, b])
        assert len(s.intervals) == 1
        assert s.intervals[0].size() == 20

    def test_from_intervals_preserves_disjoint(self):
        a = IPInterval.from_range("10.0.0.1", "10.0.0.10")
        b = IPInterval.from_range("10.0.0.20", "10.0.0.30")
        s = AddressSet.from_intervals([a, b])
        assert len(s.intervals) == 2

    def test_contains_subset(self):
        big = AddressSet.from_intervals([IPInterval.from_cidr("10.0.0.0/8")])
        small = AddressSet.from_intervals([IPInterval.from_cidr("10.1.0.0/16")])
        assert big.contains(small)
        assert not small.contains(big)

    def test_contains_any_contains_all(self):
        s = AddressSet.any()
        other = AddressSet.from_intervals([IPInterval.from_host("1.2.3.4")])
        assert s.contains(other)
        assert not other.contains(s)

    def test_contains_with_unresolved_is_conservative(self):
        big = AddressSet.from_intervals([IPInterval.from_cidr("10.0.0.0/8")])
        other = AddressSet(intervals=[IPInterval.from_cidr("10.1.0.0/16")],
                           unresolved_names=["unknown_group"])
        assert not big.contains(other)

    def test_overlaps(self):
        a = AddressSet.from_intervals([IPInterval.from_cidr("10.0.0.0/24")])
        b = AddressSet.from_intervals([IPInterval.from_cidr("10.0.0.128/25")])
        assert a.overlaps(b)

    def test_overlaps_any(self):
        a = AddressSet.any()
        b = AddressSet.from_intervals([IPInterval.from_host("1.2.3.4")])
        assert a.overlaps(b)
        assert b.overlaps(a)

    def test_overlaps_disjoint(self):
        a = AddressSet.from_intervals([IPInterval.from_cidr("10.0.0.0/24")])
        b = AddressSet.from_intervals([IPInterval.from_cidr("192.168.0.0/24")])
        assert not a.overlaps(b)

    def test_intersection(self):
        a = AddressSet.from_intervals([IPInterval.from_cidr("10.0.0.0/24")])
        b = AddressSet.from_intervals([IPInterval.from_range("10.0.0.100", "10.0.1.50")])
        inter = a.intersection(b)
        assert len(inter.intervals) == 1
        assert inter.intervals[0].start == IPInterval.from_host("10.0.0.100").start
        assert inter.intervals[0].end == IPInterval.from_host("10.0.0.255").start

    def test_intersection_with_any(self):
        a = AddressSet.any()
        b = AddressSet.from_intervals([IPInterval.from_host("5.5.5.5")])
        inter = a.intersection(b)
        assert len(inter.intervals) == 1
        inter2 = b.intersection(a)
        assert len(inter2.intervals) == 1

    def test_intersection_disjoint(self):
        a = AddressSet.from_intervals([IPInterval.from_cidr("10.0.0.0/24")])
        b = AddressSet.from_intervals([IPInterval.from_cidr("192.168.0.0/24")])
        inter = a.intersection(b)
        assert inter.is_empty()

    def test_union(self):
        a = AddressSet.from_intervals([IPInterval.from_cidr("10.0.0.0/24")])
        b = AddressSet.from_intervals([IPInterval.from_cidr("10.0.1.0/24")])
        u = a.union(b)
        # Adjacent /24s should merge
        assert len(u.intervals) == 1
        assert u.total_size() == 512

    def test_union_with_any(self):
        a = AddressSet.any()
        b = AddressSet.from_intervals([IPInterval.from_host("5.5.5.5")])
        assert a.union(b).is_any
        assert b.union(a).is_any

    def test_subtract_full(self):
        a = AddressSet.from_intervals([IPInterval.from_cidr("10.0.0.0/24")])
        b = AddressSet.from_intervals([IPInterval.from_cidr("10.0.0.0/24")])
        result = a.subtract(b)
        assert result.is_empty()

    def test_subtract_partial(self):
        a = AddressSet.from_intervals([IPInterval.from_cidr("10.0.0.0/24")])
        # Remove the first half
        b = AddressSet.from_intervals([IPInterval.from_range("10.0.0.0", "10.0.0.127")])
        result = a.subtract(b)
        assert len(result.intervals) == 1
        assert result.intervals[0].size() == 128

    def test_subtract_middle(self):
        a = AddressSet.from_intervals([IPInterval.from_range("10.0.0.0", "10.0.0.255")])
        b = AddressSet.from_intervals([IPInterval.from_range("10.0.0.100", "10.0.0.199")])
        result = a.subtract(b)
        assert len(result.intervals) == 2
        assert result.total_size() == 156  # 100 + 56

    def test_subtract_from_any(self):
        result = AddressSet.any().subtract(
            AddressSet.from_intervals([IPInterval.from_host("10.0.0.1")])
        )
        assert result.total_size() == 2**32 - 1

    def test_subtract_by_any(self):
        result = AddressSet.from_intervals([IPInterval.from_cidr("10.0.0.0/8")]).subtract(
            AddressSet.any()
        )
        assert result.is_empty()

    def test_is_empty_true(self):
        assert AddressSet.empty().is_empty()

    def test_is_empty_false_with_intervals(self):
        s = AddressSet.from_intervals([IPInterval.from_host("1.1.1.1")])
        assert not s.is_empty()

    def test_is_empty_false_with_unresolved(self):
        s = AddressSet(intervals=[], unresolved_names=["some_fqdn"])
        assert not s.is_empty()

    def test_describe_any(self):
        assert AddressSet.any().describe() == "any"

    def test_describe_empty(self):
        assert AddressSet.empty().describe() == "empty"


# =========================================================================
# PortInterval
# =========================================================================

class TestPortInterval:

    def test_any(self):
        p = PortInterval.any()
        assert p.start == 0
        assert p.end == 65535
        assert p.size() == 65536

    def test_single(self):
        p = PortInterval.single(443)
        assert p.start == 443
        assert p.end == 443
        assert p.size() == 1

    def test_contains(self):
        big = PortInterval(80, 8080)
        small = PortInterval(443, 443)
        assert big.contains(small)
        assert not small.contains(big)

    def test_contains_self(self):
        p = PortInterval(80, 443)
        assert p.contains(p)

    def test_overlaps(self):
        a = PortInterval(80, 1024)
        b = PortInterval(443, 8080)
        assert a.overlaps(b)

    def test_overlaps_disjoint(self):
        a = PortInterval(80, 80)
        b = PortInterval(443, 443)
        assert not a.overlaps(b)

    def test_intersection(self):
        a = PortInterval(80, 1024)
        b = PortInterval(443, 8080)
        inter = a.intersection(b)
        assert inter == PortInterval(443, 1024)

    def test_intersection_disjoint(self):
        a = PortInterval(80, 80)
        b = PortInterval(443, 443)
        assert a.intersection(b) is None

    def test_repr_single(self):
        assert repr(PortInterval.single(80)) == "80"

    def test_repr_range(self):
        assert repr(PortInterval(80, 443)) == "80-443"


# =========================================================================
# ServiceSpec
# =========================================================================

class TestServiceSpec:

    def test_any(self):
        s = ServiceSpec.any()
        assert s.is_any()
        assert s.protocol == Protocol.ANY

    def test_any_contains_everything(self):
        any_svc = ServiceSpec.any()
        tcp_svc = ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval.single(443))
        assert any_svc.contains(tcp_svc)
        assert not tcp_svc.contains(any_svc)

    def test_tcp_containment(self):
        broad = ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval(1, 65535))
        narrow = ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval.single(443))
        assert broad.contains(narrow)
        assert not narrow.contains(broad)

    def test_tcp_containment_with_src_ports(self):
        broad = ServiceSpec(protocol=Protocol.TCP,
                            dst_ports=PortInterval(1, 65535),
                            src_ports=PortInterval(1, 65535))
        narrow = ServiceSpec(protocol=Protocol.TCP,
                             dst_ports=PortInterval.single(443),
                             src_ports=PortInterval.single(12345))
        assert broad.contains(narrow)

    def test_tcp_no_containment_different_proto(self):
        tcp = ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval(1, 65535))
        udp = ServiceSpec(protocol=Protocol.UDP, dst_ports=PortInterval.single(53))
        assert not tcp.contains(udp)
        assert not udp.contains(tcp)

    def test_udp_overlap(self):
        a = ServiceSpec(protocol=Protocol.UDP, dst_ports=PortInterval(50, 100))
        b = ServiceSpec(protocol=Protocol.UDP, dst_ports=PortInterval(75, 200))
        assert a.overlaps(b)

    def test_udp_no_overlap(self):
        a = ServiceSpec(protocol=Protocol.UDP, dst_ports=PortInterval(50, 60))
        b = ServiceSpec(protocol=Protocol.UDP, dst_ports=PortInterval(70, 80))
        assert not a.overlaps(b)

    def test_icmp_contains_wildcard_type(self):
        # icmp_type=None means "any type"
        wild = ServiceSpec(protocol=Protocol.ICMP, icmp_type=None, icmp_code=None)
        specific = ServiceSpec(protocol=Protocol.ICMP, icmp_type=8, icmp_code=0)
        assert wild.contains(specific)
        assert not specific.contains(wild)

    def test_icmp_contains_same_type(self):
        a = ServiceSpec(protocol=Protocol.ICMP, icmp_type=8, icmp_code=None)
        b = ServiceSpec(protocol=Protocol.ICMP, icmp_type=8, icmp_code=0)
        assert a.contains(b)

    def test_icmp_no_contains_different_type(self):
        a = ServiceSpec(protocol=Protocol.ICMP, icmp_type=8)
        b = ServiceSpec(protocol=Protocol.ICMP, icmp_type=0)
        assert not a.contains(b)

    def test_icmp_overlaps_wildcard(self):
        wild = ServiceSpec(protocol=Protocol.ICMP)
        specific = ServiceSpec(protocol=Protocol.ICMP, icmp_type=8, icmp_code=0)
        assert wild.overlaps(specific)

    def test_icmp_no_overlap_different_types(self):
        a = ServiceSpec(protocol=Protocol.ICMP, icmp_type=8, icmp_code=0)
        b = ServiceSpec(protocol=Protocol.ICMP, icmp_type=0, icmp_code=0)
        assert not a.overlaps(b)

    def test_protocol_mismatch_no_overlap(self):
        tcp = ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval.any())
        udp = ServiceSpec(protocol=Protocol.UDP, dst_ports=PortInterval.any())
        assert not tcp.overlaps(udp)

    def test_any_overlaps_everything(self):
        any_svc = ServiceSpec.any()
        tcp = ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval.single(80))
        icmp = ServiceSpec(protocol=Protocol.ICMP, icmp_type=8)
        assert any_svc.overlaps(tcp)
        assert any_svc.overlaps(icmp)
        assert tcp.overlaps(any_svc)

    def test_ip_protocol_contains(self):
        a = ServiceSpec(protocol=Protocol.IP, ip_protocol=47)  # GRE
        b = ServiceSpec(protocol=Protocol.IP, ip_protocol=47)
        assert a.contains(b)

    def test_ip_protocol_different(self):
        a = ServiceSpec(protocol=Protocol.IP, ip_protocol=47)
        b = ServiceSpec(protocol=Protocol.IP, ip_protocol=50)  # ESP
        assert not a.contains(b)
        assert not a.overlaps(b)


# =========================================================================
# ServiceSet
# =========================================================================

class TestServiceSet:

    def test_any(self):
        s = ServiceSet.any()
        assert s.is_any

    def test_empty(self):
        s = ServiceSet.empty()
        assert not s.specs

    def test_contains_with_multiple_specs(self):
        # A set with TCP/80 + TCP/443 should contain a set with just TCP/80
        broad = ServiceSet(specs=[
            ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval.single(80)),
            ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval.single(443)),
        ])
        narrow = ServiceSet(specs=[
            ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval.single(80)),
        ])
        assert broad.contains(narrow)

    def test_not_contains_missing_spec(self):
        a = ServiceSet(specs=[
            ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval.single(80)),
        ])
        b = ServiceSet(specs=[
            ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval.single(443)),
        ])
        assert not a.contains(b)

    def test_any_contains_all(self):
        any_ss = ServiceSet.any()
        specific = ServiceSet(specs=[
            ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval.single(22)),
        ])
        assert any_ss.contains(specific)
        assert not specific.contains(any_ss)

    def test_contains_with_unresolved_is_conservative(self):
        broad = ServiceSet.any()
        other = ServiceSet(specs=[], unresolved_names=["custom_svc"])
        # any still contains (checked first)
        assert broad.contains(other)
        # but a non-any set should not claim to contain unresolved
        narrow = ServiceSet(specs=[
            ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval(1, 65535)),
        ])
        other2 = ServiceSet(specs=[
            ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval.single(80)),
        ], unresolved_names=["mystery"])
        assert not narrow.contains(other2)

    def test_overlaps_mixed_protocols(self):
        a = ServiceSet(specs=[
            ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval.single(80)),
            ServiceSpec(protocol=Protocol.UDP, dst_ports=PortInterval.single(53)),
        ])
        b = ServiceSet(specs=[
            ServiceSpec(protocol=Protocol.UDP, dst_ports=PortInterval(50, 60)),
        ])
        assert a.overlaps(b)

    def test_overlaps_no_match(self):
        a = ServiceSet(specs=[
            ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval.single(80)),
        ])
        b = ServiceSet(specs=[
            ServiceSpec(protocol=Protocol.UDP, dst_ports=PortInterval.single(53)),
        ])
        assert not a.overlaps(b)

    def test_overlaps_any(self):
        assert ServiceSet.any().overlaps(ServiceSet.empty())  # is_any check comes first
        assert ServiceSet.empty().overlaps(ServiceSet.any())

    def test_describe_any(self):
        assert ServiceSet.any().describe() == "ALL"

    def test_describe_empty(self):
        assert ServiceSet.empty().describe() == "empty"


# =========================================================================
# InterfaceSet
# =========================================================================

class TestInterfaceSet:

    def test_any(self):
        s = InterfaceSet.any()
        assert s.is_any

    def test_from_names_basic(self):
        s = InterfaceSet.from_names(["port1", "port2"])
        assert s.names == {"port1", "port2"}
        assert not s.is_any

    def test_from_names_with_any(self):
        s = InterfaceSet.from_names(["port1", "any", "port2"])
        assert s.is_any

    def test_from_names_case_insensitive(self):
        s = InterfaceSet.from_names(["Port1", "PORT2"])
        assert s.names == {"port1", "port2"}

    def test_from_names_any_case_insensitive(self):
        s = InterfaceSet.from_names(["ANY"])
        assert s.is_any

    def test_contains_subset(self):
        big = InterfaceSet.from_names(["port1", "port2", "port3"])
        small = InterfaceSet.from_names(["port1", "port2"])
        assert big.contains(small)
        assert not small.contains(big)

    def test_contains_any_contains_all(self):
        any_if = InterfaceSet.any()
        specific = InterfaceSet.from_names(["port1"])
        assert any_if.contains(specific)
        assert not specific.contains(any_if)

    def test_overlaps_shared_interface(self):
        a = InterfaceSet.from_names(["port1", "port2"])
        b = InterfaceSet.from_names(["port2", "port3"])
        assert a.overlaps(b)

    def test_overlaps_disjoint(self):
        a = InterfaceSet.from_names(["port1"])
        b = InterfaceSet.from_names(["port2"])
        assert not a.overlaps(b)

    def test_overlaps_any(self):
        a = InterfaceSet.any()
        b = InterfaceSet.from_names(["port1"])
        assert a.overlaps(b)
        assert b.overlaps(a)

    def test_intersection_basic(self):
        a = InterfaceSet.from_names(["port1", "port2", "port3"])
        b = InterfaceSet.from_names(["port2", "port3", "port4"])
        inter = a.intersection(b)
        assert inter.names == {"port2", "port3"}
        assert not inter.is_any

    def test_intersection_with_any(self):
        a = InterfaceSet.any()
        b = InterfaceSet.from_names(["port1", "port2"])
        inter = a.intersection(b)
        assert inter.names == {"port1", "port2"}

    def test_intersection_any_reverse(self):
        a = InterfaceSet.from_names(["port1"])
        b = InterfaceSet.any()
        inter = a.intersection(b)
        assert inter.names == {"port1"}

    def test_intersection_disjoint(self):
        a = InterfaceSet.from_names(["port1"])
        b = InterfaceSet.from_names(["port2"])
        inter = a.intersection(b)
        assert inter.names == set()

    def test_describe_any(self):
        assert InterfaceSet.any().describe() == "any"

    def test_describe_names(self):
        s = InterfaceSet.from_names(["port2", "port1"])
        assert s.describe() == "port1, port2"

    def test_describe_empty(self):
        s = InterfaceSet(names=set())
        assert s.describe() == "none"


# =========================================================================
# ScheduleSpec
# =========================================================================

class TestScheduleSpec:

    def test_always(self):
        s = ScheduleSpec.always()
        assert s.is_always
        assert s.raw_name == "always"

    def test_always_contains_everything(self):
        always = ScheduleSpec.always()
        recurring = ScheduleSpec(weekdays={1, 2, 3}, start_time="08:00", end_time="17:00")
        assert always.contains(recurring)
        assert not recurring.contains(always)

    def test_recurring_contains_subset_days(self):
        broad = ScheduleSpec(weekdays={0, 1, 2, 3, 4, 5, 6},
                             start_time="00:00", end_time="23:59")
        narrow = ScheduleSpec(weekdays={1, 2, 3},
                              start_time="08:00", end_time="17:00")
        assert broad.contains(narrow)
        assert not narrow.contains(broad)

    def test_recurring_no_contains_wider_time(self):
        a = ScheduleSpec(weekdays={1, 2, 3}, start_time="09:00", end_time="17:00")
        b = ScheduleSpec(weekdays={1, 2}, start_time="08:00", end_time="17:00")
        # b starts earlier than a, so a doesn't contain b
        assert not a.contains(b)

    def test_recurring_no_contains_extra_days(self):
        a = ScheduleSpec(weekdays={1, 2, 3}, start_time="08:00", end_time="17:00")
        b = ScheduleSpec(weekdays={1, 2, 3, 4}, start_time="08:00", end_time="17:00")
        assert not a.contains(b)

    def test_contains_unresolved_is_conservative(self):
        always = ScheduleSpec.always()
        unresolved = ScheduleSpec(unresolved_name="custom_schedule")
        assert always.contains(unresolved)  # always contains everything
        # But a non-always schedule can't claim to contain unresolved
        recurring = ScheduleSpec(weekdays={0, 1, 2, 3, 4, 5, 6},
                                 start_time="00:00", end_time="23:59")
        assert not recurring.contains(unresolved)

    def test_overlaps_always(self):
        always = ScheduleSpec.always()
        recurring = ScheduleSpec(weekdays={1}, start_time="09:00", end_time="10:00")
        assert always.overlaps(recurring)
        assert recurring.overlaps(always)

    def test_overlaps_shared_weekday_and_time(self):
        a = ScheduleSpec(weekdays={1, 2, 3}, start_time="08:00", end_time="12:00")
        b = ScheduleSpec(weekdays={3, 4, 5}, start_time="10:00", end_time="14:00")
        assert a.overlaps(b)  # shared day 3, overlapping time

    def test_overlaps_disjoint_weekdays(self):
        a = ScheduleSpec(weekdays={1, 2}, start_time="08:00", end_time="17:00")
        b = ScheduleSpec(weekdays={4, 5}, start_time="08:00", end_time="17:00")
        assert not a.overlaps(b)

    def test_overlaps_disjoint_time(self):
        a = ScheduleSpec(weekdays={1, 2, 3}, start_time="08:00", end_time="12:00")
        b = ScheduleSpec(weekdays={1, 2, 3}, start_time="13:00", end_time="17:00")
        assert not a.overlaps(b)

    def test_overlaps_unresolved_is_conservative(self):
        a = ScheduleSpec(unresolved_name="sched1")
        b = ScheduleSpec(weekdays={1}, start_time="08:00", end_time="17:00")
        assert a.overlaps(b)  # conservative: assumes overlap

    def test_describe_always(self):
        assert ScheduleSpec.always().describe() == "always"

    def test_describe_unresolved(self):
        s = ScheduleSpec(unresolved_name="my_sched")
        assert "unresolved" in s.describe()

    def test_describe_recurring(self):
        s = ScheduleSpec(weekdays={1, 3, 5}, start_time="08:00", end_time="17:00")
        desc = s.describe()
        assert "Mon" in desc
        assert "Wed" in desc
        assert "Fri" in desc
        assert "08:00-17:00" in desc


# =========================================================================
# InstallScope
# =========================================================================

class TestInstallScope:

    def test_global_scope(self):
        s = InstallScope.global_scope()
        assert s.is_global

    def test_from_scope_members_empty(self):
        s = InstallScope.from_scope_members([])
        assert s.is_global

    def test_from_scope_members(self):
        members = [
            {"name": "FW01", "vdom": "root"},
            {"name": "FW02", "vdom": "VDOM1"},
        ]
        s = InstallScope.from_scope_members(members)
        assert not s.is_global
        assert ("fw01", "root") in s.targets
        assert ("fw02", "vdom1") in s.targets

    def test_from_scope_members_default_vdom(self):
        members = [{"name": "FW01"}]
        s = InstallScope.from_scope_members(members)
        assert ("fw01", "root") in s.targets

    def test_from_scope_members_skips_empty_name(self):
        members = [{"name": "", "vdom": "root"}, {"name": "FW01", "vdom": "root"}]
        s = InstallScope.from_scope_members(members)
        assert len(s.targets) == 1

    def test_overlaps_global(self):
        g = InstallScope.global_scope()
        specific = InstallScope.from_scope_members([{"name": "FW01", "vdom": "root"}])
        assert g.overlaps(specific)
        assert specific.overlaps(g)

    def test_no_targets_scope_never_overlaps(self):
        no_targets = InstallScope.no_targets()
        global_scope = InstallScope.global_scope()
        specific = InstallScope.from_scope_members([
            {"name": "FW01", "vdom": "root"},
        ])

        assert not no_targets.overlaps(global_scope)
        assert not global_scope.overlaps(no_targets)
        assert not no_targets.overlaps(specific)

    def test_overlaps_shared_target(self):
        a = InstallScope.from_scope_members([
            {"name": "FW01", "vdom": "root"},
            {"name": "FW02", "vdom": "root"},
        ])
        b = InstallScope.from_scope_members([
            {"name": "FW02", "vdom": "root"},
            {"name": "FW03", "vdom": "root"},
        ])
        assert a.overlaps(b)

    def test_overlaps_disjoint(self):
        a = InstallScope.from_scope_members([{"name": "FW01", "vdom": "root"}])
        b = InstallScope.from_scope_members([{"name": "FW02", "vdom": "root"}])
        assert not a.overlaps(b)

    def test_overlaps_both_global(self):
        assert InstallScope.global_scope().overlaps(InstallScope.global_scope())

    def test_contains_global_covers_specific(self):
        global_scope = InstallScope.global_scope()
        specific = InstallScope.from_scope_members([
            {"name": "FW01", "vdom": "root"},
        ])
        assert global_scope.contains(specific)
        assert not specific.contains(global_scope)

    def test_contains_specific_superset(self):
        broader = InstallScope.from_scope_members([
            {"name": "FW01", "vdom": "root"},
            {"name": "FW02", "vdom": "root"},
        ])
        narrower = InstallScope.from_scope_members([
            {"name": "FW01", "vdom": "root"},
        ])
        assert broader.contains(narrower)
        assert not narrower.contains(broader)

    def test_contains_specific_equal(self):
        a = InstallScope.from_scope_members([
            {"name": "FW01", "vdom": "root"},
        ])
        b = InstallScope.from_scope_members([
            {"name": "fw01", "vdom": "ROOT"},
        ])
        assert a.contains(b)
        assert b.contains(a)

    def test_empty_specific_scope_never_proves_containment(self):
        malformed = InstallScope.no_targets()
        global_scope = InstallScope.global_scope()
        specific = InstallScope.from_scope_members([
            {"name": "FW01", "vdom": "root"},
        ])

        assert not malformed.contains(malformed)
        assert not malformed.contains(specific)
        assert not global_scope.contains(malformed)
        assert malformed.describe() == "no targets"

    def test_describe_global(self):
        assert InstallScope.global_scope().describe() == "all targets"

    def test_describe_specific(self):
        s = InstallScope.from_scope_members([{"name": "FW01", "vdom": "root"}])
        assert "fw01/root" in s.describe()

    # --- group_map expansion tests ---

    def test_from_scope_members_group_expansion(self):
        group_map = {
            "branch-firewalls": {("fw01", "root"), ("fw02", "root")},
        }
        members = [{"name": "Branch-Firewalls", "vdom": "root"}]
        s = InstallScope.from_scope_members(members, group_map=group_map)
        assert not s.is_global
        assert ("fw01", "root") in s.targets
        assert ("fw02", "root") in s.targets
        assert len(s.targets) == 2

    def test_from_scope_members_group_and_device_mixed(self):
        group_map = {
            "grp-a": {("fw01", "root"), ("fw02", "root")},
        }
        members = [
            {"name": "GRP-A", "vdom": "root"},
            {"name": "FW03", "vdom": "dmz"},
        ]
        s = InstallScope.from_scope_members(members, group_map=group_map)
        assert ("fw01", "root") in s.targets
        assert ("fw02", "root") in s.targets
        assert ("fw03", "dmz") in s.targets
        assert len(s.targets) == 3

    def test_from_scope_members_no_group_map_passthrough(self):
        """Without group_map, group names are treated as device names."""
        members = [{"name": "Branch-Firewalls", "vdom": "root"}]
        s = InstallScope.from_scope_members(members, group_map=None)
        assert ("branch-firewalls", "root") in s.targets

    def test_overlaps_after_group_expansion(self):
        group_map = {
            "grp-a": {("fw01", "root"), ("fw02", "root")},
            "grp-b": {("fw02", "root"), ("fw03", "root")},
        }
        a = InstallScope.from_scope_members(
            [{"name": "GRP-A", "vdom": "root"}], group_map=group_map,
        )
        b = InstallScope.from_scope_members(
            [{"name": "GRP-B", "vdom": "root"}], group_map=group_map,
        )
        # FW02 is in both groups, so they overlap
        assert a.overlaps(b)

    def test_no_overlap_after_group_expansion(self):
        group_map = {
            "grp-a": {("fw01", "root")},
            "grp-b": {("fw03", "root")},
        }
        a = InstallScope.from_scope_members(
            [{"name": "GRP-A", "vdom": "root"}], group_map=group_map,
        )
        b = InstallScope.from_scope_members(
            [{"name": "GRP-B", "vdom": "root"}], group_map=group_map,
        )
        assert not a.overlaps(b)

    # --- "is group" flag and vdom-absent group detection ---

    def test_is_group_flag_triggers_expansion(self):
        """Scope member with 'is group' flag should expand via group_map."""
        group_map = {
            "store-firewalls": {("store-fw1", "root"), ("store-fw2", "root")},
        }
        members = [{"name": "Store-Firewalls", "is group": True}]
        s = InstallScope.from_scope_members(members, group_map=group_map)
        assert not s.is_global
        assert ("store-fw1", "root") in s.targets
        assert ("store-fw2", "root") in s.targets
        assert len(s.targets) == 2

    def test_is_group_flag_integer(self):
        """FMG sometimes returns 'is group': 1 instead of True."""
        group_map = {
            "dc-group": {("dc-fw1", "root")},
        }
        members = [{"name": "DC-Group", "is group": 1}]
        s = InstallScope.from_scope_members(members, group_map=group_map)
        assert ("dc-fw1", "root") in s.targets

    def test_no_vdom_means_group(self):
        """Per FMG API docs, a name without vdom = device group."""
        group_map = {
            "branch-group": {("br-fw1", "root"), ("br-fw2", "root")},
        }
        members = [{"name": "Branch-Group"}]
        s = InstallScope.from_scope_members(members, group_map=group_map)
        assert ("br-fw1", "root") in s.targets
        assert ("br-fw2", "root") in s.targets

    def test_unknown_group_no_overlap_with_devices(self):
        """A group not in group_map should not overlap with named devices."""
        group_map = {}
        a = InstallScope.from_scope_members(
            [{"name": "Unknown-Group", "is group": True}], group_map=group_map,
        )
        b = InstallScope.from_scope_members(
            [{"name": "FW01", "vdom": "root"}], group_map=group_map,
        )
        assert not a.overlaps(b)

    def test_unknown_group_overlaps_with_same_group(self):
        """Two policies targeting the same unknown group should overlap."""
        group_map = {}
        a = InstallScope.from_scope_members(
            [{"name": "Unknown-Group", "is group": True}], group_map=group_map,
        )
        b = InstallScope.from_scope_members(
            [{"name": "Unknown-Group", "is group": 1}], group_map=group_map,
        )
        assert a.overlaps(b)

    def test_no_overlap_different_unknown_groups(self):
        """Two policies targeting different unknown groups should not overlap."""
        group_map = {}
        a = InstallScope.from_scope_members(
            [{"name": "Group-A", "is group": True}], group_map=group_map,
        )
        b = InstallScope.from_scope_members(
            [{"name": "Group-B", "is group": True}], group_map=group_map,
        )
        assert not a.overlaps(b)

    def test_is_group_no_vdom_mixed_with_device(self):
        """Mix of group (no vdom) and device (with vdom) in same scope."""
        group_map = {
            "grp-x": {("fw10", "root")},
        }
        members = [
            {"name": "GRP-X"},  # no vdom = group
            {"name": "FW20", "vdom": "dmz"},  # device
        ]
        s = InstallScope.from_scope_members(members, group_map=group_map)
        assert ("fw10", "root") in s.targets
        assert ("fw20", "dmz") in s.targets
