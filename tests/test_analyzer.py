"""
Comprehensive test suite for the shadow analysis engine.

Tests all 15 scenarios using synthetic CanonicalPolicy objects with
pre-resolved fields fed directly into ShadowAnalyzer.analyze_package().
"""

import pytest

from fmg_shadow.models import (
    AddressSet,
    CanonicalPolicy,
    FindingType,
    IPInterval,
    InstallScope,
    InterfaceSet,
    PolicyAction,
    PortInterval,
    Protocol,
    ScheduleSpec,
    ServiceSet,
    ServiceSpec,
)
from fmg_shadow.analyzer import ShadowAnalyzer


# ---------------------------------------------------------------------------
# Helper: build a policy with sensible defaults
# ---------------------------------------------------------------------------

def _policy(
    policyid: int,
    seq_num: int,
    *,
    name: str = "",
    srcintf=None,
    dstintf=None,
    srcaddr=None,
    dstaddr=None,
    service=None,
    schedule=None,
    action: PolicyAction = PolicyAction.ACCEPT,
    status: str = "enable",
    install_scope=None,
    is_section_title: bool = False,
    policy_section: str = "local",
) -> CanonicalPolicy:
    return CanonicalPolicy(
        fmg="test",
        adom="root",
        package="pkg1",
        policyid=policyid,
        name=name or f"rule_{policyid}",
        seq_num=seq_num,
        srcintf=srcintf or InterfaceSet.any(),
        dstintf=dstintf or InterfaceSet.any(),
        srcaddr=srcaddr or AddressSet.any(),
        dstaddr=dstaddr or AddressSet.any(),
        service=service or ServiceSet.any(),
        schedule=schedule or ScheduleSpec.always(),
        action=action,
        status=status,
        install_scope=install_scope or InstallScope.global_scope(),
        is_section_title=is_section_title,
        policy_section=policy_section,
    )


# ---------------------------------------------------------------------------
# 1. Full shadow by broader allow
# ---------------------------------------------------------------------------

class TestFullShadowByBroaderAllow:
    """Earlier any/any/any/any/ALL/always/accept fully shadows a later specific accept."""

    def test_full_shadow_by_broader_allow(self):
        broad = _policy(1, 0, action=PolicyAction.ACCEPT)  # all any
        specific = _policy(2, 1,
            srcaddr=AddressSet.from_intervals([IPInterval.from_subnet("10.0.0.0", "255.255.255.0")]),
            dstaddr=AddressSet.from_intervals([IPInterval.from_host("192.168.1.1")]),
            service=ServiceSet(specs=[ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval.single(80))]),
            action=PolicyAction.ACCEPT,
        )

        findings = ShadowAnalyzer().analyze_package([broad, specific])
        assert len(findings) == 1
        f = findings[0]
        assert f.finding_type == FindingType.FULL_REDUNDANT_COVERAGE
        assert f.is_fully_unreachable is True
        assert f.same_action is True
        assert f.shadowed_policyid == 2
        assert f.shadowing_policyids == [1]


# ---------------------------------------------------------------------------
# 2. Full shadow by broader deny
# ---------------------------------------------------------------------------

class TestFullShadowByBroaderDeny:
    """Earlier broad deny fully shadows later specific deny."""

    def test_full_shadow_by_broader_deny(self):
        broad_deny = _policy(1, 0, action=PolicyAction.DENY)
        specific_deny = _policy(2, 1,
            srcaddr=AddressSet.from_intervals([IPInterval.from_subnet("172.16.0.0", "255.255.0.0")]),
            action=PolicyAction.DENY,
        )

        findings = ShadowAnalyzer().analyze_package([broad_deny, specific_deny])
        assert len(findings) == 1
        f = findings[0]
        assert f.finding_type == FindingType.FULL_REDUNDANT_COVERAGE
        assert f.is_fully_unreachable is True
        assert f.same_action is True


# ---------------------------------------------------------------------------
# 3. Partial shadow by broader rule (overlapping srcaddr)
# ---------------------------------------------------------------------------

class TestPartialShadowByBroaderRule:
    """Earlier rule with broader srcaddr partially shadows later rule."""

    def test_partial_shadow_by_broader_rule(self):
        # Earlier: srcaddr = 10.0.0.0/16, dstaddr = 192.168.1.0/24
        earlier = _policy(1, 0,
            srcaddr=AddressSet.from_intervals([IPInterval.from_subnet("10.0.0.0", "255.255.0.0")]),
            dstaddr=AddressSet.from_intervals([IPInterval.from_subnet("192.168.1.0", "255.255.255.0")]),
            action=PolicyAction.ACCEPT,
        )
        # Later: srcaddr = 10.0.0.0/8 (broader src), same dstaddr
        later = _policy(2, 1,
            srcaddr=AddressSet.from_intervals([IPInterval.from_subnet("10.0.0.0", "255.0.0.0")]),
            dstaddr=AddressSet.from_intervals([IPInterval.from_subnet("192.168.1.0", "255.255.255.0")]),
            action=PolicyAction.ACCEPT,
        )

        findings = ShadowAnalyzer().analyze_package([earlier, later])
        assert len(findings) == 1
        f = findings[0]
        assert f.finding_type == FindingType.PARTIAL_REDUNDANT_OVERLAP
        assert f.is_fully_unreachable is False
        assert f.same_action is True


# ---------------------------------------------------------------------------
# 4. Full redundant – exact same match space, same action
# ---------------------------------------------------------------------------

class TestFullRedundantSameAction:
    """Two rules with identical match space and same action = full redundancy."""

    def test_full_redundant_same_action(self):
        net = AddressSet.from_intervals([IPInterval.from_subnet("10.1.0.0", "255.255.0.0")])
        svc = ServiceSet(specs=[ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval.single(443))])
        intf = InterfaceSet.from_names(["port1"])

        r1 = _policy(10, 0, srcintf=intf, srcaddr=net, service=svc, action=PolicyAction.ACCEPT)
        r2 = _policy(20, 1, srcintf=intf, srcaddr=net, service=svc, action=PolicyAction.ACCEPT)

        findings = ShadowAnalyzer().analyze_package([r1, r2])
        assert len(findings) == 1
        f = findings[0]
        assert f.finding_type == FindingType.FULL_REDUNDANT_COVERAGE
        assert f.is_fully_unreachable is True
        assert f.same_action is True


# ---------------------------------------------------------------------------
# 5. Partial redundant overlap
# ---------------------------------------------------------------------------

class TestPartialRedundantOverlap:
    """Overlapping rules with same action but not full containment."""

    def test_partial_redundant_overlap(self):
        # Earlier: ports 80-100
        r1 = _policy(1, 0,
            service=ServiceSet(specs=[ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval(80, 100))]),
            action=PolicyAction.ACCEPT,
        )
        # Later: ports 90-120 (overlaps 90-100)
        r2 = _policy(2, 1,
            service=ServiceSet(specs=[ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval(90, 120))]),
            action=PolicyAction.ACCEPT,
        )

        findings = ShadowAnalyzer().analyze_package([r1, r2])
        assert len(findings) == 1
        f = findings[0]
        assert f.finding_type == FindingType.PARTIAL_REDUNDANT_OVERLAP
        assert f.is_fully_unreachable is False
        assert f.same_action is True


# ---------------------------------------------------------------------------
# 6. Composite shadow – union of multiple earlier rules covers later
# ---------------------------------------------------------------------------

class TestCompositeShadowMultipleRules:
    """Three earlier rules whose srcaddr union fully covers the later rule's srcaddr."""

    def test_composite_shadow_multiple_rules(self):
        svc = ServiceSet.any()
        # Later rule: srcaddr = 10.0.0.0/24 (10.0.0.0 - 10.0.0.255)
        later_src = AddressSet.from_intervals([IPInterval.from_subnet("10.0.0.0", "255.255.255.0")])

        # Split into three chunks that together cover 10.0.0.0/24
        r1 = _policy(1, 0,
            srcaddr=AddressSet.from_intervals([IPInterval.from_range("10.0.0.0", "10.0.0.99")]),
            action=PolicyAction.ACCEPT,
        )
        r2 = _policy(2, 1,
            srcaddr=AddressSet.from_intervals([IPInterval.from_range("10.0.0.100", "10.0.0.199")]),
            action=PolicyAction.ACCEPT,
        )
        r3 = _policy(3, 2,
            srcaddr=AddressSet.from_intervals([IPInterval.from_range("10.0.0.200", "10.0.0.255")]),
            action=PolicyAction.ACCEPT,
        )
        later = _policy(4, 3, srcaddr=later_src, action=PolicyAction.ACCEPT)

        findings = ShadowAnalyzer().analyze_package([r1, r2, r3, later])
        # There will be partial pairwise findings + one composite finding
        composite_findings = [f for f in findings if f.is_composite]
        assert len(composite_findings) == 1
        cf = composite_findings[0]
        assert cf.finding_type == FindingType.FULL_REDUNDANT_COVERAGE
        assert cf.is_fully_unreachable is True
        assert cf.same_action is True
        assert cf.shadowed_policyid == 4


# ---------------------------------------------------------------------------
# 7. No shadow – non-overlapping dimensions
# ---------------------------------------------------------------------------

class TestNoShadowAdjacentRules:
    """Rules with completely non-overlapping dimensions produce no findings."""

    def test_no_shadow_different_interfaces(self):
        r1 = _policy(1, 0,
            srcintf=InterfaceSet.from_names(["port1"]),
            dstintf=InterfaceSet.from_names(["port2"]),
        )
        r2 = _policy(2, 1,
            srcintf=InterfaceSet.from_names(["port3"]),
            dstintf=InterfaceSet.from_names(["port4"]),
        )
        findings = ShadowAnalyzer().analyze_package([r1, r2])
        assert len(findings) == 0

    def test_no_shadow_different_addresses(self):
        r1 = _policy(1, 0,
            srcaddr=AddressSet.from_intervals([IPInterval.from_subnet("10.0.0.0", "255.255.255.0")]),
        )
        r2 = _policy(2, 1,
            srcaddr=AddressSet.from_intervals([IPInterval.from_subnet("172.16.0.0", "255.255.255.0")]),
        )
        findings = ShadowAnalyzer().analyze_package([r1, r2])
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# 8. Schedule-limited partial overlap
# ---------------------------------------------------------------------------

class TestScheduleLimitedPartialOverlap:
    """Earlier weekday-only schedule partially shadows later always schedule."""

    def test_schedule_limited_partial_overlap(self):
        weekday_sched = ScheduleSpec(
            weekdays={1, 2, 3, 4, 5},  # Mon-Fri
            start_time="00:00",
            end_time="23:59",
            raw_name="weekdays",
        )
        # Earlier: weekday schedule, same match space
        r1 = _policy(1, 0, schedule=weekday_sched, action=PolicyAction.ACCEPT)
        # Later: always schedule, same match space
        r2 = _policy(2, 1, schedule=ScheduleSpec.always(), action=PolicyAction.ACCEPT)

        findings = ShadowAnalyzer().analyze_package([r1, r2])
        assert len(findings) == 1
        f = findings[0]
        # Earlier covers weekdays only, not all of "always" -> partial
        assert f.finding_type == FindingType.PARTIAL_REDUNDANT_OVERLAP
        assert f.is_fully_unreachable is False


# ---------------------------------------------------------------------------
# 9. Install scope separation – no findings
# ---------------------------------------------------------------------------

class TestInstallScopeSeparation:
    """Rules with non-overlapping install scope targets must NOT be flagged."""

    def test_install_scope_separation(self):
        scope_a = InstallScope.from_scope_members([{"name": "fw1", "vdom": "root"}])
        scope_b = InstallScope.from_scope_members([{"name": "fw2", "vdom": "root"}])

        r1 = _policy(1, 0, install_scope=scope_a, action=PolicyAction.ACCEPT)
        r2 = _policy(2, 1, install_scope=scope_b, action=PolicyAction.ACCEPT)

        findings = ShadowAnalyzer().analyze_package([r1, r2])
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# 10. Nested address group shadow (resolved AddressSets)
# ---------------------------------------------------------------------------

class TestNestedAddressGroupShadow:
    """Shadow detected through resolved nested address groups."""

    def test_nested_address_group_shadow(self):
        # Simulate a nested group: outer_group = inner_group1 + inner_group2
        # inner_group1 = 10.0.0.0/24, inner_group2 = 10.0.1.0/24
        # outer_group resolves to 10.0.0.0/23
        outer_group = AddressSet.from_intervals([
            IPInterval.from_subnet("10.0.0.0", "255.255.255.0"),
            IPInterval.from_subnet("10.0.1.0", "255.255.255.0"),
        ])
        # Later rule uses only inner_group1
        inner_group = AddressSet.from_intervals([
            IPInterval.from_subnet("10.0.0.0", "255.255.255.0"),
        ])

        r1 = _policy(1, 0, srcaddr=outer_group, action=PolicyAction.ACCEPT)
        r2 = _policy(2, 1, srcaddr=inner_group, action=PolicyAction.ACCEPT)

        findings = ShadowAnalyzer().analyze_package([r1, r2])
        assert len(findings) == 1
        f = findings[0]
        assert f.finding_type == FindingType.FULL_REDUNDANT_COVERAGE
        assert f.is_fully_unreachable is True
        assert f.same_action is True


# ---------------------------------------------------------------------------
# 11. Nested service group shadow (resolved ServiceSets)
# ---------------------------------------------------------------------------

class TestNestedServiceGroupShadow:
    """Shadow detected through resolved nested service groups."""

    def test_nested_service_group_shadow(self):
        # Earlier: service group covering TCP/80 + TCP/443 + UDP/53
        broad_svc = ServiceSet(specs=[
            ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval(80, 80)),
            ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval(443, 443)),
            ServiceSpec(protocol=Protocol.UDP, dst_ports=PortInterval(53, 53)),
        ])
        # Later: just TCP/443
        narrow_svc = ServiceSet(specs=[
            ServiceSpec(protocol=Protocol.TCP, dst_ports=PortInterval(443, 443)),
        ])

        r1 = _policy(1, 0, service=broad_svc, action=PolicyAction.ACCEPT)
        r2 = _policy(2, 1, service=narrow_svc, action=PolicyAction.ACCEPT)

        findings = ShadowAnalyzer().analyze_package([r1, r2])
        assert len(findings) == 1
        f = findings[0]
        assert f.finding_type == FindingType.FULL_REDUNDANT_COVERAGE
        assert f.is_fully_unreachable is True
        assert f.same_action is True


# ---------------------------------------------------------------------------
# 12. Disabled rules excluded (unless include_disabled=True)
# ---------------------------------------------------------------------------

class TestDisabledRulesExcluded:
    """Disabled rules don't participate unless include_disabled=True."""

    def test_disabled_rules_excluded(self):
        r1 = _policy(1, 0, action=PolicyAction.ACCEPT)
        r2 = _policy(2, 1, action=PolicyAction.ACCEPT, status="disable")

        # Without include_disabled: disabled rule is skipped, only 1 effective
        findings = ShadowAnalyzer().analyze_package([r1, r2], include_disabled=False)
        assert len(findings) == 0

    def test_disabled_rules_included(self):
        r1 = _policy(1, 0, action=PolicyAction.ACCEPT)
        r2 = _policy(2, 1, action=PolicyAction.ACCEPT, status="disable")

        findings = ShadowAnalyzer().analyze_package([r1, r2], include_disabled=True)
        assert len(findings) == 1
        f = findings[0]
        assert f.finding_type == FindingType.FULL_REDUNDANT_COVERAGE


# ---------------------------------------------------------------------------
# 13. Section titles excluded
# ---------------------------------------------------------------------------

class TestSectionTitlesExcluded:
    """Section title pseudo-rules are always excluded from analysis."""

    def test_section_titles_excluded(self):
        section = _policy(0, 0, name="--- SECTION ---", is_section_title=True)
        r1 = _policy(1, 1, action=PolicyAction.ACCEPT)
        r2 = _policy(2, 2, action=PolicyAction.ACCEPT)

        findings = ShadowAnalyzer().analyze_package([section, r1, r2])
        # section title is filtered out; r1 fully shadows r2
        assert len(findings) == 1
        f = findings[0]
        assert f.shadowed_policyid == 2
        assert f.shadowing_policyids == [1]

    def test_section_title_not_shadowed(self):
        """A section title should never appear as a shadowed rule."""
        r1 = _policy(1, 0, action=PolicyAction.ACCEPT)
        section = _policy(0, 1, name="--- SECTION ---", is_section_title=True)

        findings = ShadowAnalyzer().analyze_package([r1, section])
        # Only 1 effective rule => no pairwise comparison possible
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# 14. Conflict shadow – different action
# ---------------------------------------------------------------------------

class TestConflictShadowDifferentAction:
    """Earlier accept shadows later deny = full conflict shadow."""

    def test_conflict_shadow_different_action(self):
        r1 = _policy(1, 0, action=PolicyAction.ACCEPT)  # broad accept
        r2 = _policy(2, 1,
            srcaddr=AddressSet.from_intervals([IPInterval.from_subnet("10.0.0.0", "255.255.255.0")]),
            action=PolicyAction.DENY,
        )

        findings = ShadowAnalyzer().analyze_package([r1, r2])
        assert len(findings) == 1
        f = findings[0]
        assert f.finding_type == FindingType.FULL_CONFLICT_SHADOW
        assert f.is_fully_unreachable is True
        assert f.same_action is False
        assert f.shadowed_action == "deny"
        assert f.shadowing_action == "accept"

    def test_partial_conflict_shadow(self):
        """Partial overlap with different actions = partial conflict."""
        r1 = _policy(1, 0,
            srcaddr=AddressSet.from_intervals([IPInterval.from_subnet("10.0.0.0", "255.255.0.0")]),
            action=PolicyAction.ACCEPT,
        )
        r2 = _policy(2, 1,
            srcaddr=AddressSet.from_intervals([IPInterval.from_subnet("10.0.0.0", "255.0.0.0")]),
            action=PolicyAction.DENY,
        )

        findings = ShadowAnalyzer().analyze_package([r1, r2])
        assert len(findings) == 1
        f = findings[0]
        assert f.finding_type == FindingType.PARTIAL_CONFLICT_SHADOW
        assert f.is_fully_unreachable is False
        assert f.same_action is False


# ---------------------------------------------------------------------------
# 15. Empty policy list – no crash
# ---------------------------------------------------------------------------

class TestEmptyPolicyList:
    """No crash on empty or single-item input."""

    def test_empty_policy_list(self):
        findings = ShadowAnalyzer().analyze_package([])
        assert findings == []

    def test_single_policy(self):
        findings = ShadowAnalyzer().analyze_package([_policy(1, 0)])
        assert findings == []


# ---------------------------------------------------------------------------
# 16. Global header/footer policy sections
# ---------------------------------------------------------------------------

class TestGlobalPolicySections:
    """Global header/footer policies participate in the evaluation order and
    their origin is recorded on the resulting findings."""

    def test_global_header_shadows_local(self):
        # Global header (deny any) precedes a local accept of a subset.
        gheader = _policy(
            101, 0, action=PolicyAction.DENY, policy_section="global-header"
        )
        local = _policy(
            5, 1,
            srcaddr=AddressSet.from_intervals(
                [IPInterval.from_subnet("10.0.0.0", "255.255.255.0")]
            ),
            action=PolicyAction.ACCEPT,
            policy_section="local",
        )

        findings = ShadowAnalyzer().analyze_package([gheader, local])
        assert len(findings) == 1
        f = findings[0]
        assert f.finding_type == FindingType.FULL_CONFLICT_SHADOW
        assert f.shadowed_policyid == 5
        assert f.shadowed_section == "local"
        assert f.shadowing_policyids == [101]
        assert f.shadowing_sections == ["global-header"]

    def test_local_shadows_global_footer(self):
        # A broad local accept precedes (and shadows) a global footer rule.
        local = _policy(
            5, 0, action=PolicyAction.ACCEPT, policy_section="local"
        )
        gfooter = _policy(
            201, 1,
            srcaddr=AddressSet.from_intervals(
                [IPInterval.from_subnet("10.0.0.0", "255.255.255.0")]
            ),
            action=PolicyAction.ACCEPT,
            policy_section="global-footer",
        )

        findings = ShadowAnalyzer().analyze_package([local, gfooter])
        assert len(findings) == 1
        f = findings[0]
        assert f.shadowed_policyid == 201
        assert f.shadowed_section == "global-footer"
        assert f.shadowing_sections == ["local"]


class TestPolicyLabelSection:
    """label() flags global header/footer origin; local stays unadorned."""

    def test_label_includes_section(self):
        assert _policy(1, 0, policy_section="local").label().startswith("#1 ")
        assert _policy(1, 0, policy_section="global-header").label().startswith(
            "[global-header] #1 "
        )
        assert _policy(1, 0, policy_section="global-footer").label().startswith(
            "[global-footer] #1 "
        )
