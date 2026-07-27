"""Regression tests for conservative object normalization."""

from fmg_shadow.analyzer import ShadowAnalyzer
from fmg_shadow.models import PackageResult
from fmg_shadow.objects import ObjectResolver
from fmg_shadow.policy_fetch import _build_policy
from fmg_shadow.reporting import _collect_disable_candidates


def _resolver():
    resolver = ObjectResolver(None, "root")
    resolver._addresses = {}
    resolver._addrgroups = {}
    resolver._vips = {}
    resolver._vipgroups = {}
    resolver._services = {}
    resolver._service_groups = {}
    resolver._sched_onetime = {}
    resolver._sched_recurring = {}
    resolver._sched_groups = {}
    return resolver


class _MappingClient:

    def __init__(self):
        self.calls = []

    def get(
        self,
        url,
        option=None,
        range_=None,
        loadsub=None,
    ):
        self.calls.append({
            "url": url,
            "option": option,
            "range_": range_,
            "loadsub": loadsub,
        })
        if url.endswith("/obj/firewall/address"):
            return [{
                "name": "mapped-address",
                "type": "ipmask",
                "subnet": ["10.0.0.0", "255.255.255.0"],
                "dynamic_mapping": [{
                    "scope": "fw1",
                    "subnet": ["192.0.2.1", "255.255.255.255"],
                }],
            }]
        return []


class TestDynamicMappings:

    def test_bulk_fetch_loads_subtables_and_blocks_remediation(self):
        client = _MappingClient()
        resolver = ObjectResolver(client, "root")
        resolver.fetch_all_addresses()
        address_call = client.calls[0]

        assert address_call["loadsub"] == 1

        def policy(policy_id, seq, srcaddr):
            result = _build_policy({
                "policyid": policy_id,
                "name": "policy-{}".format(policy_id),
                "action": "accept",
                "status": "enable",
                "srcintf": ["any"],
                "dstintf": ["any"],
                "srcaddr": [srcaddr],
                "dstaddr": ["all"],
                "service": ["ALL"],
                "schedule": ["always"],
            }, "root", "pkg", seq)
            result.fmg = "fmg.example"
            resolver._resolve_policy(result)
            return result

        earlier = policy(10, 0, "all")
        target = policy(20, 1, "mapped-address")
        findings = ShadowAnalyzer().analyze_package([earlier, target])
        package = PackageResult(
            fmg="fmg.example",
            adom="root",
            package="pkg",
            policies=[earlier, target],
            findings=findings,
            total_policies=2,
            effective_policies=2,
        )

        assert target.has_unresolved
        assert any("dynamic-mapping" in note for note in target.unresolved_notes)
        assert _collect_disable_candidates(package) == []

    def test_address_mapping_is_unresolved(self):
        result = _resolver()._resolve_address_obj({
            "name": "mapped-address",
            "type": "ipmask",
            "subnet": ["10.0.0.0", "255.255.255.0"],
            "dynamic_mapping": [{"scope": "fw1", "subnet": "192.0.2.1/32"}],
        })

        assert result.unresolved_names == [
            "mapped-address:dynamic-mapping",
        ]

    def test_service_and_schedule_mappings_are_unresolved(self):
        resolver = _resolver()
        service = resolver._resolve_service_obj({
            "name": "mapped-service",
            "protocol": 5,
            "tcp-portrange": ["443"],
            "platform_mapping": [{"name": "fortigate", "tcp-portrange": "8443"}],
        })
        schedule = resolver._resolve_recurring_schedule({
            "name": "mapped-schedule",
            "day": ["monday"],
            "start": "08:00",
            "end": "17:00",
            "dynamic-mapping": [{"scope": "fw1"}],
        })

        assert service.unresolved_names == [
            "mapped-service:dynamic-mapping",
        ]
        assert schedule.unresolved_name == "mapped-schedule:dynamic-mapping"


class TestAddressGroups:

    def test_disabled_exclusion_is_not_treated_as_enabled(self):
        resolver = _resolver()
        resolver._addresses["fqdn"] = {
            "name": "fqdn",
            "type": "fqdn",
        }
        result = resolver._resolve_addrgroup({
            "name": "group",
            "member": ["all"],
            "exclude": "disable",
            "exclude-member": ["fqdn"],
        }, 0)

        assert result.is_any
        assert result.unresolved_names == []

    def test_unresolved_exclusion_uncertainty_is_propagated(self):
        resolver = _resolver()
        resolver._addresses["fqdn"] = {
            "name": "fqdn",
            "type": "fqdn",
        }
        result = resolver._resolve_addrgroup({
            "name": "group",
            "member": ["all"],
            "exclude": "enable",
            "exclude-member": ["fqdn"],
        }, 0)

        assert "exclude:fqdn" in result.unresolved_names


class TestVipResolution:

    def test_vip_policy_priority_blocks_disable_candidate(self):
        resolver = _resolver()
        resolver._vips["plain-vip"] = {
            "name": "plain-vip",
            "type": "static-nat",
            "extip": ["203.0.113.10"],
            "extintf": ["any"],
            "portforward": "disable",
        }

        def policy(policy_id, seq, action, destination):
            result = _build_policy({
                "policyid": policy_id,
                "name": "policy-{}".format(policy_id),
                "action": action,
                "status": "enable",
                "srcintf": ["any"],
                "dstintf": ["any"],
                "srcaddr": ["all"],
                "dstaddr": [destination],
                "service": ["ALL"],
                "schedule": ["always"],
            }, "root", "pkg", seq)
            result.fmg = "fmg.example"
            resolver._resolve_policy(result)
            return result

        earlier = policy(10, 0, "deny", "all")
        target = policy(20, 1, "accept", "plain-vip")
        findings = ShadowAnalyzer().analyze_package([earlier, target])
        package = PackageResult(
            fmg="fmg.example",
            adom="root",
            package="pkg",
            policies=[earlier, target],
            findings=findings,
            total_policies=2,
            effective_policies=2,
        )

        assert target.has_unresolved
        assert any("vip-priority" in note for note in target.unresolved_notes)
        assert _collect_disable_candidates(package) == []

    def test_plain_static_nat_vip_preserves_extip_but_marks_priority(self):
        result = _resolver()._resolve_vip({
            "name": "plain-vip",
            "type": "static-nat",
            "extip": ["203.0.113.10"],
            "extintf": ["any"],
            "portforward": "disable",
        })

        assert result.unresolved_names == ["plain-vip:vip-priority"]
        assert "203.0.113.10" in result.describe()

    def test_port_forward_vip_is_unresolved(self):
        result = _resolver()._resolve_vip({
            "name": "https-vip",
            "type": "static-nat",
            "extip": ["203.0.113.10"],
            "portforward": "enable",
            "protocol": "tcp",
            "extport": "443",
        })

        assert result.unresolved_names == ["https-vip:complex-vip"]

    def test_vip_uncertainty_survives_union_with_all(self):
        resolver = _resolver()
        resolver._vips["plain-vip"] = {
            "name": "plain-vip",
            "type": "static-nat",
            "extip": ["203.0.113.10"],
            "extintf": ["any"],
            "portforward": "disable",
        }

        result = resolver.resolve_address_list(["all", "plain-vip"])

        assert result.is_any
        assert "plain-vip:vip-priority" in result.unresolved_names


class TestScheduleResolution:

    def test_nontrivial_schedule_group_is_unresolved(self):
        resolver = _resolver()
        resolver._sched_recurring = {
            "monday": {
                "name": "monday",
                "day": ["monday"],
                "start": "08:00",
                "end": "17:00",
            },
            "tuesday": {
                "name": "tuesday",
                "day": ["tuesday"],
                "start": "08:00",
                "end": "17:00",
            },
        }
        result = resolver._resolve_schedule_group({
            "name": "weekday-parts",
            "member": ["monday", "tuesday"],
        }, 0)

        assert result.unresolved_name == "weekday-parts:schedule-group"

    def test_group_containing_always_is_exactly_always(self):
        result = _resolver()._resolve_schedule_group({
            "name": "always-group",
            "member": ["always", "other"],
        }, 0)

        assert result.is_always

    def test_cross_midnight_schedule_is_unresolved(self):
        result = _resolver()._resolve_recurring_schedule({
            "name": "overnight",
            "day": ["monday"],
            "start": "22:00",
            "end": "06:00",
        })

        assert result.unresolved_name == "overnight:cross-midnight"
