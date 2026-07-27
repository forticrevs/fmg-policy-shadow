"""
Tests for policy normalization and global header/footer policy fetching.

Uses a lightweight fake client so no live FortiManager is required.
"""

from fmg_shadow.policy_fetch import (
    _build_policy,
    _scope_response_uses_explicit_empty,
    fetch_global_policies,
)
from fmg_shadow.models import PolicyAction


class _FakeClient:
    """Minimal stand-in for FMGClient.get()."""

    def __init__(self, responses):
        # responses: dict mapping url -> return value (or Exception to raise)
        self.responses = responses
        self.calls = []

    def get(self, url, option=None, **kwargs):
        self.calls.append((url, option))
        val = self.responses.get(url)
        if isinstance(val, Exception):
            raise val
        return val


# ---------------------------------------------------------------------------
# _build_policy
# ---------------------------------------------------------------------------

class TestBuildPolicy:
    def test_section_and_raw_fields(self):
        raw = {
            "policyid": 7,
            "name": "rule7",
            "action": "deny",
            "status": "enable",
            "srcintf": ["port1"],
            "dstintf": ["port2"],
            "srcaddr": ["gall"],
            "dstaddr": ["host1"],
            "service": ["HTTPS"],
            "schedule": ["galways"],
        }
        p = _build_policy(raw, "root", "pkg1", 3, section="global-header")
        assert p.policy_section == "global-header"
        assert p.policyid == 7
        assert p.seq_num == 3
        assert p.action == PolicyAction.DENY
        assert p.srcintf.describe() == "port1"
        assert p.dstintf.describe() == "port2"
        assert p.raw_data["_raw_srcaddr"] == ["gall"]
        assert p.raw_data["_raw_schedule"] == ["galways"]

    def test_default_section_is_local(self):
        p = _build_policy({"policyid": 1, "action": "accept"}, "root", "pkg1", 0)
        assert p.policy_section == "local"

    def test_modern_absent_scope_is_default_but_explicit_empty_has_no_targets(self):
        base = {
            "policyid": 1,
            "action": "accept",
            "status": "enable",
            "srcintf": ["any"],
            "dstintf": ["any"],
            "srcaddr": ["all"],
            "dstaddr": ["all"],
            "service": ["ALL"],
            "schedule": ["always"],
        }
        inherited = _build_policy(
            dict(base),
            "root",
            "pkg1",
            0,
            modern_scope_semantics=True,
        )
        explicit_none_raw = dict(base)
        explicit_none_raw["scope member"] = []
        explicit_none = _build_policy(
            explicit_none_raw,
            "root",
            "pkg1",
            1,
        )

        assert inherited.install_scope.is_global
        assert not explicit_none.install_scope.is_global
        assert explicit_none.install_scope.targets == set()
        assert explicit_none.is_effective() is False

    def test_legacy_absent_scope_requires_obj_flags_scope_bit(self):
        base = {
            "policyid": 1,
            "action": "accept",
            "status": "enable",
            "srcintf": ["any"],
            "dstintf": ["any"],
            "srcaddr": ["all"],
            "dstaddr": ["all"],
            "service": ["ALL"],
            "schedule": ["always"],
        }
        for flags in (16, "16", "0x10"):
            default_raw = dict(base)
            default_raw["obj flags"] = flags
            default_scope = _build_policy(
                default_raw,
                "root",
                "pkg1",
                0,
                modern_scope_semantics=False,
            )
            assert default_scope.install_scope.is_global

        install_on_none = _build_policy(
            dict(base),
            "root",
            "pkg1",
            1,
            modern_scope_semantics=False,
        )
        assert not install_on_none.install_scope.is_global
        assert install_on_none.install_scope.targets == set()
        assert install_on_none.is_effective() is False

    def test_unknown_absent_scope_fails_closed(self):
        policy = _build_policy(
            {
                "policyid": 1,
                "action": "accept",
                "status": "enable",
                "srcintf": ["any"],
                "dstintf": ["any"],
                "srcaddr": ["all"],
                "dstaddr": ["all"],
                "service": ["ALL"],
                "schedule": ["always"],
            },
            "root",
            "pkg1",
            0,
        )

        assert policy.is_effective() is False
        assert any(
            "ambiguous per-policy install scope" in note
            for note in policy.unresolved_notes
        )

    def test_scope_response_version_thresholds(self):
        assert _scope_response_uses_explicit_empty((6, 4, 15)) is False
        assert _scope_response_uses_explicit_empty((7, 0, 10)) is False
        assert _scope_response_uses_explicit_empty((7, 0, 11)) is True
        assert _scope_response_uses_explicit_empty((7, 2, 4)) is False
        assert _scope_response_uses_explicit_empty((7, 2, 5)) is True
        assert _scope_response_uses_explicit_empty((7, 4, 2)) is False
        assert _scope_response_uses_explicit_empty((7, 4, 3)) is True
        assert _scope_response_uses_explicit_empty((7, 6, 0)) is True
        assert _scope_response_uses_explicit_empty((8, 0, 0)) is True
        assert _scope_response_uses_explicit_empty(None) is None
        assert _scope_response_uses_explicit_empty((7, 3, 1)) is None

    def test_marks_identity_and_ngfw_selectors_unresolved(self):
        configured_fields = {
            "groups": ["customer-users"],
            "users": [{"name": "alice"}],
            "fsso-groups": ["corp-fsso"],
            "devices": ["legacy-device"],
            "fsso": "enable",
            "rsso": "enable",
            "wsso": "enable",
            "sgt-check": "enable",
            "ztna-ems-tag": ["compliant"],
            "ztna-destination": ["private-app"],
            "app-category": [5],
            "app-group": ["business-apps"],
            "url-category": [42],
            "network-service-dynamic": ["cloud-service"],
            "rtp-nat": "enable",
            "rtp-addr": ["198.51.100.10"],
            "nat46": "enable",
            "nat64": "enable",
        }

        for field, value in configured_fields.items():
            policy = _build_policy(
                {"policyid": 1, "action": "accept", field: value},
                "root",
                "pkg1",
                0,
            )
            assert policy.has_unresolved, field
            assert any(
                note.startswith("unsupported match criterion:")
                for note in policy.unresolved_notes
            ), field

    def test_default_match_values_do_not_mark_policy_unresolved(self):
        raw = {
            "policyid": 1,
            "action": "accept",
            "status": "enable",
            "srcintf": ["any"],
            "dstintf": ["any"],
            "srcaddr": ["all"],
            "dstaddr": ["all"],
            "service": ["ALL"],
            "schedule": ["always"],
            "tos": "0x00",
            "tos-mask": "0x00",
            "tos-negate": "disable",
            "sgt-check": "disable",
            "ztna-device-ownership": "disable",
            "ztna-status": "disable",
            "match-vip": "disable",
            "match-vip-only": "disable",
            "policy-expiry": "disable",
            "policy-expiry-date": "0000-00-00 00:00:00",
            "internet-service": "disable",
            "internet-service-src": 0,
            "internet-service6": "disable",
        }

        policy = _build_policy(
            raw,
            "root",
            "pkg1",
            0,
            modern_scope_semantics=True,
        )

        assert policy.has_unresolved is False
        assert policy.unresolved_notes == []

    def test_missing_core_fields_are_unresolved(self):
        policy = _build_policy(
            {"policyid": 1},
            "root",
            "pkg1",
            0,
        )

        assert policy.action == PolicyAction.UNKNOWN
        assert policy.status == "unknown"
        assert policy.has_unresolved
        assert any(
            note.startswith("missing core match field:")
            for note in policy.unresolved_notes
        )

    def test_marks_isdb_variants_and_nondefault_vip_matching_unresolved(self):
        isdb_policy = _build_policy(
            {
                "policyid": 1,
                "action": "accept",
                "internet-service6-custom-group": ["custom-isdb"],
            },
            "root",
            "pkg1",
            0,
        )
        vip_policy = _build_policy(
            {
                "policyid": 2,
                "action": "deny",
                "match-vip": "disable",
            },
            "root",
            "pkg1",
            1,
        )

        assert isdb_policy.has_unresolved
        assert vip_policy.has_unresolved

    def test_deny_match_vip_is_unresolved_for_either_value(self):
        for value in ("enable", "disable"):
            policy = _build_policy(
                {
                    "policyid": 1,
                    "action": "deny",
                    "match-vip": value,
                },
                "root",
                "pkg1",
                0,
            )

            assert any(
                "VIP matching priority" in note
                for note in policy.unresolved_notes
            )

    def test_enabled_match_vip_on_accept_is_unresolved(self):
        policy = _build_policy(
            {
                "policyid": 1,
                "action": "accept",
                "match-vip": "enable",
            },
            "root",
            "pkg1",
            0,
        )

        assert any(
            "VIP matching priority" in note
            for note in policy.unresolved_notes
        )

    def test_embedded_dynamic_mapping_is_unresolved(self):
        policy = _build_policy(
            {
                "policyid": 1,
                "action": "accept",
                "status": "enable",
                "srcintf": [{
                    "name": "normalized-lan",
                    "dynamic_mapping": [{"scope": "fw1", "name": "port2"}],
                }],
                "dstintf": ["any"],
                "srcaddr": ["all"],
                "dstaddr": ["all"],
                "service": ["ALL"],
                "schedule": ["always"],
            },
            "root",
            "pkg1",
            0,
        )

        assert policy.has_unresolved
        assert any(
            "dynamic mapping" in note
            for note in policy.unresolved_notes
        )

    def test_unknown_status_and_ipsec_action_are_unresolved(self):
        unknown = _build_policy(
            {"policyid": 1, "action": "accept", "status": "unexpected"},
            "root",
            "pkg1",
            0,
        )
        ipsec = _build_policy(
            {"policyid": 2, "action": "ipsec", "status": "enable"},
            "root",
            "pkg1",
            1,
        )

        assert unknown.status == "unknown"
        assert unknown.has_unresolved
        assert "unsupported policy status" in unknown.unresolved_notes
        assert ipsec.action == PolicyAction.IPSEC
        assert ipsec.has_unresolved
        assert any("policy-based IPsec" in note for note in ipsec.unresolved_notes)


# ---------------------------------------------------------------------------
# fetch_global_policies
# ---------------------------------------------------------------------------

class TestFetchGlobalPolicies:
    def test_header_url_and_section(self):
        url = "/pm/config/adom/root/pkg/pkgA/global/header/policy"
        client = _FakeClient({
            url: [
                {"policyid": 11, "name": "gh1", "action": "accept", "status": "enable"},
                {"policyid": 12, "name": "gh2", "action": "deny", "status": "enable"},
            ]
        })
        pols = fetch_global_policies(client, "root", "pkgA", "global-header")
        assert [p.policyid for p in pols] == [11, 12]
        assert all(p.policy_section == "global-header" for p in pols)
        # seq numbers are local to the fetch (renumbering happens in orchestrator)
        assert [p.seq_num for p in pols] == [0, 1]
        assert client.calls == [(url, ["scope member"])]

    def test_footer_url(self):
        url = "/pm/config/adom/root/pkg/pkgA/global/footer/policy"
        client = _FakeClient({url: [{"policyid": 99, "action": "accept"}]})
        pols = fetch_global_policies(client, "root", "pkgA", "global-footer")
        assert len(pols) == 1
        assert pols[0].policy_section == "global-footer"
        assert client.calls[0][0] == url

    def test_empty_when_no_global_policies(self):
        url = "/pm/config/adom/root/pkg/pkgA/global/header/policy"
        client = _FakeClient({url: []})
        assert fetch_global_policies(client, "root", "pkgA", "global-header") == []

    def test_errors_are_swallowed(self):
        url = "/pm/config/adom/root/pkg/pkgA/global/header/policy"
        client = _FakeClient({url: RuntimeError("no global db assigned")})
        # Must not raise — global policies are supplemental.
        assert fetch_global_policies(client, "root", "pkgA", "global-header") == []
