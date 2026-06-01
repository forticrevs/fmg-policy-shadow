"""
Tests for policy normalization and global header/footer policy fetching.

Uses a lightweight fake client so no live FortiManager is required.
"""

from fmg_shadow.policy_fetch import (
    _build_policy,
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
        assert p.raw_data["_raw_srcaddr"] == ["gall"]
        assert p.raw_data["_raw_schedule"] == ["galways"]

    def test_default_section_is_local(self):
        p = _build_policy({"policyid": 1, "action": "accept"}, "root", "pkg1", 0)
        assert p.policy_section == "local"


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
