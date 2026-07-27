"""Tests for FortiManager version detection used by scope normalization."""

from fmg_shadow.orchestrator import _detect_fmg_version


class _StatusClient:
    host = "fmg.example"

    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url):
        self.calls.append(url)
        return self.response


def test_detect_fmg_version_from_numeric_fields():
    client = _StatusClient({
        "Major": 7,
        "Minor": "4",
        "Patch": 3,
        "Version": "v7.4.3-build2573",
    })

    assert _detect_fmg_version(client) == (7, 4, 3)
    assert client.calls == ["/sys/status"]


def test_detect_fmg_version_falls_back_to_version_text():
    client = _StatusClient({
        "Version": "v6.4.15-build2488 240410 (GA)",
    })

    assert _detect_fmg_version(client) == (6, 4, 15)


def test_detect_fmg_version_fails_closed_on_unknown_response():
    client = _StatusClient({"Version": "not reported"})

    assert _detect_fmg_version(client) is None
