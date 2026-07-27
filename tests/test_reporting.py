"""Tests for HTML reporting and conservative remediation eligibility."""

import re

from fmg_shadow.models import (
    CanonicalPolicy,
    Confidence,
    FindingType,
    InstallScope,
    InterfaceSet,
    PackageResult,
    PolicyAction,
    RunResult,
    ScheduleSpec,
    ShadowFinding,
)
from fmg_shadow.analyzer import ShadowAnalyzer
from fmg_shadow.objects import ObjectResolver
from fmg_shadow.policy_fetch import _build_policy
from fmg_shadow.reporting import (
    _collect_disable_candidates,
    _collect_manual_script_candidates,
    generate_html_report,
)


def _policy(
    policy_id,
    seq,
    name="policy",
    section="local",
    status="enable",
    scope=None,
    comments="",
    action=PolicyAction.ACCEPT,
    unresolved=False,
    raw_data=None,
    schedule=None,
):
    return CanonicalPolicy(
        fmg="fmg.example",
        adom="root",
        package="pkg",
        policyid=policy_id,
        seq_num=seq,
        name=name,
        policy_section=section,
        status=status,
        install_scope=scope or InstallScope.global_scope(),
        action=action,
        comments=comments,
        has_unresolved=unresolved,
        raw_data=raw_data or {},
        schedule=schedule or ScheduleSpec.always(),
    )


def _full_finding(
    target,
    shadowing,
    finding_type=FindingType.FULL_REDUNDANT_COVERAGE,
    confidence=Confidence.HIGH,
    composite=False,
    unreachable=True,
):
    return ShadowFinding(
        fmg="fmg.example",
        adom="root",
        package="pkg",
        shadowed_policyid=target.policyid,
        shadowed_name=target.name,
        shadowed_seq=target.seq_num,
        shadowed_section=target.policy_section,
        finding_type=finding_type,
        is_composite=composite,
        shadowing_policyids=[shadowing.policyid],
        shadowing_names=[shadowing.name],
        shadowing_seqs=[shadowing.seq_num],
        shadowing_sections=[shadowing.policy_section],
        is_fully_unreachable=unreachable,
        shadowed_action=target.action.value,
        shadowing_action=shadowing.action.value,
        same_action=True,
        confidence=confidence,
        risk_score=4.5,
    )


def _package(policies, findings, package="pkg"):
    for policy in policies:
        policy.package = package
    for finding in findings:
        finding.package = package
    return PackageResult(
        fmg="fmg.example",
        adom="root",
        package=package,
        policies=policies,
        findings=findings,
        total_policies=len(policies),
        effective_policies=len(policies),
    )


class TestRecommendedCandidates:

    def test_includes_high_confidence_pairwise_package_policy(self):
        # Global-header policies use FortiManager's reserved high ID range;
        # the shadowing ID is metadata only and must not be rejected by the
        # package target-ID validator.
        shadowing = _policy(1073741825, 0, section="global-header")
        target = _policy(20, 1, name="eligible")
        finding = _full_finding(
            target,
            shadowing,
            finding_type=FindingType.FULL_CONFLICT_SHADOW,
        )
        package = _package([shadowing, target], [finding])

        candidates = _collect_disable_candidates(package)

        assert len(candidates) == 1
        assert candidates[0]["policy"] is target
        assert candidates[0]["policy_id"] == 20
        assert candidates[0]["finding_labels"] == [
            "Fully Shadowed (Conflict)",
        ]
        assert candidates[0]["shadowing_policyids"] == ["1073741825"]

    def test_deduplicates_multiple_full_relationships(self):
        shadowing_a = _policy(10, 0)
        shadowing_b = _policy(11, 1)
        target = _policy(20, 2)
        finding_a = _full_finding(target, shadowing_a)
        finding_b = _full_finding(target, shadowing_b)
        package = _package(
            [shadowing_a, shadowing_b, target],
            [finding_a, finding_b],
        )

        candidates = _collect_disable_candidates(package)

        assert len(candidates) == 1
        assert candidates[0]["relationship_count"] == 2
        assert candidates[0]["shadowing_policyids"] == ["10", "11"]

    def test_excludes_composite_and_non_high_confidence(self):
        shadowing = _policy(10, 0)
        composite_target = _policy(20, 1)
        medium_target = _policy(21, 2)
        package = _package(
            [shadowing, composite_target, medium_target],
            [
                _full_finding(composite_target, shadowing, composite=True),
                _full_finding(
                    medium_target,
                    shadowing,
                    confidence=Confidence.MEDIUM,
                ),
            ],
        )

        assert _collect_disable_candidates(package) == []

    def test_excludes_global_disabled_partial_and_invalid_targets(self):
        shadowing = _policy(10, 0)
        global_target = _policy(20, 1, section="global-footer")
        disabled_target = _policy(21, 2, status="disable")
        partial_target = _policy(22, 3)
        invalid_target = _policy(0, 4)
        findings = [
            _full_finding(global_target, shadowing),
            _full_finding(disabled_target, shadowing),
            _full_finding(
                partial_target,
                shadowing,
                finding_type=FindingType.PARTIAL_REDUNDANT_OVERLAP,
                unreachable=False,
            ),
            _full_finding(invalid_target, shadowing),
        ]
        package = _package(
            [
                shadowing,
                global_target,
                disabled_target,
                partial_target,
                invalid_target,
            ],
            findings,
        )

        assert _collect_disable_candidates(package) == []

    def test_rechecks_install_scope_containment(self):
        fw1 = InstallScope.from_scope_members([
            {"name": "fw1", "vdom": "root"},
        ])
        fw1_fw2 = InstallScope.from_scope_members([
            {"name": "fw1", "vdom": "root"},
            {"name": "fw2", "vdom": "root"},
        ])
        shadowing = _policy(10, 0, scope=fw1)
        target = _policy(20, 1, scope=fw1_fw2)
        # Even if a stale/imported finding incorrectly claims full
        # reachability loss, report eligibility independently checks scope.
        finding = _full_finding(target, shadowing)
        package = _package([shadowing, target], [finding])

        assert _collect_disable_candidates(package) == []

    def test_excludes_ambiguous_duplicate_local_policy_ids(self):
        shadowing = _policy(10, 0)
        target_a = _policy(20, 1)
        target_b = _policy(20, 2)
        finding = _full_finding(target_a, shadowing)
        package = _package(
            [shadowing, target_a, target_b],
            [finding],
        )

        assert _collect_disable_candidates(package) == []

    def test_excludes_findings_from_disabled_shadowing_policy(self):
        shadowing = _policy(10, 0, status="disable")
        target = _policy(20, 1)
        finding = _full_finding(target, shadowing)
        package = _package([shadowing, target], [finding])

        assert _collect_disable_candidates(package) == []

    def test_requires_exact_enabled_status_and_higher_priority_order(self):
        shadowing = _policy(10, 0)
        unknown_target = _policy(20, 1, status="unknown")
        unknown_shadowing = _policy(11, 2, status="unknown")
        target = _policy(21, 3)
        reversed_shadowing = _policy(12, 5)
        reversed_target = _policy(22, 4)
        findings = [
            _full_finding(unknown_target, shadowing),
            _full_finding(target, unknown_shadowing),
            _full_finding(reversed_target, reversed_shadowing),
        ]
        package = _package(
            [
                shadowing,
                unknown_target,
                unknown_shadowing,
                target,
                reversed_target,
                reversed_shadowing,
            ],
            findings,
        )

        assert _collect_disable_candidates(package) == []

    def test_excludes_unresolved_and_ipsec_participants(self):
        shadowing = _policy(10, 0)
        unresolved_target = _policy(20, 1, unresolved=True)
        unresolved_shadowing = _policy(11, 2, unresolved=True)
        normal_target = _policy(21, 3)
        ipsec_target = _policy(22, 4, action=PolicyAction.IPSEC)
        findings = [
            _full_finding(unresolved_target, shadowing),
            _full_finding(normal_target, unresolved_shadowing),
            _full_finding(ipsec_target, shadowing),
        ]
        package = _package(
            [
                shadowing,
                unresolved_target,
                unresolved_shadowing,
                normal_target,
                ipsec_target,
            ],
            findings,
        )

        assert _collect_disable_candidates(package) == []

    def test_enforces_fortimanager_policy_id_range(self):
        shadowing = _policy(10, 0)
        max_target = _policy(1071741824, 1)
        reserved_target = _policy(1071741825, 2)
        huge_target = _policy("9" * 5000, 3)
        findings = [
            _full_finding(max_target, shadowing),
            _full_finding(reserved_target, shadowing),
            _full_finding(huge_target, shadowing),
        ]
        package = _package(
            [shadowing, max_target, reserved_target, huge_target],
            findings,
        )

        candidates = _collect_disable_candidates(package)

        assert [candidate["policy_id"] for candidate in candidates] == [
            1071741824,
        ]

    def test_excludes_malformed_empty_install_scope(self):
        malformed = InstallScope(is_global=False, targets=set())
        shadowing = _policy(10, 0)
        target = _policy(20, 1, scope=malformed)
        finding = _full_finding(target, shadowing)
        package = _package([shadowing, target], [finding])

        assert _collect_disable_candidates(package) == []

    def test_excludes_non_always_schedule_on_either_side(self):
        recurring = ScheduleSpec(
            weekdays={1},
            start_time="08:00",
            end_time="17:00",
            raw_name="business-hours",
        )
        shadowing = _policy(10, 0)
        recurring_shadowing = _policy(11, 1, schedule=recurring)
        recurring_target = _policy(20, 2, schedule=recurring)
        normal_target = _policy(21, 3)
        findings = [
            _full_finding(recurring_target, shadowing),
            _full_finding(normal_target, recurring_shadowing),
        ]
        package = _package(
            [shadowing, recurring_shadowing, recurring_target, normal_target],
            findings,
        )

        assert _collect_disable_candidates(package) == []

    def test_fetched_interfaces_prevent_false_disable_candidate(self):
        def build(policy_id, seq, srcintf):
            raw = {
                "policyid": policy_id,
                "name": "policy-{}".format(policy_id),
                "action": "accept",
                "status": "enable",
                "srcintf": [srcintf],
                "dstintf": ["wan"],
                "srcaddr": ["all"],
                "dstaddr": ["all"],
                "service": ["ALL"],
                "schedule": ["always"],
            }
            policy = _build_policy(
                raw,
                "root",
                "pkg",
                seq,
                modern_scope_semantics=True,
            )
            policy.fmg = "fmg.example"
            ObjectResolver(None, "root")._resolve_policy(policy)
            return policy

        earlier = build(10, 0, "lan-a")
        disjoint_target = build(20, 1, "lan-b")
        analyzer = ShadowAnalyzer()

        findings = analyzer.analyze_package([earlier, disjoint_target])

        assert earlier.srcintf.describe() == "lan-a"
        assert disjoint_target.srcintf.describe() == "lan-b"
        assert findings == []
        assert _collect_disable_candidates(
            _package([earlier, disjoint_target], findings)
        ) == []

    def test_legacy_install_on_none_cannot_source_disable_candidate(self):
        base = {
            "action": "accept",
            "status": "enable",
            "srcintf": ["any"],
            "dstintf": ["any"],
            "srcaddr": ["all"],
            "dstaddr": ["all"],
            "service": ["ALL"],
            "schedule": ["always"],
        }
        no_target_raw = dict(base, policyid=10, name="not-installed")
        target_raw = dict(
            base,
            policyid=20,
            name="active-target",
            **{"obj flags": "0x10"}
        )
        no_target = _build_policy(
            no_target_raw,
            "root",
            "pkg",
            0,
            modern_scope_semantics=False,
        )
        target = _build_policy(
            target_raw,
            "root",
            "pkg",
            1,
            modern_scope_semantics=False,
        )
        for policy in (no_target, target):
            policy.fmg = "fmg.example"
            ObjectResolver(None, "root")._resolve_policy(policy)

        findings = ShadowAnalyzer().analyze_package([no_target, target])

        assert no_target.is_effective() is False
        assert findings == []
        assert _collect_disable_candidates(
            _package([no_target, target], findings)
        ) == []

    def test_rechecks_modeled_dimensions_before_emission(self):
        shadowing = _policy(10, 0)
        target = _policy(20, 1)
        shadowing.srcintf = InterfaceSet.from_names(["lan-a"])
        target.srcintf = InterfaceSet.from_names(["lan-b"])
        stale_full_finding = _full_finding(target, shadowing)

        assert _collect_disable_candidates(
            _package([shadowing, target], [stale_full_finding])
        ) == []

    def test_recommendation_rejects_cross_context_policy_data(self):
        wrong_source = _policy(10, 0)
        target = _policy(20, 1)
        finding = _full_finding(target, wrong_source)
        package = _package([wrong_source, target], [finding])
        wrong_source.fmg = "different.example"

        assert _collect_disable_candidates(package) == []


class TestManualScriptCandidates:

    def test_manual_selection_includes_other_enabled_package_rules(self):
        recurring = ScheduleSpec(
            weekdays={1},
            start_time="08:00",
            end_time="17:00",
            raw_name="business-hours",
        )
        shadowing = _policy(10, 0, name="shadowing")
        recommended_target = _policy(20, 1, name="recommended")
        unresolved = _policy(21, 2, name="unresolved", unresolved=True)
        ipsec = _policy(
            22,
            3,
            name="ipsec",
            action=PolicyAction.IPSEC,
        )
        scheduled = _policy(23, 4, name="scheduled", schedule=recurring)
        composite = _policy(24, 5, name="composite")
        partial = _policy(25, 6, name="partial")
        no_finding = _policy(26, 7, name="no-finding")
        findings = [
            _full_finding(recommended_target, shadowing),
            _full_finding(composite, shadowing, composite=True),
            _full_finding(
                partial,
                shadowing,
                finding_type=FindingType.PARTIAL_REDUNDANT_OVERLAP,
                unreachable=False,
            ),
        ]
        package = _package(
            [
                shadowing,
                recommended_target,
                unresolved,
                ipsec,
                scheduled,
                composite,
                partial,
                no_finding,
            ],
            findings,
        )

        recommended = _collect_disable_candidates(package)
        manual = _collect_manual_script_candidates(package, recommended)

        assert [candidate["policy_id"] for candidate in recommended] == [20]
        assert [candidate["policy_id"] for candidate in manual] == [
            10,
            21,
            22,
            23,
            24,
            25,
            26,
        ]
        assert all(
            candidate["selection_kind"] == "manual"
            for candidate in manual
        )
        manual_by_id = {
            candidate["policy_id"]: candidate
            for candidate in manual
        }
        assert manual_by_id[24]["finding_labels"] == [
            "Fully Shadowed (Redundant)",
        ]
        assert manual_by_id[25]["finding_labels"] == [
            "Partial Redundant Overlap",
        ]
        assert manual_by_id[26]["finding_labels"] == [
            "Not recommended automatically",
        ]
        assert manual_by_id[26]["max_risk"] is None

    def test_manual_selection_keeps_cli_targeting_constraints(self):
        valid = _policy(10, 0)
        disabled = _policy(11, 1, status="disable")
        unknown = _policy(12, 2, status="unknown")
        inherited = _policy(
            1073741825,
            3,
            section="global-header",
        )
        section_title = _policy(0, 4)
        section_title.is_section_title = True
        invalid = _policy(0, 5)
        reserved = _policy(1071741825, 6)
        duplicate_a = _policy(20, 7)
        duplicate_b = _policy(20, 8)
        wrong_context = _policy(30, 9)
        package = _package(
            [
                valid,
                disabled,
                unknown,
                inherited,
                section_title,
                invalid,
                reserved,
                duplicate_a,
                duplicate_b,
                wrong_context,
            ],
            [],
        )
        wrong_context.fmg = "different.example"

        manual = _collect_manual_script_candidates(package, [])

        assert [candidate["policy_id"] for candidate in manual] == [10]

    def test_manual_metadata_ignores_cross_context_findings(self):
        shadowing = _policy(10, 0)
        target = _policy(20, 1)
        foreign_finding = _full_finding(target, shadowing)
        foreign_finding.fmg = "different.example"
        package = _package(
            [shadowing, target],
            [foreign_finding],
        )

        manual = _collect_manual_script_candidates(package, [])
        manual_by_id = {
            candidate["policy_id"]: candidate
            for candidate in manual
        }

        assert manual_by_id[20]["finding_labels"] == [
            "Not recommended automatically",
        ]
        assert manual_by_id[20]["shadowing_policyids"] == []


class TestDisableScriptHtml:

    def test_builder_is_package_scoped_and_escapes_metadata(self, tmp_path):
        shadowing = _policy(10, 0)
        target = _policy(
            20,
            1,
            name='customer <script> & "policy"',
            comments="review\nnext\nend & </textarea>",
            raw_data={"uuid": "11111111-2222-3333-4444-555555555555"},
        )
        finding = _full_finding(target, shadowing)
        package = _package([shadowing, target], [finding], package="edge/pkg")
        run = RunResult(
            run_timestamp="2026-07-27T12:00:00+00:00",
            package_results=[package],
        )
        output = tmp_path / "report.html"

        generate_html_report(run, str(output))
        html = output.read_text(encoding="utf-8")

        assert "<h2>CLI Script Builder</h2>" in html
        assert "Disable Script Builder" not in html
        assert "Safety boundary" not in html
        assert "local policies" not in html.lower()
        assert "Build a script to disable policy package rules" in html
        assert 'data-package="edge/pkg"' in html
        assert 'data-policy-id="20"' in html
        assert 'class="remediation-policy recommended-policy"' in html
        assert 'class="remediation-policy manual-policy"' in html
        assert 'data-selection="Recommended by analyzer"' in html
        assert 'data-selection="Added manually"' in html
        assert not re.search(
            r'class="remediation-policy [^"]+"[^>]*\schecked(?:\s|>)',
            html,
        )
        assert 'autocomplete="off"' in html
        assert 'data-uuid="11111111-2222-3333-4444-555555555555"' in html
        assert "customer &lt;script&gt; &amp; &quot;policy&quot;" in html
        assert "review\nnext\nend &amp; &lt;/textarea&gt;" in html
        assert "Run script on: Policy Package or ADOM Database" in html
        assert "lines.push('edit ' + policyId)" in html
        assert "lines.push('    set status disable')" in html
        assert "lines.push('next')" in html
        assert "lines.push('end')" in html
        assert "# Selection: " in html
        assert "# Analyzer result: " in html
        assert "disable-selected-policies" in html
        assert "new Blob" in html
        assert "clearRestoredSelections()" in html
        assert "querySelectorAll('.recommended-policy')" in html
        assert "Number(policyId) &gt; 1071741824" not in html
        assert "Number(policyId) > 1071741824" in html

    def test_each_package_gets_a_separate_builder(self, tmp_path):
        package_results = []
        for index, package_name in enumerate(("pkg-a", "pkg-b")):
            shadowing = _policy(10, 0)
            target = _policy(20, 1)
            package_results.append(
                _package(
                    [shadowing, target],
                    [_full_finding(target, shadowing)],
                    package=package_name,
                )
            )
        run = RunResult(
            run_timestamp="2026-07-27T12:00:00+00:00",
            package_results=package_results,
        )
        output = tmp_path / "report.html"

        generate_html_report(run, str(output))
        html = output.read_text(encoding="utf-8")

        assert html.count('class="card cli-builder"') == 2
        assert 'data-package="pkg-a"' in html
        assert 'data-package="pkg-b"' in html
        assert "separate script for each" in html

    def test_no_recommendations_still_allows_manual_selection(self, tmp_path):
        shadowing = _policy(10, 0)
        target = _policy(20, 1)
        finding = _full_finding(target, shadowing, composite=True)
        run = RunResult(
            run_timestamp="2026-07-27T12:00:00+00:00",
            package_results=[_package([shadowing, target], [finding])],
        )
        output = tmp_path / "report.html"

        generate_html_report(run, str(output))
        html = output.read_text(encoding="utf-8")

        assert 'class="card cli-builder"' in html
        assert "No rules were recommended" in html
        assert "Manual selection: choose from 2 other enabled rules" in html
        assert 'class="remediation-policy manual-policy"' in html
        assert 'class="remediation-policy recommended-policy"' not in html
        assert "Not recommended automatically" in html
        assert ">—</td>" in html
        assert (
            '<input type="checkbox" id="remediationSelectAll"'
            not in html
        )

    def test_bulk_controls_only_select_recommended_rules(self, tmp_path):
        shadowing = _policy(10, 0)
        target = _policy(20, 1)
        run = RunResult(
            run_timestamp="2026-07-27T12:00:00+00:00",
            package_results=[
                _package(
                    [shadowing, target],
                    [_full_finding(target, shadowing)],
                ),
            ],
        )
        output = tmp_path / "report.html"

        generate_html_report(run, str(output))
        html = output.read_text(encoding="utf-8")
        package_handler = html.split(
            "packageToggle.addEventListener('change'",
            1,
        )[1].split("previewButton.addEventListener", 1)[0]
        global_handler = html.split(
            "globalSelect.addEventListener('change'",
            1,
        )[1].split("if (clearAll)", 1)[0]
        clear_handler = html.split(
            "clearAll.addEventListener('click'",
            1,
        )[1].split("window.addEventListener('pageshow'", 1)[0]

        assert "querySelectorAll('.recommended-policy')" in package_handler
        assert "querySelectorAll('.remediation-policy')" not in package_handler
        assert "querySelectorAll('.recommended-policy')" in global_handler
        assert "querySelectorAll('.remediation-policy')" not in global_handler
        assert "querySelectorAll('.remediation-policy')" in clear_handler

    def test_no_command_eligible_rules_renders_no_package_card(self, tmp_path):
        disabled = _policy(10, 0, status="disable")
        inherited = _policy(
            1073741825,
            1,
            section="global-header",
        )
        invalid = _policy(0, 2)
        run = RunResult(
            run_timestamp="2026-07-27T12:00:00+00:00",
            package_results=[
                _package([disabled, inherited, invalid], []),
            ],
        )
        output = tmp_path / "report.html"

        generate_html_report(run, str(output))
        html = output.read_text(encoding="utf-8")

        assert "<h2>CLI Script Builder</h2>" in html
        assert 'class="card cli-builder"' not in html
        assert "No rules are available for this" in html

    def test_finding_detail_dom_ids_are_unique_across_packages(self, tmp_path):
        package_results = []
        for package_name in ("pkg-a", "pkg-b"):
            shadowing = _policy(10, 0)
            target = _policy(20, 1)
            package_results.append(
                _package(
                    [shadowing, target],
                    [_full_finding(target, shadowing)],
                    package=package_name,
                )
            )
        run = RunResult(
            run_timestamp="2026-07-27T12:00:00+00:00",
            package_results=package_results,
        )
        output = tmp_path / "report.html"

        generate_html_report(run, str(output))
        html = output.read_text(encoding="utf-8")
        detail_ids = re.findall(r'id="(detail-[^"]+)"', html)

        assert len(detail_ids) == 2
        assert len(detail_ids) == len(set(detail_ids))
