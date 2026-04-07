"""
Core shadow analysis engine.

Compares firewall policies in evaluation order to detect shadowed,
redundant, and conflicting rules using interval-based set operations
across all match dimensions.
"""

from __future__ import annotations

import logging
from typing import Optional

from .models import (
    AddressSet,
    CanonicalPolicy,
    Confidence,
    FindingType,
    PolicyAction,
    ShadowFinding,
)
logger = logging.getLogger(__name__)

# Severity ordering for sort (lower index = higher severity)
_SEVERITY_ORDER = {
    FindingType.FULL_CONFLICT_SHADOW: 0,
    FindingType.PARTIAL_CONFLICT_SHADOW: 1,
    FindingType.FULL_REDUNDANT_COVERAGE: 2,
    FindingType.PARTIAL_REDUNDANT_OVERLAP: 3,
    FindingType.INDETERMINATE: 4,
}


class ShadowAnalyzer:
    """Pairwise and composite shadow detection across a policy package."""

    def __init__(self, max_composite_candidates: int = 50):
        self.max_composite_candidates = max_composite_candidates

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze_package(
        self,
        policies: list[CanonicalPolicy],
        include_disabled: bool = False,
    ) -> list[ShadowFinding]:
        """Analyze a list of policies (in evaluation order) for shadow relationships.

        Returns findings sorted by severity (critical first).
        Policies with unresolved objects are included with reduced confidence —
        resolved dimensions are analyzed normally, unresolved dimensions are
        marked indeterminate.
        """
        effective = [p for p in policies if p.is_effective(include_disabled)]

        for p in effective:
            if p.has_unresolved:
                logger.info(
                    "Policy id=%d name=%r (seq %d, pkg=%s) has unresolved objects "
                    "(will analyze with reduced confidence): %s",
                    p.policyid,
                    p.name,
                    p.seq_num,
                    p.package,
                    "; ".join(p.unresolved_notes) if p.unresolved_notes else "unknown",
                )

        if len(effective) < 2:
            return []

        findings: list[ShadowFinding] = []
        # Track which later rules already have a full pairwise shadow so we
        # can skip the more expensive composite check for them.
        fully_shadowed: set[int] = set()

        for j in range(1, len(effective)):
            later = effective[j]
            pairwise_found_full = False

            # --- pairwise checks against all earlier rules ---
            for i in range(j):
                earlier = effective[i]
                # Only compare rules with overlapping install scope
                if not earlier.install_scope.overlaps(later.install_scope):
                    continue
                finding = self._pairwise_check(earlier, later)
                if finding is not None:
                    findings.append(finding)
                    if finding.finding_type in (
                        FindingType.FULL_CONFLICT_SHADOW,
                        FindingType.FULL_REDUNDANT_COVERAGE,
                    ):
                        pairwise_found_full = True
                        fully_shadowed.add(j)

            # --- composite shadow check ---
            if not pairwise_found_full and j not in fully_shadowed:
                earlier_candidates = [
                    effective[i]
                    for i in range(j)
                    if effective[i].install_scope.overlaps(later.install_scope)
                ]
                comp = self._composite_shadow_check(earlier_candidates, later)
                if comp is not None:
                    findings.append(comp)

        # Sort by severity (most critical first), then risk score (highest
        # first), then by shadowed seq
        findings.sort(
            key=lambda f: (
                _SEVERITY_ORDER.get(f.finding_type, 99),
                -f.risk_score,
                f.shadowed_seq,
            )
        )
        return findings

    # ------------------------------------------------------------------
    # Pairwise shadow check
    # ------------------------------------------------------------------

    def _pairwise_check(
        self,
        earlier: CanonicalPolicy,
        later: CanonicalPolicy,
    ) -> Optional[ShadowFinding]:
        """Check if *earlier* shadows or overlaps *later* on all 6 dimensions."""

        # Negation flags invert what the address/service set means.
        # When negation is present, reliable overlap/containment analysis
        # requires computing the complement against the full address space,
        # which is impractical.  We treat negated dimensions conservatively.
        has_negation = (
            earlier.srcaddr_negate or later.srcaddr_negate
            or earlier.dstaddr_negate or later.dstaddr_negate
            or earlier.service_negate or later.service_negate
        )

        # Quick reject: if any dimension has zero overlap, no relationship
        # (Skip quick-reject for negated dimensions — overlap is uncertain)
        if not earlier.srcintf.overlaps(later.srcintf):
            return None
        if not earlier.dstintf.overlaps(later.dstintf):
            return None
        if not (earlier.srcaddr_negate or later.srcaddr_negate):
            if not earlier.srcaddr.overlaps(later.srcaddr):
                return None
        if not (earlier.dstaddr_negate or later.dstaddr_negate):
            if not earlier.dstaddr.overlaps(later.dstaddr):
                return None
        if not (earlier.service_negate or later.service_negate):
            if not earlier.service.overlaps(later.service):
                return None
        if not earlier.schedule.overlaps(later.schedule):
            return None

        # Per-dimension containment
        contains = self._dimension_contains(earlier, later)

        # If any negation is present, we cannot prove full containment —
        # force the finding to indeterminate / partial at best.
        if has_negation:
            full_shadow = False
        else:
            full_shadow = all(contains.values())

        # Determine same/different action
        same_action = earlier.action == later.action

        # Classify
        if full_shadow:
            if same_action:
                ftype = FindingType.FULL_REDUNDANT_COVERAGE
            else:
                ftype = FindingType.FULL_CONFLICT_SHADOW
        else:
            if same_action:
                ftype = FindingType.PARTIAL_REDUNDANT_OVERLAP
            else:
                ftype = FindingType.PARTIAL_CONFLICT_SHADOW

        # Confidence
        has_unresolved = earlier.has_unresolved or later.has_unresolved
        if has_unresolved:
            if full_shadow:
                # Can't be sure of full shadow with unresolved objects
                ftype = FindingType.INDETERMINATE
                confidence = Confidence.LOW
            else:
                confidence = Confidence.LOW
        else:
            confidence = Confidence.HIGH if full_shadow else Confidence.MEDIUM

        # Build overlap descriptions
        overlap_desc = self._describe_overlap(earlier, later)

        finding = ShadowFinding(
            fmg=later.fmg,
            adom=later.adom,
            package=later.package,
            shadowed_policyid=later.policyid,
            shadowed_name=later.name,
            shadowed_seq=later.seq_num,
            finding_type=ftype,
            is_composite=False,
            shadowing_policyids=[earlier.policyid],
            shadowing_names=[earlier.name],
            shadowing_seqs=[earlier.seq_num],
            srcintf_overlap=overlap_desc["srcintf"],
            dstintf_overlap=overlap_desc["dstintf"],
            srcaddr_overlap=overlap_desc["srcaddr"],
            dstaddr_overlap=overlap_desc["dstaddr"],
            service_overlap=overlap_desc["service"],
            schedule_overlap=overlap_desc["schedule"],
            is_fully_unreachable=full_shadow and not has_unresolved,
            shadowed_action=later.action.value,
            shadowing_action=earlier.action.value,
            same_action=same_action,
            confidence=confidence,
            unsupported_notes=(
                earlier.unresolved_notes + later.unresolved_notes
                if has_unresolved
                else []
            ),
        )
        finding.explanation = self._generate_explanation(finding, earlier, later)
        self._compute_risk_score(finding, [earlier], later)
        return finding

    # ------------------------------------------------------------------
    # Composite (union) shadow check
    # ------------------------------------------------------------------

    def _composite_shadow_check(
        self,
        earlier_policies: list[CanonicalPolicy],
        later: CanonicalPolicy,
    ) -> Optional[ShadowFinding]:
        """Check if the *union* of earlier rules fully covers later."""
        if not earlier_policies:
            return None

        # Skip if later has negation — can't prove full coverage with complements
        if later.srcaddr_negate or later.dstaddr_negate or later.service_negate:
            return None

        # Prune: only keep earlier rules that overlap later on at least
        # interfaces and at least one address dimension
        candidates = []
        for ep in earlier_policies:
            if ep.has_unresolved:
                continue
            if not ep.srcintf.overlaps(later.srcintf):
                continue
            if not ep.dstintf.overlaps(later.dstintf):
                continue
            # Must overlap on at least address or service
            addr_overlap = (
                ep.srcaddr.overlaps(later.srcaddr)
                and ep.dstaddr.overlaps(later.dstaddr)
            )
            svc_overlap = ep.service.overlaps(later.service)
            sched_overlap = ep.schedule.overlaps(later.schedule)
            if addr_overlap and svc_overlap and sched_overlap:
                candidates.append(ep)

        if len(candidates) < 2:
            return None  # need at least 2 rules for composite

        # Limit candidates to avoid combinatorial explosion
        if len(candidates) > self.max_composite_candidates:
            candidates = candidates[: self.max_composite_candidates]

        # --- Check each dimension for full coverage by the union ---

        # 1) srcintf: later's srcintf must be contained by the union
        #    of earlier srcintf intersections
        srcintf_covered = self._check_interface_union_coverage(
            [c.srcintf for c in candidates], later.srcintf
        )
        if not srcintf_covered:
            return None

        # 2) dstintf
        dstintf_covered = self._check_interface_union_coverage(
            [c.dstintf for c in candidates], later.dstintf
        )
        if not dstintf_covered:
            return None

        # 3) srcaddr: subtract each earlier's intersection from remaining
        src_remaining = later.srcaddr
        for c in candidates:
            inter = c.srcaddr.intersection(later.srcaddr)
            src_remaining = src_remaining.subtract(inter)
            if src_remaining.is_empty():
                break
        if not src_remaining.is_empty():
            return None

        # 4) dstaddr
        dst_remaining = later.dstaddr
        for c in candidates:
            inter = c.dstaddr.intersection(later.dstaddr)
            dst_remaining = dst_remaining.subtract(inter)
            if dst_remaining.is_empty():
                break
        if not dst_remaining.is_empty():
            return None

        # 5) service: check if union of earlier services covers later's services
        svc_covered = self._check_service_union_coverage(
            [c.service for c in candidates], later.service
        )
        if not svc_covered:
            return None

        # 6) schedule: check if union of earlier schedules covers later
        sched_covered = self._check_schedule_union_coverage(
            [c.schedule for c in candidates], later.schedule
        )
        if not sched_covered:
            return None

        # Full composite shadow detected!
        # Determine action agreement
        actions = {c.action for c in candidates}
        if len(actions) == 1:
            composite_action = next(iter(actions)).value
            same_action = (next(iter(actions)) == later.action)
        else:
            composite_action = ", ".join(sorted(a.value for a in actions))
            same_action = False

        # Check if any participant has unresolved objects
        has_unresolved = later.has_unresolved or any(c.has_unresolved for c in candidates)

        if same_action:
            ftype = FindingType.FULL_REDUNDANT_COVERAGE
        else:
            ftype = FindingType.FULL_CONFLICT_SHADOW

        # Downgrade confidence when unresolved objects are involved
        if has_unresolved:
            confidence = Confidence.LOW
        else:
            confidence = Confidence.MEDIUM

        unsupported_notes = []
        if has_unresolved:
            for p in [later] + candidates:
                unsupported_notes.extend(p.unresolved_notes)

        finding = ShadowFinding(
            fmg=later.fmg,
            adom=later.adom,
            package=later.package,
            shadowed_policyid=later.policyid,
            shadowed_name=later.name,
            shadowed_seq=later.seq_num,
            finding_type=ftype,
            is_composite=True,
            shadowing_policyids=[c.policyid for c in candidates],
            shadowing_names=[c.name for c in candidates],
            shadowing_seqs=[c.seq_num for c in candidates],
            srcintf_overlap="composite union fully contains shadowed srcintf",
            dstintf_overlap="composite union fully contains shadowed dstintf",
            srcaddr_overlap="composite union fully contains shadowed srcaddr="
            + later.srcaddr.describe(),
            dstaddr_overlap="composite union fully contains shadowed dstaddr="
            + later.dstaddr.describe(),
            service_overlap="composite union fully contains shadowed services="
            + later.service.describe(),
            schedule_overlap="composite union fully contains shadowed schedule="
            + later.schedule.describe(),
            is_fully_unreachable=not has_unresolved,
            shadowed_action=later.action.value,
            shadowing_action=composite_action,
            same_action=same_action,
            confidence=confidence,
            unsupported_notes=unsupported_notes,
        )
        finding.explanation = self._generate_composite_explanation(
            finding, candidates, later
        )
        self._compute_risk_score(finding, candidates, later)
        return finding

    # ------------------------------------------------------------------
    # Risk score computation
    # ------------------------------------------------------------------

    def _compute_risk_score(
        self,
        finding: ShadowFinding,
        earlier_policies: list[CanonicalPolicy],
        later: CanonicalPolicy,
    ) -> None:
        """Compute a weighted risk score (0-10) for a shadow finding."""
        score = 0.0
        factors: list[str] = []

        # 1. Base score from finding type
        base_scores = {
            FindingType.FULL_CONFLICT_SHADOW: 8.0,
            FindingType.PARTIAL_CONFLICT_SHADOW: 6.0,
            FindingType.FULL_REDUNDANT_COVERAGE: 3.0,
            FindingType.PARTIAL_REDUNDANT_OVERLAP: 1.5,
            FindingType.INDETERMINATE: 2.0,
        }
        score = base_scores.get(finding.finding_type, 0)
        factors.append(f"base:{score:.1f} ({finding.finding_type.value})")

        # 2. Action conflict multiplier
        if not finding.same_action:
            score *= 1.3
            factors.append("action_conflict:x1.3")

        # 3. Address breadth factor (most impactful)
        breadth_weights = {
            "any": 2.0,
            "massive": 1.8,
            "large": 1.5,
            "medium": 1.2,
            "small": 1.0,
            "host": 0.8,
            "empty": 0.5,
        }
        # Use the BROADER of src/dst address breadth
        src_breadth = later.srcaddr.breadth_category()
        dst_breadth = later.dstaddr.breadth_category()
        breadth_order = ["empty", "host", "small", "medium", "large", "massive", "any"]
        src_idx = breadth_order.index(src_breadth) if src_breadth in breadth_order else 0
        dst_idx = breadth_order.index(dst_breadth) if dst_breadth in breadth_order else 0
        wider = src_breadth if src_idx > dst_idx else dst_breadth
        breadth_mult = breadth_weights.get(wider, 1.0)
        score *= breadth_mult
        factors.append(f"address_breadth:{wider}:x{breadth_mult}")

        # 4. Dimension overlap weighting
        # Interface overlap is expected/common - don't add much
        # Address overlap is critical
        # Service+schedule overlap on top of address is most critical
        addr_overlap = (
            "covers" in finding.srcaddr_overlap
            or "covers" in finding.dstaddr_overlap
        )
        svc_overlap = "covers" in finding.service_overlap
        sched_overlap = "covers" in finding.schedule_overlap

        if addr_overlap and svc_overlap and sched_overlap:
            score += 2.0
            factors.append("full_dimension_coverage:+2.0")
        elif addr_overlap and svc_overlap:
            score += 1.5
            factors.append("addr+svc_coverage:+1.5")
        elif addr_overlap:
            score += 1.0
            factors.append("addr_coverage:+1.0")
        # Interface-only overlap does NOT add score (it's expected)

        # 5. Fully unreachable bonus
        if finding.is_fully_unreachable:
            score += 1.0
            factors.append("fully_unreachable:+1.0")

        # 6. Composite finding (harder to detect, may be less obvious)
        if finding.is_composite:
            score += 0.5
            factors.append("composite:+0.5")

        # Cap at 10.0
        score = min(score, 10.0)

        finding.risk_score = round(score, 1)
        finding.risk_factors = factors

    # ------------------------------------------------------------------
    # Dimension containment check
    # ------------------------------------------------------------------

    def _dimension_contains(
        self,
        earlier: CanonicalPolicy,
        later: CanonicalPolicy,
    ) -> dict[str, bool]:
        """Per-dimension: does earlier fully contain later?"""
        return {
            "srcintf": earlier.srcintf.contains(later.srcintf),
            "dstintf": earlier.dstintf.contains(later.dstintf),
            "srcaddr": earlier.srcaddr.contains(later.srcaddr),
            "dstaddr": earlier.dstaddr.contains(later.dstaddr),
            "service": earlier.service.contains(later.service),
            "schedule": earlier.schedule.contains(later.schedule),
        }

    # ------------------------------------------------------------------
    # Overlap description
    # ------------------------------------------------------------------

    @staticmethod
    def _raw_names(policy: CanonicalPolicy, field: str) -> str:
        """Get the raw FMG object names for a policy field."""
        raw = policy.raw_data.get(f"_raw_{field}", [])
        if not raw:
            return ""
        return ", ".join(str(n) for n in raw)

    def _describe_overlap(
        self,
        earlier: CanonicalPolicy,
        later: CanonicalPolicy,
    ) -> dict[str, str]:
        """Human-readable per-dimension overlap descriptions.

        Includes both raw FMG object names and resolved IP/port values
        so operators can verify the resolution.
        """
        desc: dict[str, str] = {}

        # Helper: format "objects=[names] resolved=[ranges]" when names differ from resolved
        def _addr_label(policy: CanonicalPolicy, field: str, addr_set) -> str:
            raw = self._raw_names(policy, field)
            resolved = addr_set.describe()
            if raw and raw.lower() not in ("all", resolved.lower()):
                return f"[{raw}] ({resolved})"
            return resolved

        def _svc_label(policy: CanonicalPolicy) -> str:
            raw = self._raw_names(policy, "service")
            resolved = policy.service.describe()
            if raw and raw.upper() not in ("ALL", resolved.upper()):
                return f"[{raw}] ({resolved})"
            return resolved

        def _sched_label(policy: CanonicalPolicy) -> str:
            raw = self._raw_names(policy, "schedule")
            resolved = policy.schedule.describe()
            if raw and raw.lower() not in ("always", resolved.lower()):
                return f"[{raw}] ({resolved})"
            return resolved

        # srcintf
        if earlier.srcintf.contains(later.srcintf):
            desc["srcintf"] = (
                f"shadowing srcintf={earlier.srcintf.describe()} "
                f"fully contains shadowed srcintf={later.srcintf.describe()}"
            )
        elif earlier.srcintf.overlaps(later.srcintf):
            common = earlier.srcintf.intersection(later.srcintf)
            desc["srcintf"] = (
                f"partial srcintf overlap on {common.describe()}"
            )
        else:
            desc["srcintf"] = "no srcintf overlap"

        # dstintf
        if earlier.dstintf.contains(later.dstintf):
            desc["dstintf"] = (
                f"shadowing dstintf={earlier.dstintf.describe()} "
                f"fully contains shadowed dstintf={later.dstintf.describe()}"
            )
        elif earlier.dstintf.overlaps(later.dstintf):
            common = earlier.dstintf.intersection(later.dstintf)
            desc["dstintf"] = (
                f"partial dstintf overlap on {common.describe()}"
            )
        else:
            desc["dstintf"] = "no dstintf overlap"

        # srcaddr — include raw object names + negation
        e_src = _addr_label(earlier, "srcaddr", earlier.srcaddr)
        l_src = _addr_label(later, "srcaddr", later.srcaddr)
        if earlier.srcaddr_negate:
            e_src = f"NOT({e_src})"
        if later.srcaddr_negate:
            l_src = f"NOT({l_src})"
        if earlier.srcaddr_negate or later.srcaddr_negate:
            desc["srcaddr"] = (
                f"NEGATED srcaddr — shadowing={e_src}, shadowed={l_src} "
                f"(indeterminate due to negation)"
            )
        elif earlier.srcaddr.contains(later.srcaddr):
            desc["srcaddr"] = (
                f"shadowing srcaddr={e_src} "
                f"fully contains shadowed srcaddr={l_src}"
            )
        elif earlier.srcaddr.overlaps(later.srcaddr):
            inter = earlier.srcaddr.intersection(later.srcaddr)
            desc["srcaddr"] = (
                f"partial srcaddr overlap: {inter.describe()} "
                f"(shadowing={e_src}, shadowed={l_src})"
            )
        else:
            desc["srcaddr"] = "no srcaddr overlap"

        # dstaddr — include raw object names + negation
        e_dst = _addr_label(earlier, "dstaddr", earlier.dstaddr)
        l_dst = _addr_label(later, "dstaddr", later.dstaddr)
        if earlier.dstaddr_negate:
            e_dst = f"NOT({e_dst})"
        if later.dstaddr_negate:
            l_dst = f"NOT({l_dst})"
        if earlier.dstaddr_negate or later.dstaddr_negate:
            desc["dstaddr"] = (
                f"NEGATED dstaddr — shadowing={e_dst}, shadowed={l_dst} "
                f"(indeterminate due to negation)"
            )
        elif earlier.dstaddr.contains(later.dstaddr):
            desc["dstaddr"] = (
                f"shadowing dstaddr={e_dst} "
                f"fully contains shadowed dstaddr={l_dst}"
            )
        elif earlier.dstaddr.overlaps(later.dstaddr):
            inter = earlier.dstaddr.intersection(later.dstaddr)
            desc["dstaddr"] = (
                f"partial dstaddr overlap: {inter.describe()} "
                f"(shadowing={e_dst}, shadowed={l_dst})"
            )
        else:
            desc["dstaddr"] = "no dstaddr overlap"

        # service — include raw object names + negation
        e_svc = _svc_label(earlier)
        l_svc = _svc_label(later)
        if earlier.service_negate:
            e_svc = f"NOT({e_svc})"
        if later.service_negate:
            l_svc = f"NOT({l_svc})"
        if earlier.service_negate or later.service_negate:
            desc["service"] = (
                f"NEGATED service — shadowing={e_svc}, shadowed={l_svc} "
                f"(indeterminate due to negation)"
            )
        elif earlier.service.contains(later.service):
            desc["service"] = (
                f"shadowing service={e_svc} "
                f"fully contains shadowed service={l_svc}"
            )
        elif earlier.service.overlaps(later.service):
            desc["service"] = (
                f"partial service overlap "
                f"(shadowing={e_svc}, shadowed={l_svc})"
            )
        else:
            desc["service"] = "no service overlap"

        # schedule — include raw object names
        e_sched = _sched_label(earlier)
        l_sched = _sched_label(later)
        if earlier.schedule.contains(later.schedule):
            desc["schedule"] = (
                f"shadowing schedule={e_sched} "
                f"fully contains shadowed schedule={l_sched}"
            )
        elif earlier.schedule.overlaps(later.schedule):
            desc["schedule"] = (
                f"schedule overlap "
                f"(shadowing={e_sched}, shadowed={l_sched})"
            )
        else:
            desc["schedule"] = "no schedule overlap"

        return desc

    # ------------------------------------------------------------------
    # Explanation generation
    # ------------------------------------------------------------------

    def _generate_explanation(
        self,
        finding: ShadowFinding,
        earlier: CanonicalPolicy,
        later: CanonicalPolicy,
    ) -> str:
        """Full natural-language explanation of a pairwise shadow."""
        e_label = earlier.label()
        l_label = later.label()

        if finding.finding_type == FindingType.FULL_CONFLICT_SHADOW:
            intro = (
                f"Rule {l_label} is FULLY SHADOWED by higher-priority rule {e_label} "
                f"with a DIFFERENT action ({earlier.action.value} vs "
                f"{later.action.value}). "
                f"Rule {l_label} will NEVER be reached for any traffic."
            )
        elif finding.finding_type == FindingType.FULL_REDUNDANT_COVERAGE:
            intro = (
                f"Rule {l_label} is FULLY COVERED by higher-priority rule {e_label} "
                f"with the SAME action ({later.action.value}). "
                f"Rule {l_label} is redundant and can potentially be removed."
            )
        elif finding.finding_type == FindingType.PARTIAL_CONFLICT_SHADOW:
            intro = (
                f"Rule {l_label} is PARTIALLY SHADOWED by higher-priority rule "
                f"{e_label} with a DIFFERENT action ({earlier.action.value} "
                f"vs {later.action.value}). Some traffic matching rule "
                f"{l_label} will be handled by rule {e_label} instead."
            )
        elif finding.finding_type == FindingType.PARTIAL_REDUNDANT_OVERLAP:
            intro = (
                f"Rule {l_label} PARTIALLY OVERLAPS with higher-priority rule "
                f"{e_label} with the SAME action ({later.action.value}). "
                f"Some traffic matches both rules."
            )
        elif finding.finding_type == FindingType.INDETERMINATE:
            intro = (
                f"Rule {l_label} has an INDETERMINATE relationship with "
                f"higher-priority rule {e_label} due to unresolved objects. "
                f"Manual review recommended."
            )
        else:
            intro = f"Rule {l_label} has a relationship with rule {e_label}."

        details = []
        for dim in ("srcintf", "dstintf", "srcaddr", "dstaddr", "service", "schedule"):
            val = getattr(finding, f"{dim}_overlap", "")
            if val:
                details.append(f"  - {val}")

        if finding.unsupported_notes:
            details.append(
                "  - Unresolved objects: " + "; ".join(finding.unsupported_notes)
            )

        return intro + "\n" + "\n".join(details) if details else intro

    def _generate_composite_explanation(
        self,
        finding: ShadowFinding,
        candidates: list[CanonicalPolicy],
        later: CanonicalPolicy,
    ) -> str:
        """Full explanation for composite shadow findings.

        Uses a structured format with the policy list as a separate
        SHADOWING_RULES: block so the HTML renderer can present it as
        a table instead of inline text.
        """
        l_label = later.label()

        if finding.same_action:
            intro = (
                f"Rule {l_label} is FULLY COVERED by the COMPOSITE UNION "
                f"of {len(candidates)} higher-priority rules with the SAME action "
                f"({later.action.value}). Rule {l_label} is redundant."
            )
        else:
            intro = (
                f"Rule {l_label} is FULLY SHADOWED by the COMPOSITE UNION "
                f"of {len(candidates)} higher-priority rules with DIFFERENT actions. "
                f"Rule {l_label} will NEVER be reached."
            )

        details = [
            f"  - {len(candidates)} higher-priority rules combine to cover all "
            f"traffic matched by rule {l_label}.",
        ]
        for dim in ("srcaddr", "dstaddr", "service", "schedule"):
            val = getattr(finding, f"{dim}_overlap", "")
            if val:
                details.append(f"  - {val}")

        if finding.unsupported_notes:
            details.append(
                "  - Unresolved objects: " + "; ".join(finding.unsupported_notes)
            )

        # Structured policy list — one line per policy for readability.
        # Format: SHADOWING_RULES:\n  seq|policyid|name|action\n  ...
        rules_block = "\nSHADOWING_RULES:"
        for c in candidates:
            rules_block += f"\n  {c.seq_num + 1}|{c.policyid}|{c.name}|{c.action.value}"

        return intro + "\n" + "\n".join(details) + rules_block

    # ------------------------------------------------------------------
    # Composite helper: interface union coverage
    # ------------------------------------------------------------------

    @staticmethod
    def _check_interface_union_coverage(
        earlier_intfs: list,
        later_intf,
    ) -> bool:
        """Check if the union of earlier interface sets covers later."""
        if later_intf.is_any:
            # Need at least one earlier to be 'any' to cover 'any'
            return any(e.is_any for e in earlier_intfs)
        # later has specific names; check each is in at least one earlier
        for name in later_intf.names:
            covered = False
            for e in earlier_intfs:
                if e.is_any or name in e.names:
                    covered = True
                    break
            if not covered:
                return False
        return True

    # ------------------------------------------------------------------
    # Composite helper: service union coverage
    # ------------------------------------------------------------------

    @staticmethod
    def _check_service_union_coverage(
        earlier_svcs: list,
        later_svc,
    ) -> bool:
        """Check if union of earlier service sets covers later's services."""
        if later_svc.is_any:
            return any(e.is_any for e in earlier_svcs)
        # Each spec in later must be contained by at least one earlier set
        for lspec in later_svc.specs:
            covered = False
            for esvc in earlier_svcs:
                if esvc.is_any:
                    covered = True
                    break
                for espec in esvc.specs:
                    if espec.contains(lspec):
                        covered = True
                        break
                if covered:
                    break
            if not covered:
                return False
        return True

    # ------------------------------------------------------------------
    # Composite helper: schedule union coverage
    # ------------------------------------------------------------------

    @staticmethod
    def _check_schedule_union_coverage(
        earlier_scheds: list,
        later_sched,
    ) -> bool:
        """Check if union of earlier schedules covers later's schedule.

        Conservative: only returns True if later is 'always' and at least
        one earlier is 'always', or all earlier schedules contain later.
        For recurring schedules, we require at least one earlier to fully
        contain later (simplified v1 approach).
        """
        if later_sched.is_always:
            return any(e.is_always for e in earlier_scheds)
        # At least one earlier must contain later's schedule
        return any(e.contains(later_sched) for e in earlier_scheds)
