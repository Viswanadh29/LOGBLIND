"""Gap detection engine — the core analysis logic of LogBlind.

Compares a PolicySnapshot against the KnowledgeBase to find which
ATT&CK detection requirements are NOT met by the current audit config.
"""

from __future__ import annotations

from logblind.models.analysis import CoverageStatus, EventGap, TechniqueGapResult
from logblind.models.policy import PolicySnapshot
from logblind.models.technique import EventRequirement, KnowledgeBase, Technique


class GapDetector:
    """Analyzes audit policy against knowledge base requirements."""

    def analyze(
        self,
        policy: PolicySnapshot,
        kb: KnowledgeBase,
        technique_filter: list[str] | None = None,
    ) -> list[TechniqueGapResult]:
        """Analyze all techniques against the policy."""
        results: list[TechniqueGapResult] = []
        for technique in kb.techniques:
            if technique_filter and technique.technique_id not in technique_filter:
                continue
            results.append(self._analyze_technique(policy, technique))
        return results

    def _analyze_technique(
        self,
        policy: PolicySnapshot,
        technique: Technique,
    ) -> TechniqueGapResult:
        """Analyze a single technique against the policy."""
        gaps: list[EventGap] = []
        met_count = 0
        total_count = len(technique.event_requirements)
        notes: list[str] = []

        if total_count == 0:
            return TechniqueGapResult(
                technique_id=technique.technique_id,
                technique_name=technique.name,
                coverage_percent=0.0,
                status=CoverageStatus.BLIND,
                total_requirements=0,
                met_requirements=0,
                notes=["No detection requirements defined."],
            )

        for req in technique.event_requirements:
            is_met, gap = self._check_requirement(policy, req)
            if is_met:
                met_count += 1
            elif gap:
                gaps.append(gap)

        coverage = self._calculate_weighted_coverage(technique.event_requirements, gaps)

        if coverage >= 80:
            status = CoverageStatus.COVERED
        elif coverage > 0:
            status = CoverageStatus.PARTIAL
        else:
            status = CoverageStatus.BLIND

        # Notes about supplementary tools
        if policy.registry.sysmon_installed:
            notes.append("[+] Sysmon is installed -- enhances detection capability.")
        else:
            sysmon_reqs = [r for r in technique.event_requirements if r.sysmon_required]
            if sysmon_reqs:
                notes.append(
                    f"[!] Sysmon not installed -- {len(sysmon_reqs)} detection(s) unavailable."
                )

        return TechniqueGapResult(
            technique_id=technique.technique_id,
            technique_name=technique.name,
            coverage_percent=coverage,
            status=status,
            total_requirements=total_count,
            met_requirements=met_count,
            gaps=gaps,
            notes=notes,
        )

    def _check_requirement(
        self,
        policy: PolicySnapshot,
        req: EventRequirement,
    ) -> tuple[bool, EventGap | None]:
        """Check if a single event requirement is met."""
        # Sysmon-dependent events
        if req.sysmon_required:
            if policy.registry.sysmon_installed:
                return True, None
            return False, EventGap(
                event_id=req.event_id,
                channel=req.channel,
                condition=req.condition,
                importance=req.importance,
                reason="Sysmon is not installed.",
                fix_command="# Install Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
            )

        # Registry-based checks
        if req.registry_check:
            is_met = self._check_registry_requirement(policy, req.registry_check)
            if is_met:
                return True, None
            return False, EventGap(
                event_id=req.event_id,
                channel=req.channel,
                condition=req.condition,
                importance=req.importance,
                reason=f"Registry check '{req.registry_check}' is not configured.",
                fix_command=f"# Configure: {req.registry_check}",
            )

        # Audit subcategory-based checks
        if req.audit_subcategory:
            needs_success = "success" in req.audit_setting.lower()
            needs_failure = "failure" in req.audit_setting.lower()

            success_ok = not needs_success or policy.is_success_enabled(req.audit_subcategory)
            failure_ok = not needs_failure or policy.is_failure_enabled(req.audit_subcategory)

            if success_ok and failure_ok:
                return True, None

            missing = []
            fix_parts = []
            if needs_success and not success_ok:
                missing.append("Success")
                fix_parts.append("/success:enable")
            if needs_failure and not failure_ok:
                missing.append("Failure")
                fix_parts.append("/failure:enable")

            missing_audits = " and ".join(missing)
            fix_command = (
                f'auditpol /set /subcategory:"{req.audit_subcategory}" {" ".join(fix_parts)}'
            )
            return False, EventGap(
                event_id=req.event_id,
                channel=req.channel,
                condition=req.condition,
                importance=req.importance,
                reason=(
                    f"Audit subcategory '{req.audit_subcategory}' not set to"
                    f" {missing_audits} auditing."
                ),
                fix_command=fix_command,
            )

        # Operational log events — typically always available
        return True, None

    def _check_registry_requirement(self, policy: PolicySnapshot, check_name: str) -> bool:
        """Check if a named registry requirement is met."""
        cl = check_name.lower()
        if "scriptblock" in cl or "script block" in cl:
            return policy.registry.scriptblock_logging
        elif "commandline" in cl or "command-line" in cl or "cmdline" in cl:
            return policy.registry.commandline_audit
        elif "sysmon" in cl:
            return policy.registry.sysmon_installed
        elif "wef" in cl or "event forwarding" in cl:
            return policy.registry.wef_configured
        return False

    def _calculate_weighted_coverage(
        self,
        requirements: list[EventRequirement],
        gaps: list[EventGap],
    ) -> float:
        """Calculate weighted coverage. CRITICAL=3x, HIGH=2x, MEDIUM=1x, LOW=0.5x."""
        weights = {"CRITICAL": 3.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.5}
        total = sum(weights.get(r.importance, 1.0) for r in requirements)
        if total == 0:
            return 0.0

        gap_keys = {(g.event_id, g.channel) for g in gaps}
        met = sum(
            weights.get(r.importance, 1.0)
            for r in requirements
            if (r.event_id, r.channel) not in gap_keys
        )
        return round((met / total) * 100, 1)
