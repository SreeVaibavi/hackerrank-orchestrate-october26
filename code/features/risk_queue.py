"""
GhostTrace AI - Risk-Based Review Queue
Prioritizes cases by residual risk severity: active data flows, restore risks, exposed PII, and contradictions.
"""

from typing import Dict, List, Any


class RiskQueueManager:
    """
    Ranks cases by audit risk severity to allow data governance teams
    to triage high-risk deletion failures first.
    """

    def __init__(self):
        pass

    def evaluate_case_risk(self, case_id: str, status: str, steps: List[Dict[str, Any]], contradictions: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Calculate composite risk score (0-100) and severity category for a case.
        """
        score = 0
        factors = []

        if status == "INCOMPLETE":
            score += 35
            factors.append("Status is INCOMPLETE (remediation required)")
        elif status == "COMPLETE":
            score += 5
            factors.append("Status is COMPLETE (evidence-verified)")
        else:
            factors.append("Request is NOT_APPLICABLE")

        # Check steps for high-risk flags
        has_active_flow = False
        has_backup_risk = False
        has_exposed_pii = False
        finding_count = 0

        for s in steps:
            op = s.get("operation", "")
            phase = s.get("phase", "")
            sys_id = s.get("system_id", "")
            res_id = s.get("resource_id", "")

            if phase == "FINDING":
                finding_count += 1
                if "backup" in sys_id.lower() or "snapshot" in res_id.lower() or op == "BLOCK_RESTORE":
                    has_backup_risk = True
                if "connector" in sys_id.lower() or "flow" in res_id.lower() or "stream" in sys_id.lower():
                    has_active_flow = True
                if "support" in sys_id.lower() or "attachment" in res_id.lower() or "log" in sys_id.lower():
                    has_exposed_pii = True

            if op == "BLOCK_RESTORE":
                has_backup_risk = True

        if has_active_flow:
            score += 25
            factors.append("Active data flow/connector detected")
        if has_backup_risk:
            score += 20
            factors.append("Snapshot re-introduction / restore risk detected")
        if has_exposed_pii:
            score += 15
            factors.append("Unredacted PII in support attachments or logs")

        if contradictions:
            score += 15
            factors.append(f"{len(contradictions)} system status contradiction(s) detected")

        # Clamp score
        score = min(100, max(0, score))

        if score >= 70:
            severity = "CRITICAL"
        elif score >= 45:
            severity = "HIGH"
        elif score >= 25:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "case_id": case_id,
            "status": status,
            "risk_score": score,
            "severity": severity,
            "finding_count": finding_count,
            "risk_factors": factors,
            "requires_urgent_action": score >= 70
        }

    def rank_cases(self, audited_cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sort list of evaluated cases by risk score descending.
        """
        return sorted(audited_cases, key=lambda c: c.get("risk_score", 0), reverse=True)
