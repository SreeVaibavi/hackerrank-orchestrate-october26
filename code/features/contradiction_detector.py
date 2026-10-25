"""
GhostTrace AI — Contradiction Detector Engine
Domain: Northstar Shop E-Commerce Data Deletion Assurance
Flags inconsistencies between reported workflow deletion claims and ground evidence.
"""
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class ContradictionAlert:
    case_id: str
    contradiction_type: str
    severity: str
    claim_description: str
    evidence_reality: str
    cited_evidence_id: str
    system_id: str
    resource_id: str
    confidence_pct: int
    recommendation: str

class ContradictionDetector:
    def __init__(self):
        pass

    def detect_contradictions(self, case_id: str, reported_status: str, reported_at: str, audit_at: str, steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        contradictions = []

        findings = [s for s in steps if s.get("phase") == "FINDING"]

        # Contradiction 1: Workflow claims COMPLETE, but residual findings exist
        if reported_status == "COMPLETE" and findings:
            for f in findings:
                op = f.get("operation", "")
                sys_id = f.get("system_id", "")
                rid = f.get("resource_id", "")
                ev = f.get("evidence_id", "")

                c_type = "CLAIMED_COMPLETE_BUT_RESIDUAL_DATA"
                severity = "CRITICAL"
                claim = f"Workflow reported deletion as COMPLETE at {reported_at}."
                reality = f"Ground evidence {ev} proves resource {rid} in {sys_id} is still {f.get('state')} with operation {op}."

                if op == "REPORT_ACTIVE_DATA_FLOW":
                    c_type = "ACTIVE_DATA_FLOW_AFTER_DELETION"
                    reality = f"Active data connector {rid} is actively syncing updates despite reported completion."
                elif op == "REPORT_RESTORE_RISK":
                    c_type = "UNPROTECTED_BACKUP_RESTORE_PATH"
                    reality = f"Disaster recovery snapshot {rid} allows unquarantined restoration of deleted customer records."
                elif op == "REPORT_EXPOSED_PII":
                    c_type = "EXPOSED_PII_IN_SECONDARY_SYSTEM"
                    reality = f"Support message or analytics profile {rid} still contains direct personal identifiers (email/phone)."

                contradictions.append(ContradictionAlert(
                    case_id=case_id,
                    contradiction_type=c_type,
                    severity=severity,
                    claim_description=claim,
                    evidence_reality=reality,
                    cited_evidence_id=ev,
                    system_id=sys_id,
                    resource_id=rid,
                    confidence_pct=95,
                    recommendation=f"Execute remediation operation {op.replace('REPORT_', '')} to eliminate ghost data."
                ))

        # Contradiction 2: Workflow claims PARTIALLY_COMPLETE, but no residual issues exist (false incomplete claim)
        if reported_status == "PARTIALLY_COMPLETE" and not findings:
            contradictions.append(ContradictionAlert(
                case_id=case_id,
                contradiction_type="WORKFLOW_UNDERCLAIMED_COMPLETION",
                severity="LOW",
                claim_description=f"Workflow flagged request as PARTIALLY_COMPLETE at {reported_at}.",
                evidence_reality=f"Evidence audit at {audit_at} confirms all records and data flows are already compliant/absent.",
                cited_evidence_id=steps[0].get("evidence_id", "") if steps else "",
                system_id="workflow_manager",
                resource_id="audit_assessment",
                confidence_pct=90,
                recommendation="Update workflow status in case management to COMPLETE based on evidence proof."
            ))

        return [
            {
                "case_id": c.case_id,
                "contradiction_type": c.contradiction_type,
                "severity": c.severity,
                "claim_description": c.claim_description,
                "evidence_reality": c.evidence_reality,
                "cited_evidence_id": c.cited_evidence_id,
                "system_id": c.system_id,
                "resource_id": c.resource_id,
                "confidence_pct": c.confidence_pct,
                "recommendation": c.recommendation
            }
            for c in contradictions
        ]

    def cross_examine(self, case_id: str, claims: List[Dict[str, Any]], steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Cross examine claimed system states against step findings."""
        alerts = []
        for c in claims:
            sys_id = c.get("system_id", "")
            claimed_state = c.get("reported_state", "DELETED")
            matching_finding = next((s for s in steps if s.get("phase") == "FINDING" and s.get("system_id") == sys_id), None)
            if matching_finding:
                alerts.append({
                    "case_id": case_id,
                    "system_id": sys_id,
                    "claimed_state": claimed_state,
                    "ground_truth_state": matching_finding.get("state", "PRESENT"),
                    "finding_evidence_id": matching_finding.get("evidence_id", "evidence_unknown"),
                    "contradiction_type": "SYSTEM_CLAIM_CONTRADICTED"
                })
        return alerts
