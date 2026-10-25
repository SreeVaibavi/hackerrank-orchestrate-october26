"""
GhostTrace AI — Remediation Playbook Generator
Domain: Northstar Shop E-Commerce Data Deletion Assurance
Translates raw audit findings into actionable engineering and operations playbooks for INCOMPLETE cases.
"""
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class PlaybookItem:
    priority: int
    system_id: str
    resource_id: str
    action_required: str
    target_state: str
    policy_rule: str
    operational_instruction: str
    verification_check: str
    evidence_trigger: str

class RemediationPlaybookGenerator:
    def __init__(self):
        pass

    def generate_playbook(self, case_id: str, steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        findings = [s for s in steps if s.get("phase") == "FINDING"]
        remediations = [s for s in steps if s.get("phase") == "REMEDIATION"]
        verifications = [s for s in steps if s.get("phase") == "VERIFICATION"]

        items: List[PlaybookItem] = []
        prio = 1

        # Map findings and remediations
        rem_by_res = {r.get("resource_id"): r for r in remediations}

        for f in findings:
            sys_id = f.get("system_id", "")
            rid = f.get("resource_id", "")
            op = f.get("operation", "")
            ev_id = f.get("evidence_id", "")

            rem = rem_by_res.get(rid, {})
            rem_op = rem.get("operation", "MANUAL_INSPECTION")
            target_st = rem.get("state", "ABSENT")

            rule_desc = "Deletion Rules Specification (HackerRank October 2026)"
            instruction = ""
            verif_op = "VERIFY_RECORD_ABSENT"

            if op == "REPORT_ACTIVE_DATA_FLOW":
                rule_desc = "Rule 16: Active connectors must be disabled prior to deleting downstream copies."
                instruction = f"Execute connector shutdown API on integration_service for {rid}. Disable scheduler and unbind tenant webhook."
                verif_op = "VERIFY_DATA_FLOW_DISABLED"
            elif op == "REPORT_RESTORE_RISK":
                rule_desc = "Rule 14: Backup archives must have restore access blocked to prevent ghost data resurrection."
                instruction = f"Issue BLOCK_RESTORE call to backup_service for snapshot {rid}. Revoke subject restoration decryption key."
                verif_op = "VERIFY_RESTORE_BLOCKED"
            elif op == "REPORT_EXPOSED_PII":
                if sys_id == "support_platform":
                    rule_desc = "Rule 05: Support conversations must retain transactional context while redacting direct customer PII."
                    instruction = f"Invoke support_platform redaction pipeline on ticket {rid}. Mask requester_name, requester_email, requester_phone."
                    verif_op = "VERIFY_RECORD_REDACTED"
                elif sys_id == "analytics_platform":
                    rule_desc = "Rule 07/08: Analytics and product telemetry must be irreversibly unlinked and anonymized."
                    instruction = f"Execute anonymization worker for cohort record {rid}. Strip customer_reference, email, and IP attributes."
                    verif_op = "VERIFY_RECORD_ANONYMIZED"
                elif sys_id == "identity_service":
                    rule_desc = "Rule 15: Account tombstone must retain only stable internal user_id; all direct PII must be purged."
                    instruction = f"Redact tombstone {rid}. Clear name, email, phone, and email_hash; preserve user_id tombstone pointer."
                    verif_op = "VERIFY_RECORD_REDACTED"
            elif op == "REPORT_REMAINING_RECORD":
                rule_desc = "Rule 01-04/06/09: Surviving profiles, search indices, attachments, or exports must be permanently purged."
                instruction = f"Send hard-delete request to {sys_id} for resource {rid}. Purge associated object keys and replica partitions."
                verif_op = "VERIFY_RECORD_ABSENT"

            items.append(PlaybookItem(
                priority=prio,
                system_id=sys_id,
                resource_id=rid,
                action_required=rem_op,
                target_state=target_st,
                policy_rule=rule_desc,
                operational_instruction=instruction,
                verification_check=verif_op,
                evidence_trigger=ev_id
            ))
            prio += 1

        return {
            "case_id": case_id,
            "total_actions": len(items),
            "total_remediation_actions": len(items),
            "summary": f"{len(items)} remediation action(s) required to eliminate residual ghost data" if items else "No outstanding remediation actions required.",
            "estimated_execution_time_minutes": len(items) * 5,
            "playbook_actions": [
                {
                    "priority": it.priority,
                    "system_id": it.system_id,
                    "resource_id": it.resource_id,
                    "action_required": it.action_required,
                    "target_state": it.target_state,
                    "policy_rule": it.policy_rule,
                    "operational_instruction": it.operational_instruction,
                    "verification_check": it.verification_check,
                    "evidence_trigger": it.evidence_trigger
                }
                for it in items
            ]
        }
