"""
GhostTrace AI — Residual-Data Heatmap Engine
Domain: Northstar Shop E-Commerce Data Deletion Assurance
Generates residual-risk heatmaps across all Northstar Shop subsystems for inspected customer cases.
"""
from typing import Dict, List, Any, Optional

SYSTEM_DEFINITIONS = [
    {
        "system_id": "account_service",
        "system_name": "Primary Customer Database & Replicas",
        "description": "Primary user profiles, failover replicas, regional mirrors, and account tombstones.",
        "icon": "database"
    },
    {
        "system_id": "support_platform",
        "system_name": "Customer Support & Attachments",
        "description": "Customer service tickets, handover notes, message transcripts, and attached PDFs/images.",
        "icon": "headset"
    },
    {
        "system_id": "search_service",
        "system_name": "Customer Search Indexes",
        "description": "Elasticsearch / OpenSearch customer_directory_v3 directory indexes and lookup shards.",
        "icon": "search"
    },
    {
        "system_id": "analytics_platform",
        "system_name": "Behavioral Analytics & Cohorts",
        "description": "Customer clickstream, cohort segments, product viewing records, and behavioral metrics.",
        "icon": "chart-bar"
    },
    {
        "system_id": "export_service",
        "system_name": "Customer Data Exports",
        "description": "Historical data export bundles, download archives, and object storage staging keys.",
        "icon": "download"
    },
    {
        "system_id": "integration_service",
        "system_name": "Data Connectors & Pipelines",
        "description": "Active sync bridges (e.g. analytics_identity_bridge, support_profile_sync, warehouse connectors).",
        "icon": "exchange-alt"
    },
    {
        "system_id": "backup_service",
        "system_name": "Backup Archives & Snapshots",
        "description": "Point-in-time database snapshots, tape archives, and cold disaster-recovery bundles.",
        "icon": "archive"
    },
    {
        "system_id": "security_service",
        "system_name": "Compliance & Security Audit Log",
        "description": "Tamper-evident legal audit trail, deletion reviewed events, and retention registers.",
        "icon": "shield-alt"
    }
]

class HeatmapGenerator:
    def __init__(self):
        pass

    def generate_heatmap_for_case(self, case_id: str, deletion_status: str, steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        system_status_map: Dict[str, Dict[str, Any]] = {}
        for sdef in SYSTEM_DEFINITIONS:
            system_status_map[sdef["system_id"]] = {
                "system_id": sdef["system_id"],
                "system_name": sdef["system_name"],
                "description": sdef["description"],
                "icon": sdef["icon"],
                "status": "VERIFIED_COMPLIANT" if deletion_status == "COMPLETE" else "NOT_FOUND",
                "risk_level": "LOW",
                "findings_count": 0,
                "remediations_count": 0,
                "verifications_count": 0,
                "evidence_cited": [],
                "resources": []
            }

        for step in steps:
            sys_id = step.get("system_id", "")
            if sys_id not in system_status_map:
                continue

            entry = system_status_map[sys_id]
            phase = step.get("phase", "")
            op = step.get("operation", "")
            res_id = step.get("resource_id", "")
            ev_id = step.get("evidence_id", "")

            if res_id and res_id not in entry["resources"]:
                entry["resources"].append(res_id)
            if ev_id and ev_id not in entry["evidence_cited"]:
                entry["evidence_cited"].append(ev_id)

            if phase == "FINDING":
                entry["findings_count"] += 1
                if op == "REPORT_ACTIVE_DATA_FLOW":
                    entry["status"] = "ACTIVE_RECREATION_RISK"
                    entry["risk_level"] = "CRITICAL"
                elif op == "REPORT_RESTORE_RISK":
                    entry["status"] = "RESTORE_RISK"
                    entry["risk_level"] = "CRITICAL"
                elif op == "REPORT_EXPOSED_PII":
                    entry["status"] = "EXPOSED_PII_FOUND"
                    entry["risk_level"] = "HIGH"
                elif op == "REPORT_REMAINING_RECORD":
                    entry["status"] = "RESIDUAL_RECORD_FOUND"
                    entry["risk_level"] = "HIGH"
            elif phase == "REMEDIATION":
                entry["remediations_count"] += 1
            elif phase == "VERIFICATION":
                entry["verifications_count"] += 1
                if entry["findings_count"] == 0:
                    entry["status"] = "VERIFIED_COMPLIANT"
                    entry["risk_level"] = "LOW"

        # Overall summary metrics
        total_systems = len(SYSTEM_DEFINITIONS)
        compliant_systems = sum(1 for e in system_status_map.values() if e["status"] == "VERIFIED_COMPLIANT")
        risk_systems = sum(1 for e in system_status_map.values() if e["risk_level"] in ["HIGH", "CRITICAL"])

        return {
            "case_id": case_id,
            "deletion_status": deletion_status,
            "total_systems": total_systems,
            "compliant_systems": compliant_systems,
            "risk_systems": risk_systems,
            "systems": list(system_status_map.values())
        }

    def get_subsystem_matrix(self) -> List[Dict[str, Any]]:
        demo = self.generate_demo_heatmap()
        res = []
        for s in demo["systems"]:
            res.append({
                "subsystem": s["system_name"],
                "description": s["description"],
                "residual_risk": s["risk_level"],
                "evidence_types": ", ".join(s["evidence_cited"]) if s["evidence_cited"] else "None",
                "recommended_action": "REMEDIATE & PURGE" if s["risk_level"] in ["HIGH", "CRITICAL"] else "VERIFIED"
            })
        return res

    def get_aggregate_risk_score(self) -> Dict[str, Any]:
        demo = self.generate_demo_heatmap()
        return {
            "aggregate_posture": "ELEVATED (Active Ghost Data)",
            "high_risk_subsystems": demo["risk_systems"],
            "total_subsystems": demo["total_systems"]
        }

    def generate_demo_heatmap(self) -> Dict[str, Any]:
        """Synthetic demonstration heatmap for Priya's journey"""
        demo_steps = [
            {"phase": "FINDING", "system_id": "search_service", "resource_id": "search_demo_01", "operation": "REPORT_REMAINING_RECORD", "evidence_id": "evidence_57"},
            {"phase": "FINDING", "system_id": "support_platform", "resource_id": "support_demo_01", "operation": "REPORT_EXPOSED_PII", "evidence_id": "evidence_58"},
            {"phase": "FINDING", "system_id": "integration_service", "resource_id": "data_flow_demo_01", "operation": "REPORT_ACTIVE_DATA_FLOW", "evidence_id": "evidence_03"},
            {"phase": "FINDING", "system_id": "backup_service", "resource_id": "backup_demo_01", "operation": "REPORT_RESTORE_RISK", "evidence_id": "evidence_93"},
            {"phase": "VERIFICATION", "system_id": "account_service", "resource_id": "account_demo_01", "operation": "VERIFY_RECORD_ABSENT", "evidence_id": "evidence_54"},
            {"phase": "VERIFICATION", "system_id": "security_service", "resource_id": "audit_record_demo", "operation": "VERIFY_RECORD_PRESENT", "evidence_id": "evidence_92"}
        ]
        return self.generate_heatmap_for_case("DEMO_PRIYA_01", "INCOMPLETE", demo_steps)
