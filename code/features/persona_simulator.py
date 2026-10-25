"""
GhostTrace AI — Customer Persona Journey Simulator
Domain: Northstar Shop E-Commerce Data Deletion Assurance
Traces synthetic customer Priya's complete data lifecycle and residual-data footprint across Northstar Shop subsystems.
"""
from typing import Dict, List, Any
from dataclasses import dataclass, field

@dataclass
class PersonaEvent:
    stage_id: str
    stage_title: str
    description: str
    action_type: str
    timestamp: str
    artifacts_created: List[Dict[str, str]]
    residual_risk: str
    audit_finding: str

class PersonaJourneySimulator:
    def __init__(self):
        self.persona_name = "Priya Ramanathan (Synthetic Demonstration)"
        self.persona_email = "priya.ramanathan.demo@northstar-shop.internal"
        self.persona_phone = "+91 90000 82014"
        self.customer_id = "CUST-DEMO-9821"

    def run_simulation(self) -> Dict[str, Any]:
        stages = [
            PersonaEvent(
                stage_id="stage_01",
                stage_title="1. Account Registration",
                description="Priya registers an account on Northstar Shop, verifying email and mobile number.",
                action_type="SIGNUP",
                timestamp="2026-03-10T08:15:00Z",
                artifacts_created=[
                    {"system": "account_service", "artifact": "customer_profiles primary table", "identifier": self.persona_email},
                    {"system": "search_service", "artifact": "customer_directory_v3 index doc", "identifier": "search_demo_01"},
                    {"system": "auth_service", "artifact": "credential_hash and session record", "identifier": self.customer_id}
                ],
                residual_risk="LOW",
                audit_finding="Standard profile baseline established."
            ),
            PersonaEvent(
                stage_id="stage_02",
                stage_title="2. Product Browsing & Recommendations",
                description="Priya browses electronics and home lifestyle categories; analytics platform captures user events.",
                action_type="TELEMETRY",
                timestamp="2026-03-15T14:22:10Z",
                artifacts_created=[
                    {"system": "analytics_platform", "artifact": "analytics_profile cohort mobile_shopper", "identifier": "analytics_demo_01"},
                    {"system": "recommendation_engine", "artifact": "feature vector and browsing history", "identifier": self.customer_id}
                ],
                residual_risk="MEDIUM",
                audit_finding="Attributable user events stored in behavioral analytics database."
            ),
            PersonaEvent(
                stage_id="stage_03",
                stage_title="3. Order Placement & Payment",
                description="Priya purchases a Ceramic Coffee Set (Order ORD-2026-8812) with home delivery.",
                action_type="ORDER_TRANSACTION",
                timestamp="2026-03-20T11:05:30Z",
                artifacts_created=[
                    {"system": "order_service", "artifact": "order_records with billing & shipping address", "identifier": "ORD-2026-8812"},
                    {"system": "payment_gateway", "artifact": "tokenized payment log", "identifier": "pay_tok_8812"},
                    {"system": "integration_service", "artifact": "customer-events-to-warehouse connector", "identifier": "data_flow_demo_01"}
                ],
                residual_risk="HIGH",
                audit_finding="Commercial and tax records created; data flow connector actively synchronizing updates."
            ),
            PersonaEvent(
                stage_id="stage_04",
                stage_title="4. Customer Support Interaction",
                description="Priya submits a delivery address correction request with an attached PDF document.",
                action_type="SUPPORT_TICKET",
                timestamp="2026-04-02T09:44:00Z",
                artifacts_created=[
                    {"system": "support_platform", "artifact": "ticket_case_4827 conversation transcript", "identifier": "support_demo_01"},
                    {"system": "object_storage", "artifact": "support_attachment delivery_address_correction.pdf", "identifier": "att_demo_01"}
                ],
                residual_risk="HIGH",
                audit_finding="Direct PII (phone, alternate address, full name) embedded in conversation message and PDF attachment."
            ),
            PersonaEvent(
                stage_id="stage_05",
                stage_title="5. Data Export & System Backup",
                description="Priya requests a GDPR/privacy data export, followed by weekly automated database backup.",
                action_type="EXPORT_AND_BACKUP",
                timestamp="2026-04-10T16:30:00Z",
                artifacts_created=[
                    {"system": "export_service", "artifact": "customer_data_export.zip in S3 staging bucket", "identifier": "export_demo_01"},
                    {"system": "backup_service", "artifact": "weekly full database snapshot segment-42.tar.zst", "identifier": "backup_demo_01"}
                ],
                residual_risk="CRITICAL",
                audit_finding="Cold archive backup and downloadable export bundle contain complete snapshot of customer data."
            ),
            PersonaEvent(
                stage_id="stage_06",
                stage_title="6. Deletion Request & Workflow Claim",
                description="Priya submits an account deletion request under GDPR Article 17. Workflow reports status: COMPLETE.",
                action_type="DELETION_SUBMITTED",
                timestamp="2026-04-15T12:00:00Z",
                artifacts_created=[
                    {"system": "privacy_case_mgmt", "artifact": "privacy request case_demo_priya", "identifier": "case_demo_priya"},
                    {"system": "account_service", "artifact": "primary profile marked DELETED", "identifier": "account_demo_01"}
                ],
                residual_risk="CRITICAL",
                audit_finding="Workflow claimed 'Complete'. However, secondary systems, search index, backup, and attachment were not verified."
            ),
            PersonaEvent(
                stage_id="stage_07",
                stage_title="7. GhostTrace AI Audit & Assurance",
                description="GhostTrace AI audits Northstar Shop systems at audit_at cutoff and reconstructs true residual state.",
                action_type="AUDIT_VERIFICATION",
                timestamp="2026-04-20T12:00:00Z",
                artifacts_created=[
                    {"system": "ghosttrace_ai", "artifact": "audit verification matrix & remediation plan", "identifier": "audit_priya_01"}
                ],
                residual_risk="RESOLVED_VIA_PLAN",
                audit_finding="Detected 4 unverified residual artifacts (search index hit, exposed support ticket PII, active warehouse data flow, unrestrained backup restore path). Generated complete 14-step remediation plan."
            )
        ]

        return {
            "persona_name": self.persona_name,
            "persona_email": self.persona_email,
            "persona_phone": self.persona_phone,
            "customer_id": self.customer_id,
            "total_stages": len(stages),
            "stages": [
                {
                    "stage_id": s.stage_id,
                    "stage_title": s.stage_title,
                    "description": s.description,
                    "action_type": s.action_type,
                    "timestamp": s.timestamp,
                    "artifacts_created": s.artifacts_created,
                    "residual_risk": s.residual_risk,
                    "audit_finding": s.audit_finding
                }
                for s in stages
            ]
        }

    def get_journey_summary(self) -> Dict[str, Any]:
        sim = self.run_simulation()
        return {
            "persona_name": sim["persona_name"],
            "total_events": sim["total_stages"],
            "journey_events": sim["stages"]
        }
