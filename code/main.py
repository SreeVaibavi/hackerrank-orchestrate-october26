"""
GhostTrace AI — Defence & Commercial Data Deletion Assurance Agent
Official HackerRank Orchestrate (October 2026) Submission Entry Point

Primary Domain: Northstar Shop E-Commerce Data Deletion Assurance & Forensics
Commands:
  python code/main.py --audit          Run full audit on dataset/deletion_requests.csv -> output.csv
  python code/main.py --sample         Evaluate against sample_output.csv (benchmark validation)
  python code/main.py --evaluate       Generate evaluation_report.md & usage_report.md
  python code/main.py --serve          Start interactive web dashboard on http://127.0.0.1:8000
  python code/main.py --features       Run demonstration of all 12 secondary analytical features
  python code/main.py --package        Build submission code.zip archive
"""

import sys
import os
import argparse
import json
import csv
import zipfile
from pathlib import Path
from datetime import datetime, timezone

# Add code directory to sys.path
BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from engine.audit_engine import AuditEngine
from engine.models import DeletionStatus


def run_audit(input_csv: Path, output_csv: Path) -> None:
    """
    Execute full deterministic audit and write strict output.csv
    Header: case_id,deletion_status,steps_json
    Sorted ascending by case_id
    """
    dataset_dir = REPO_ROOT / "dataset"
    print(f"[*] Initializing GhostTrace AI Engine with dataset: {dataset_dir}")
    engine = AuditEngine(dataset_dir)
    engine.initialize()

    print(f"[*] Loading requests from: {input_csv}")
    requests = engine.load_case_requests(input_csv)
    print(f"[*] Processing {len(requests)} deletion requests...")

    rows = []
    complete_count = 0
    incomplete_count = 0
    na_count = 0

    for i, req in enumerate(requests):
        status, steps = engine.audit_case(req)
        steps_dicts = [s.to_dict() for s in steps]
        steps_json = json.dumps(steps_dicts, separators=(",", ":"))

        rows.append({
            "case_id": req.case_id,
            "deletion_status": status.value,
            "steps_json": steps_json
        })

        if status == DeletionStatus.COMPLETE:
            complete_count += 1
        elif status == DeletionStatus.INCOMPLETE:
            incomplete_count += 1
        else:
            na_count += 1

        if (i + 1) % 50 == 0 or (i + 1) == len(requests):
            print(f"    Processed {i + 1}/{len(requests)} cases...")

    # Sort numerically/lexicographically by case_id
    def case_sort_key(r):
        cid = r["case_id"]
        if cid.startswith("case_") and cid[5:].isdigit():
            return (0, int(cid[5:]))
        return (1, cid)

    rows.sort(key=case_sort_key)

    # Write output.csv
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"], quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    print(f"[+] Successfully wrote {len(rows)} audit results to: {output_csv}")
    print(f"[+] Summary: COMPLETE={complete_count}, INCOMPLETE={incomplete_count}, NOT_APPLICABLE={na_count}")


def run_sample_eval() -> None:
    """Validate engine against ground-truth sample_output.csv."""
    dataset_dir = REPO_ROOT / "dataset"
    engine = AuditEngine(dataset_dir)
    engine.initialize()

    sample_req_path = dataset_dir / "sample_deletion_requests.csv"
    sample_out_path = dataset_dir / "sample_output.csv"

    requests = engine.load_case_requests(sample_req_path)
    ground_truth = {}
    with open(sample_out_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ground_truth[row["case_id"]] = {
                "status": row["deletion_status"],
                "steps": json.loads(row["steps_json"])
            }

    correct_status = 0
    total = len(requests)

    print("\n--- SAMPLE BENCHMARK EVALUATION (32 CASES) ---")
    for req in requests:
        status, steps = engine.audit_case(req)
        gt = ground_truth.get(req.case_id, {})
        gt_status = gt.get("status")

        is_match = (status.value == gt_status)
        if is_match:
            correct_status += 1
        else:
            print(f"[MISMATCH] {req.case_id}: Predicted={status.value}, Expected={gt_status}")

    acc = (correct_status / total) * 100
    print(f"Status Accuracy: {correct_status}/{total} ({acc:.2f}%)")
    if acc == 100.0:
        print("[SUCCESS] Engine passed 100% of sample benchmark cases!\n")


def run_features_demo() -> None:
    """Execute all 12 secondary features and display results."""
    from features.persona_simulator import PersonaJourneySimulator
    from features.heatmap_generator import HeatmapGenerator
    from features.backup_simulator import BackupReintroductionSimulator
    from features.contradiction_detector import ContradictionDetector
    from features.confidence_scorer import EvidenceConfidenceScorer
    from features.remediation_playbook import RemediationPlaybookGenerator
    from features.chain_of_custody import ChainOfCustodyTracker
    from features.policy_advisor import PolicyActionAdvisor
    from features.exposure_scanner import SensitiveFieldExposureScanner
    from features.risk_queue import RiskQueueManager
    from features.evidence_pack_exporter import EvidencePackExporter
    from features.whatif_simulator import WhatIfSimulator

    print("\n=== RUNNING GHOSTTRACE AI SECONDARY FEATURES DEMO ===")
    
    # 1. Persona Simulator
    p_sim = PersonaJourneySimulator()
    summary = p_sim.get_journey_summary()
    print(f"[1] Persona Journey: {summary['persona_name']} ({summary['total_events']} lifecycle events)")

    # 2. Heatmap
    heatmap = HeatmapGenerator()
    score = heatmap.get_aggregate_risk_score()
    print(f"[2] Residual Heatmap: Aggregate Platform Risk = {score['aggregate_posture']} ({score['high_risk_subsystems']} high-risk subsystems)")

    # 3. Backup Simulator
    b_sim = BackupReintroductionSimulator()
    b_res = b_sim.simulate_restore_scenario("CUST-DEMO-9821")
    print(f"[3] Backup Simulator: {len(b_res['simulated_snapshots'])} snapshots evaluated. Contamination: {b_res['contamination_count']} snapshots")

    # 4. Contradictions
    c_det = ContradictionDetector()
    sample_steps = [{"system_id": "analytics_data_stream", "resource_id": "analytics_export_44", "operation": "ANONYMIZE", "state": "PENDING", "evidence_id": "evidence_12"}]
    c_res = c_det.cross_examine("case_10", [{"system_id": "analytics_data_stream", "reported_state": "DELETED"}], sample_steps)
    print(f"[4] Contradiction Detector: Detected {len(c_res)} system claim contradiction(s)")

    # 5. Confidence Scorer
    c_scorer = EvidenceConfidenceScorer()
    conf = c_scorer.calculate_confidence("case_10", "INCOMPLETE", sample_steps)
    print(f"[5] Confidence Scorer: Advisory Score = {conf['confidence_score']}/100 ({conf['confidence_tier']})")

    # 6. Remediation Playbook
    p_gen = RemediationPlaybookGenerator()
    pb = p_gen.generate_playbook("case_10", sample_steps)
    print(f"[6] Remediation Playbook: Generated {pb['total_actions']} operational action items")

    # 7. Chain of Custody
    c_track = ChainOfCustodyTracker()
    cust = c_track.build_chain("case_10", "2026-10-01T12:00:00Z", "INCOMPLETE", sample_steps)
    print(f"[7] Chain of Custody: Sealed chain with SHA-256 seal: {cust['chain_hash_sha256'][:16]}...")

    # 8. Policy Advisor
    p_adv = PolicyActionAdvisor()
    advice = p_adv.get_advice_for_category("ATTACHMENT")
    print(f"[8] Policy Advisor: Taxonomized support attachment action -> {advice['title']}")

    # 9. Exposure Scanner
    e_scan = SensitiveFieldExposureScanner()
    exp = e_scan.scan_text("Contact user priya.ramanathan@northstar.internal at +91 90000 82014")
    print(f"[9] Exposure Scanner: Discovered {len(exp)} sensitive PII field occurrences")

    # 10. Risk Queue
    r_mgr = RiskQueueManager()
    rk = r_mgr.evaluate_case_risk("case_10", "INCOMPLETE", sample_steps, [c.__dict__ for c in c_res])
    print(f"[10] Risk Queue: Case evaluated at Risk Score = {rk['risk_score']}/100 (Severity: {rk['severity']})")

    # 11. Evidence Pack Exporter
    pack_exp = EvidencePackExporter(REPO_ROOT / "dataset")
    pack = pack_exp.generate_pack("case_10", "INCOMPLETE", sample_steps)
    print(f"[11] Evidence Pack: Generated tamper-evident pack. Seal = {pack['tamper_evident_seal_sha256'][:16]}...")

    # 12. What-If Simulator
    w_sim = WhatIfSimulator()
    w_res = w_sim.simulate_policy_impact("strict_zero_trust", {"total_cases": 518, "incomplete_cases": 380})
    print(f"[12] What-If Simulator: Strict Zero Trust projected incomplete cases = {w_res['projections']['projected_incomplete_cases']}")
    print("=== ALL 12 SECONDARY FEATURES OPERATIONAL ===\n")


def run_package() -> None:
    """Build compliant submission code.zip archive."""
    zip_path = REPO_ROOT / "code.zip"
    if zip_path.exists():
        zip_path.unlink()

    print(f"[*] Packaging submission archive: {zip_path}")
    excluded_dirs = {".git", ".venv", "venv", "__pycache__", "dataset", ".gemini"}
    excluded_exts = {".pyc", ".pyo", ".zip", ".tar", ".gz"}

    count = 0
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Include code/
        code_dir = REPO_ROOT / "code"
        for root, dirs, files in os.walk(code_dir):
            dirs[:] = [d for d in dirs if d not in excluded_dirs]
            for file in files:
                ext = Path(file).suffix.lower()
                if ext in excluded_exts:
                    continue
                full_path = Path(root) / file
                arcname = str(full_path.relative_to(REPO_ROOT)).replace("\\", "/")
                zf.write(full_path, arcname)
                count += 1

        # Include root documentation and instructions
        root_files = ["README.md", "CLAUDE.md", "AGENTS.md", "problem_statement.md", "agent_trace_instructions.md", "log.txt"]
        for rf in root_files:
            fp = REPO_ROOT / rf
            if fp.exists():
                zf.write(fp, rf)
                count += 1

    size_kb = zip_path.stat().st_size / 1024
    print(f"[+] Successfully created {zip_path.name} ({count} files, {size_kb:.1f} KB)")


def start_server() -> None:
    """Start web dashboard server."""
    import uvicorn
    print("[*] Starting GhostTrace AI Web Dashboard on http://127.0.0.1:8000 ...")
    uvicorn.run("dashboard.app:app", host="127.0.0.1", port=8000, reload=False)


def main():
    parser = argparse.ArgumentParser(description="GhostTrace AI — Deletion Assurance Engine")
    parser.add_argument("--audit", "-a", action="store_true", help="Run audit on dataset/deletion_requests.csv")
    parser.add_argument("--sample", "-s", action="store_true", help="Run sample benchmark evaluation")
    parser.add_argument("--evaluate", "-e", action="store_true", help="Run full evaluation and generate reports")
    parser.add_argument("--serve", "-w", action="store_true", help="Start web dashboard on port 8000")
    parser.add_argument("--features", "-f", action="store_true", help="Run secondary features demonstration")
    parser.add_argument("--package", "-p", action="store_true", help="Package submission code.zip")

    args = parser.parse_args()

    if args.sample:
        run_sample_eval()
    elif args.serve:
        start_server()
    elif args.features:
        run_features_demo()
    elif args.package:
        run_package()
    elif args.evaluate:
        # Run evaluation script
        from evaluation.main import run_full_evaluation
        run_full_evaluation()
    else:
        # Default or explicit --audit
        input_csv = REPO_ROOT / "dataset" / "deletion_requests.csv"
        output_csv = REPO_ROOT / "output.csv"
        run_audit(input_csv, output_csv)


if __name__ == "__main__":
    main()
