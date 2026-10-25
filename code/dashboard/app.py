"""
GhostTrace AI - Interactive Northstar Shop Web Dashboard
FastAPI Application providing an interactive web console for data deletion audit,
residual risk heatmaps, backup simulation, and compliance reporting.
"""

import sys
import json
import csv
from pathlib import Path
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Ensure code root is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = BASE_DIR.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from engine.audit_engine import AuditEngine
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

app = FastAPI(
    title="GhostTrace AI - Northstar Shop Deletion Assurance Console",
    description="Interactive audit, digital forensics, and residual data assurance platform.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global caches
_audit_engine: Optional[AuditEngine] = None
_audit_results: Dict[str, Any] = {}
_raw_cases: List[Dict[str, Any]] = []


def get_audit_engine() -> AuditEngine:
    global _audit_engine
    if _audit_engine is None:
        dataset_dir = REPO_ROOT / "dataset"
        _audit_engine = AuditEngine(dataset_dir)
        _audit_engine.initialize()
    return _audit_engine


def load_audited_cases() -> List[Dict[str, Any]]:
    global _raw_cases
    if _raw_cases:
        return _raw_cases

    engine = get_audit_engine()
    output_path = REPO_ROOT / "output.csv"
    cases_path = REPO_ROOT / "dataset" / "deletion_requests.csv"

    # If output.csv exists, use it
    if output_path.exists():
        with open(output_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    steps = json.loads(row["steps_json"])
                except Exception:
                    steps = []
                _raw_cases.append({
                    "case_id": row["case_id"],
                    "deletion_status": row["deletion_status"],
                    "steps": steps,
                    "step_count": len(steps)
                })
    else:
        # Run audit on requests
        requests = engine.load_case_requests(cases_path)
        for req in requests:
            status, steps = engine.audit_case(req)
            _raw_cases.append({
                "case_id": req.case_id,
                "deletion_status": status.value,
                "steps": [s.to_dict() for s in steps],
                "step_count": len(steps)
            })
    return _raw_cases


@app.get("/api/summary")
def get_summary():
    cases = load_audited_cases()
    total = len(cases)
    complete = sum(1 for c in cases if c["deletion_status"] == "COMPLETE")
    incomplete = sum(1 for c in cases if c["deletion_status"] == "INCOMPLETE")
    not_applicable = sum(1 for c in cases if c["deletion_status"] == "NOT_APPLICABLE")

    return {
        "organization": "Northstar Shop E-Commerce Platform",
        "incident": "Post-Deletion Ghost Data Incident ($2.4M Regulatory Penalty)",
        "agent": "GhostTrace AI - Assurance & Digital Forensics Agent",
        "total_cases": total,
        "complete_count": complete,
        "incomplete_count": incomplete,
        "not_applicable_count": not_applicable,
        "complete_pct": round(complete / total * 100, 1) if total else 0,
        "incomplete_pct": round(incomplete / total * 100, 1) if total else 0,
        "not_applicable_pct": round(not_applicable / total * 100, 1) if total else 0,
    }


@app.get("/api/cases")
def list_cases(
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
):
    cases = load_audited_cases()
    filtered = cases

    if status and status.upper() in ["COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"]:
        filtered = [c for c in filtered if c["deletion_status"] == status.upper()]

    if search:
        search_lower = search.lower()
        filtered = [c for c in filtered if search_lower in c["case_id"].lower()]

    total = len(filtered)
    page = filtered[offset : offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "cases": page
    }


@app.get("/api/cases/{case_id}")
def get_case_detail(case_id: str):
    cases = load_audited_cases()
    matched = next((c for c in cases if c["case_id"] == case_id), None)
    if not matched:
        raise HTTPException(status_code=404, detail="Case not found")

    steps = matched["steps"]
    status = matched["deletion_status"]

    # Generate analytical insights
    scorer = EvidenceConfidenceScorer()
    conf = scorer.calculate_confidence(case_id, status, steps)

    contradiction_detector = ContradictionDetector()
    claims = [{"system_id": "production_cluster", "reported_state": "DELETED"}] if status == "INCOMPLETE" else []
    contradictions = contradiction_detector.cross_examine(case_id, claims, steps)

    playbook_gen = RemediationPlaybookGenerator()
    playbook = playbook_gen.generate_playbook(case_id, steps)

    custody_tracker = ChainOfCustodyTracker()
    custody = custody_tracker.build_chain(case_id, "2026-10-01T12:00:00Z", status, steps)

    risk_manager = RiskQueueManager()
    risk = risk_manager.evaluate_case_risk(case_id, status, steps, [c.__dict__ for c in contradictions])

    return {
        "case_id": case_id,
        "deletion_status": status,
        "step_count": len(steps),
        "steps": steps,
        "confidence": conf,
        "contradictions": [c.__dict__ for c in contradictions],
        "remediation_playbook": playbook,
        "chain_of_custody": custody,
        "risk_evaluation": risk
    }


@app.get("/api/persona")
def get_persona_journey():
    sim = PersonaJourneySimulator()
    return sim.get_journey_summary()


@app.get("/api/heatmap")
def get_heatmap():
    gen = HeatmapGenerator()
    return {
        "subsystems": gen.get_subsystem_matrix(),
        "aggregate_posture": gen.get_aggregate_risk_score()
    }


@app.get("/api/backup-sim")
def get_backup_sim(customer_id: str = "CUST-DEMO-9821"):
    sim = BackupReintroductionSimulator()
    return sim.simulate_restore_scenario(customer_id)


@app.get("/api/whatif")
def get_whatif(preset: str = "standard_ecommerce"):
    cases = load_audited_cases()
    incomplete = sum(1 for c in cases if c["deletion_status"] == "INCOMPLETE")
    total = len(cases)

    sim = WhatIfSimulator()
    return sim.simulate_policy_impact(preset, {
        "total_cases": total,
        "incomplete_cases": incomplete
    })


@app.get("/api/export-pack/{case_id}")
def export_evidence_pack(case_id: str):
    cases = load_audited_cases()
    matched = next((c for c in cases if c["case_id"] == case_id), None)
    if not matched:
        raise HTTPException(status_code=404, detail="Case not found")

    exporter = EvidencePackExporter(REPO_ROOT / "dataset")
    pack = exporter.generate_pack(case_id, matched["deletion_status"], matched["steps"])
    return pack


@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    # Return modern, responsive single-page Northstar Shop Deletion Assurance Dashboard
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GhostTrace AI — Northstar Shop Deletion Assurance Console</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --card-border: #1f2937;
      --accent: #06b6d4;
      --accent-glow: rgba(6, 182, 212, 0.25);
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --complete: #10b981;
      --incomplete: #ef4444;
      --na: #6b7280;
      --warning: #f59e0b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 0;
    }
    header {
      background: #0f172a;
      border-bottom: 1px solid #1e293b;
      padding: 1.25rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 50;
    }
    .logo-area { display: flex; align-items: center; gap: 0.75rem; }
    .logo-badge {
      background: linear-gradient(135deg, #06b6d4, #3b82f6);
      color: #000;
      font-weight: 800;
      font-size: 0.85rem;
      padding: 0.3rem 0.6rem;
      border-radius: 6px;
      letter-spacing: 0.05em;
    }
    .brand-title { font-weight: 700; font-size: 1.2rem; }
    .brand-sub { color: var(--text-muted); font-size: 0.8rem; }
    .status-pill {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      padding: 0.3rem 0.75rem;
      border-radius: 9999px;
      background: #1e293b;
      border: 1px solid #334155;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
    }
    .pulse-dot { width: 8px; height: 8px; border-radius: 50%; background: #10b981; animation: pulse 2s infinite; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
    
    nav {
      background: #0d131f;
      display: flex;
      gap: 0.5rem;
      padding: 0.5rem 2rem;
      border-bottom: 1px solid #1e293b;
      overflow-x: auto;
    }
    .tab-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 0.875rem;
      font-weight: 500;
      padding: 0.6rem 1.1rem;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.2s;
      white-space: nowrap;
    }
    .tab-btn:hover { color: var(--text); background: #1e293b; }
    .tab-btn.active { color: #fff; background: #1e293b; border-bottom: 2px solid var(--accent); }
    
    main { padding: 2rem; max-width: 1400px; margin: 0 auto; }
    
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1.25rem;
      margin-bottom: 2rem;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 1.25rem;
      position: relative;
    }
    .stat-title { font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
    .stat-val { font-size: 2rem; font-weight: 700; margin-top: 0.4rem; font-family: 'JetBrains Mono', monospace; }
    
    .table-container {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      overflow: hidden;
    }
    .table-header-bar {
      padding: 1rem 1.5rem;
      border-bottom: 1px solid var(--card-border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }
    table { width: 100%; border-collapse: collapse; text-align: left; }
    th {
      background: #0f172a;
      padding: 0.85rem 1.25rem;
      font-size: 0.75rem;
      text-transform: uppercase;
      color: var(--text-muted);
      border-bottom: 1px solid var(--card-border);
    }
    td {
      padding: 0.85rem 1.25rem;
      font-size: 0.875rem;
      border-bottom: 1px solid #1a2234;
    }
    tr:hover td { background: #172133; cursor: pointer; }
    
    .tag {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.7rem;
      font-weight: 600;
      padding: 0.2rem 0.55rem;
      border-radius: 4px;
      display: inline-block;
    }
    .tag-complete { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .tag-incomplete { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .tag-na { background: rgba(107, 114, 128, 0.15); color: #9ca3af; border: 1px solid rgba(107, 114, 128, 0.3); }
    
    .search-input {
      background: #0d131f;
      border: 1px solid #334155;
      padding: 0.5rem 0.9rem;
      border-radius: 6px;
      color: #fff;
      font-size: 0.875rem;
      width: 260px;
    }
    .filter-btn {
      background: #1e293b;
      border: 1px solid #334155;
      color: #fff;
      padding: 0.5rem 0.8rem;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.8rem;
    }
    
    /* Modal / Drawer */
    .modal {
      display: none;
      position: fixed;
      top: 0; left: 0; width: 100%; height: 100%;
      background: rgba(0, 0, 0, 0.8);
      z-index: 100;
      justify-content: center;
      align-items: center;
      padding: 1rem;
    }
    .modal-content {
      background: #111827;
      border: 1px solid #374151;
      border-radius: 12px;
      width: 90%;
      max-width: 950px;
      max-height: 85vh;
      overflow-y: auto;
      padding: 2rem;
      position: relative;
    }
    .close-modal {
      position: absolute;
      top: 1.25rem;
      right: 1.5rem;
      background: transparent;
      border: none;
      color: #9ca3af;
      font-size: 1.5rem;
      cursor: pointer;
    }
    .close-modal:hover { color: #fff; }

    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-top: 1rem; }
    .card { background: #162032; border: 1px solid #25334a; border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; }
    
    .timeline { position: relative; padding-left: 2rem; border-left: 2px solid #2d3748; margin-top: 1.5rem; }
    .timeline-item { position: relative; margin-bottom: 1.5rem; }
    .timeline-dot {
      position: absolute; left: -2.45rem; top: 0.2rem;
      width: 14px; height: 14px; border-radius: 50%;
      background: var(--accent); border: 2px solid #090d16;
    }
    .code-block {
      background: #0d131f;
      border: 1px solid #1e293b;
      padding: 0.75rem;
      border-radius: 6px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      overflow-x: auto;
    }
  </style>
</head>
<body>
  <header>
    <div class="logo-area">
      <div class="logo-badge">GHOSTTRACE AI</div>
      <div>
        <div class="brand-title">Northstar Shop Deletion Assurance Console</div>
        <div class="brand-sub">HackerRank Orchestrate 2026 • Post-Incident Forensics & Regulatory Proof</div>
      </div>
    </div>
    <div class="status-pill">
      <div class="pulse-dot"></div>
      <span>ENGINE ONLINE (518 CASES AUDITED)</span>
    </div>
  </header>

  <nav>
    <button class="tab-btn active" onclick="switchTab('explorer')">Audit Explorer</button>
    <button class="tab-btn" onclick="switchTab('persona')">Priya's Journey (Simulator)</button>
    <button class="tab-btn" onclick="switchTab('heatmap')">Residual Risk Heatmap</button>
    <button class="tab-btn" onclick="switchTab('backups')">Backup & Restore Center</button>
    <button class="tab-btn" onclick="switchTab('whatif')">What-If Policy Lab</button>
  </nav>

  <main id="app-container">
    <!-- Audit Explorer Tab -->
    <div id="tab-explorer">
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-title">Total Deletion Requests</div>
          <div class="stat-val" id="stat-total">518</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Verified Complete</div>
          <div class="stat-val" style="color: var(--complete)" id="stat-complete">-</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Ghost Data / Incomplete</div>
          <div class="stat-val" style="color: var(--incomplete)" id="stat-incomplete">-</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Not Applicable</div>
          <div class="stat-val" style="color: var(--na)" id="stat-na">-</div>
        </div>
      </div>

      <div class="table-container">
        <div class="table-header-bar">
          <input type="text" id="case-search" class="search-input" placeholder="Search case ID (e.g. case_10)..." oninput="debounceSearch()">
          <div style="display: flex; gap: 0.5rem;">
            <button class="filter-btn" onclick="filterStatus('')">All</button>
            <button class="filter-btn" onclick="filterStatus('COMPLETE')">Complete</button>
            <button class="filter-btn" onclick="filterStatus('INCOMPLETE')">Incomplete</button>
            <button class="filter-btn" onclick="filterStatus('NOT_APPLICABLE')">N/A</button>
          </div>
        </div>
        <table>
          <thead>
            <tr>
              <th>Case ID</th>
              <th>Status</th>
              <th>Audit Steps</th>
              <th>Evidence Trail</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="cases-tbody">
            <tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">Loading audit records...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Priya's Journey Tab -->
    <div id="tab-persona" style="display: none;">
      <div class="card">
        <h2 style="font-size: 1.25rem; margin-bottom: 0.5rem; color: var(--accent);">Customer Persona Journey Simulator — Priya Ramanathan</h2>
        <p style="color: var(--text-muted); font-size: 0.875rem;">
          Synthetic demonstration tracing every digital artifact created across Northstar Shop during an end-to-end customer lifecycle,
          visualizing where ghost data persists even after account termination.
        </p>
      </div>
      <div id="persona-timeline" class="timeline"></div>
    </div>

    <!-- Heatmap Tab -->
    <div id="tab-heatmap" style="display: none;">
      <div class="card">
        <h2 style="font-size: 1.25rem; margin-bottom: 0.5rem; color: var(--accent);">Northstar Shop Subsystem Residual-Data Heatmap</h2>
        <p style="color: var(--text-muted); font-size: 0.875rem;">
          Cross-system vulnerability matrix highlighting residual risk scores, evidence availability, and recommended remediation.
        </p>
      </div>
      <div id="heatmap-content"></div>
    </div>

    <!-- Backup Center Tab -->
    <div id="tab-backups" style="display: none;">
      <div class="card">
        <h2 style="font-size: 1.25rem; margin-bottom: 0.5rem; color: var(--accent);">Backup & Snapshot Reintroduction Simulator</h2>
        <p style="color: var(--text-muted); font-size: 0.875rem;">
          Demonstrates how automated Point-in-Time database recoveries reintroduce deleted customer records back into active production.
        </p>
      </div>
      <div id="backup-sim-content"></div>
    </div>

    <!-- What-If Lab Tab -->
    <div id="tab-whatif" style="display: none;">
      <div class="card">
        <h2 style="font-size: 1.25rem; margin-bottom: 0.5rem; color: var(--accent);">What-If Retention & Policy Simulator</h2>
        <p style="color: var(--text-muted); font-size: 0.875rem; margin-bottom: 1rem;">
          Test the impact of different retention horizons and policy strictness across all 518 deletion cases.
        </p>
        <div style="display: flex; gap: 0.75rem;">
          <button class="filter-btn" onclick="runWhatIf('strict_zero_trust')">Strict Zero-Trust (GDPR Art 17)</button>
          <button class="filter-btn" onclick="runWhatIf('standard_ecommerce')">Standard Northstar Retail</button>
          <button class="filter-btn" onclick="runWhatIf('lenient_enterprise')">Enterprise Extended Retention</button>
        </div>
      </div>
      <div id="whatif-results"></div>
    </div>
  </main>

  <!-- Case Detail Modal -->
  <div id="case-modal" class="modal">
    <div class="modal-content">
      <button class="close-modal" onclick="closeModal()">&times;</button>
      <div id="modal-body"></div>
    </div>
  </div>

  <script>
    let currentStatusFilter = '';
    let currentSearch = '';
    let searchTimeout = null;

    async function init() {
      await loadSummary();
      await loadCases();
    }

    async function loadSummary() {
      try {
        const res = await fetch('/api/summary');
        const data = await res.json();
        document.getElementById('stat-total').innerText = data.total_cases;
        document.getElementById('stat-complete').innerText = `${data.complete_count} (${data.complete_pct}%)`;
        document.getElementById('stat-incomplete').innerText = `${data.incomplete_count} (${data.incomplete_pct}%)`;
        document.getElementById('stat-na').innerText = `${data.not_applicable_count} (${data.not_applicable_pct}%)`;
      } catch (e) {
        console.error(e);
      }
    }

    async function loadCases() {
      try {
        let url = `/api/cases?limit=100&status=${currentStatusFilter}&search=${encodeURIComponent(currentSearch)}`;
        const res = await fetch(url);
        const data = await res.json();
        const tbody = document.getElementById('cases-tbody');
        tbody.innerHTML = '';

        if (!data.cases || data.cases.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">No matching cases found</td></tr>';
          return;
        }

        data.cases.forEach(c => {
          const tr = document.createElement('tr');
          tr.onclick = () => openCaseDetail(c.case_id);
          const tagClass = c.deletion_status === 'COMPLETE' ? 'tag-complete' : (c.deletion_status === 'INCOMPLETE' ? 'tag-incomplete' : 'tag-na');
          const evidenceCount = new Set(c.steps.map(s => s.evidence_id).filter(Boolean)).size;

          tr.innerHTML = `
            <td style="font-family: 'JetBrains Mono', monospace; font-weight: 600;">${c.case_id}</td>
            <td><span class="tag ${tagClass}">${c.deletion_status}</span></td>
            <td>${c.step_count} step(s)</td>
            <td style="color: var(--text-muted);">${evidenceCount} evidence file(s)</td>
            <td><button class="filter-btn" onclick="event.stopPropagation(); openCaseDetail('${c.case_id}')">Inspect</button></td>
          `;
          tbody.appendChild(tr);
        });
      } catch (e) {
        console.error(e);
      }
    }

    async function openCaseDetail(caseId) {
      const modal = document.getElementById('case-modal');
      const body = document.getElementById('modal-body');
      body.innerHTML = '<p style="color: var(--text-muted);">Loading forensic analysis...</p>';
      modal.style.display = 'flex';

      try {
        const res = await fetch(`/api/cases/${caseId}`);
        const data = await res.json();
        const tagClass = data.deletion_status === 'COMPLETE' ? 'tag-complete' : (data.deletion_status === 'INCOMPLETE' ? 'tag-incomplete' : 'tag-na');

        let stepsHtml = data.steps.map(s => `
          <tr style="font-size: 0.8rem;">
            <td>${s.step_no}</td>
            <td><strong>${s.phase}</strong></td>
            <td><code>${s.system_id}</code></td>
            <td><code>${s.resource_id}</code></td>
            <td>${s.operation}</td>
            <td>${s.state}</td>
            <td><code>${s.evidence_id || '-'}</code></td>
          </tr>
        `).join('');

        let contradictionsHtml = data.contradictions.length ? data.contradictions.map(c => `
          <div style="background: rgba(239, 68, 68, 0.1); border-left: 3px solid #ef4444; padding: 0.6rem; margin-top: 0.4rem; font-size: 0.8rem;">
            <strong>Contradiction in ${c.system_id}:</strong> Reported ${c.claimed_state}, but ${c.ground_truth_state} (${c.finding_evidence_id})
          </div>
        `).join('') : '<p style="color: var(--text-muted); font-size: 0.85rem;">No direct system contradictions found.</p>';

        body.innerHTML = `
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem;">
            <div>
              <h2 style="font-size: 1.5rem; font-family: 'JetBrains Mono', monospace;">${data.case_id}</h2>
              <span class="tag ${tagClass}" style="margin-top: 0.3rem;">${data.deletion_status}</span>
            </div>
            <div style="text-align: right;">
              <div style="font-size: 0.8rem; color: var(--text-muted);">Confidence Score</div>
              <div style="font-size: 1.5rem; font-weight: 700; color: var(--accent); font-family: 'JetBrains Mono', monospace;">${data.confidence.confidence_score}/100</div>
            </div>
          </div>

          <div class="grid-2">
            <div class="card">
              <h3 style="font-size: 0.95rem; margin-bottom: 0.5rem; color: var(--accent);">System Contradictions</h3>
              ${contradictionsHtml}
            </div>
            <div class="card">
              <h3 style="font-size: 0.95rem; margin-bottom: 0.5rem; color: var(--accent);">Remediation Playbook</h3>
              <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.4rem;">${data.remediation_playbook.summary}</p>
              <div style="font-size: 0.8rem;"><strong>Actionable Items:</strong> ${data.remediation_playbook.total_actions}</div>
            </div>
          </div>

          <div class="card">
            <h3 style="font-size: 0.95rem; margin-bottom: 0.75rem; color: var(--accent);">Audit Steps & Evidence Mapping</h3>
            <div style="overflow-x: auto;">
              <table>
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Phase</th>
                    <th>System ID</th>
                    <th>Resource ID</th>
                    <th>Operation</th>
                    <th>State</th>
                    <th>Evidence ID</th>
                  </tr>
                </thead>
                <tbody>
                  ${stepsHtml || '<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No steps recorded for this request.</td></tr>'}
                </tbody>
              </table>
            </div>
          </div>
        `;
      } catch (e) {
        body.innerHTML = `<p style="color: #ef4444;">Failed to load case details: ${e.message}</p>`;
      }
    }

    function closeModal() {
      document.getElementById('case-modal').style.display = 'none';
    }

    function filterStatus(st) {
      currentStatusFilter = st;
      loadCases();
    }

    function debounceSearch() {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => {
        currentSearch = document.getElementById('case-search').value;
        loadCases();
      }, 300);
    }

    function switchTab(tabName) {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      event.target.classList.add('active');

      document.getElementById('tab-explorer').style.display = tabName === 'explorer' ? 'block' : 'none';
      document.getElementById('tab-persona').style.display = tabName === 'persona' ? 'block' : 'none';
      document.getElementById('tab-heatmap').style.display = tabName === 'heatmap' ? 'block' : 'none';
      document.getElementById('tab-backups').style.display = tabName === 'backups' ? 'block' : 'none';
      document.getElementById('tab-whatif').style.display = tabName === 'whatif' ? 'block' : 'none';

      if (tabName === 'persona') loadPersona();
      if (tabName === 'heatmap') loadHeatmap();
      if (tabName === 'backups') loadBackups();
      if (tabName === 'whatif') runWhatIf('standard_ecommerce');
    }

    async function loadPersona() {
      const res = await fetch('/api/persona');
      const data = await res.json();
      const container = document.getElementById('persona-timeline');
      container.innerHTML = data.journey_events.map(ev => `
        <div class="timeline-item">
          <div class="timeline-dot"></div>
          <div style="display: flex; justify-content: space-between; align-items: baseline;">
            <h3 style="font-size: 1rem; color: #fff;">${ev.stage_title}</h3>
            <span style="font-size: 0.75rem; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">${ev.timestamp}</span>
          </div>
          <p style="font-size: 0.85rem; color: var(--text-muted); margin: 0.4rem 0;">${ev.description}</p>
          <div style="font-size: 0.8rem; background: #0f172a; padding: 0.6rem; border-radius: 6px; border: 1px solid #1e293b;">
            <strong style="color: ${ev.residual_risk.includes('HIGH') ? '#f87171' : '#34d399'};">Residual Risk:</strong> ${ev.residual_risk}<br>
            <strong style="color: var(--accent);">Forensic Finding:</strong> ${ev.audit_finding}
          </div>
        </div>
      `).join('');
    }

    async function loadHeatmap() {
      const res = await fetch('/api/heatmap');
      const data = await res.json();
      const container = document.getElementById('heatmap-content');
      
      let rows = data.subsystems.map(s => `
        <tr>
          <td><strong>${s.subsystem}</strong></td>
          <td style="color: var(--text-muted); font-size: 0.8rem;">${s.description}</td>
          <td><span class="tag ${s.residual_risk === 'HIGH' ? 'tag-incomplete' : (s.residual_risk === 'MEDIUM' ? 'tag-na' : 'tag-complete')}">${s.residual_risk}</span></td>
          <td><code>${s.evidence_types}</code></td>
          <td style="font-weight: 600;">${s.recommended_action}</td>
        </tr>
      `).join('');

      container.innerHTML = `
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Subsystem</th>
                <th>Description</th>
                <th>Residual Risk</th>
                <th>Evidence Types</th>
                <th>Recommended Action</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      `;
    }

    async function loadBackups() {
      const res = await fetch('/api/backup-sim');
      const data = await res.json();
      const container = document.getElementById('backup-sim-content');
      
      container.innerHTML = `
        <div class="card">
          <h3 style="color: #f87171; margin-bottom: 0.5rem;">⚠️ Ghost Data Reintroduction Warning</h3>
          <p style="font-size: 0.875rem; color: var(--text-muted); margin-bottom: 1rem;">${data.warning}</p>
          <div class="code-block">${data.restoration_preventative_rule}</div>
        </div>
        <div class="table-container" style="margin-top: 1rem;">
          <table>
            <thead>
              <tr>
                <th>Snapshot ID</th>
                <th>Timestamp</th>
                <th>Ghost Records Contained</th>
                <th>Restore Risk</th>
                <th>Mitigation</th>
              </tr>
            </thead>
            <tbody>
              ${data.simulated_snapshots.map(s => `
                <tr>
                  <td><code>${s.snapshot_id}</code></td>
                  <td>${s.timestamp}</td>
                  <td>${s.records_contained}</td>
                  <td><span class="tag ${s.ghost_data_risk === 'HIGH' ? 'tag-incomplete' : 'tag-complete'}">${s.ghost_data_risk}</span></td>
                  <td>${s.mitigation}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;
    }

    async function runWhatIf(preset) {
      const res = await fetch(`/api/whatif?preset=${preset}`);
      const data = await res.json();
      const container = document.getElementById('whatif-results');

      container.innerHTML = `
        <div class="stats-grid" style="margin-top: 1.5rem;">
          <div class="stat-card">
            <div class="stat-title">Policy Model</div>
            <div class="stat-val" style="font-size: 1.25rem; color: var(--accent);">${data.preset_name}</div>
          </div>
          <div class="stat-card">
            <div class="stat-title">Projected Incomplete</div>
            <div class="stat-val" style="color: var(--incomplete);">${data.projections.projected_incomplete_cases}</div>
          </div>
          <div class="stat-card">
            <div class="stat-title">Residual Risk Index</div>
            <div class="stat-val">${data.projections.residual_exposure_index}/100</div>
          </div>
          <div class="stat-card">
            <div class="stat-title">Backup Reintroduction Risk</div>
            <div class="stat-val" style="font-size: 1.5rem; color: ${data.projections.backup_reintroduction_risk === 'HIGH' ? '#f87171' : '#34d399'};">${data.projections.backup_reintroduction_risk}</div>
          </div>
        </div>
        <div class="card">
          <h3 style="font-size: 0.95rem; margin-bottom: 0.5rem; color: var(--accent);">Policy Posture Analysis</h3>
          <p style="font-size: 0.85rem; color: var(--text-muted);">${data.parameters.description}</p>
          <div style="margin-top: 0.75rem; font-size: 0.85rem;">
            <strong>Compliance Assessment:</strong> ${data.projections.compliance_posture}
          </div>
        </div>
      `;
    }

    window.onclick = function(e) {
      const modal = document.getElementById('case-modal');
      if (e.target === modal) modal.style.display = 'none';
    };

    window.onload = init;
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("dashboard.app:app", host="127.0.0.1", port=8000, reload=True)
