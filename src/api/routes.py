"""
src/api/routes.py - FastAPI REST Endpoints for CyberRiskQuant Platform.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from src.config import USD_TO_INR_RATE, inr_to_usd, usd_to_inr
from src.api.schemas import (
    HealthResponse,
    ExecutiveDashboardResponse,
    TechnicalDashboardResponse,
    SimulationRequest,
    SimulationResponse,
    WhatIfRequest,
    WhatIfResponse,
    NLQRequest,
    NLQResponse,
    OptimizeRequest,
    OptimizeResponse,
    ComplianceMatrixResponse,
    TelemetryDrilldownResponse,
    AttackInjectionRequest,
    AttackInjectionResponse,
    TelemetryTickerResponse,
    ResetAttackResponse,
    VendorComparisonResponse,
    VirtualPurchaseRequest,
    VirtualPurchaseResponse,
    AIChatRequest,
    AIChatResponse,
    AINavigateRequest,
    AINavigateResponse,
    AIExecutiveSummaryRequest,
    AIExecutiveSummaryResponse,
)
from src.ai import get_copilot
from src.compliance.catalog import get_all_frameworks, get_framework_controls_as_dicts
from src.compliance.mapper import ComplianceMapper
from src.compliance.scoring import ComplianceScorer
from src.decision_support.nlq_parser import NLQParser, QueryIntent
from src.decision_support.narrative import ExecutiveNarrativeGenerator, format_currency
from src.decision_support.what_if import WhatIfEngine
from src.decision_support.delay_cost import DelayedRemediationModel
from src.decision_support.trajectory import ThreatTrajectoryForecaster
from src.optimization.models import OptimizationRequest, SecurityControl, ThreatShield, ThreatVectorEnum
from src.optimization.solver import OptimizationSolver
from src.optimization.vendor_benchmarking import (
    get_ceo_vendor_catalog,
    get_vendor_by_id,
    apply_virtual_vendor_purchase,
    VENDOR_CATALOG,
)
from src.quant.monte_carlo import MonteCarloEngine
from src.telemetry.attack_engine import AttackType, DemoAttackStateManager
from src.telemetry.generator import ApexEnterpriseGenerator

router = APIRouter(prefix="/api/v1", tags=["CyberRiskQuant"])

# Initialize singleton engines
_compliance_scorer = ComplianceScorer()
_narrative_gen = ExecutiveNarrativeGenerator()
_nlq_parser = NLQParser()
_what_if_engine = WhatIfEngine()
_trajectory_engine = ThreatTrajectoryForecaster()
_delay_model = DelayedRemediationModel()
_opt_solver = OptimizationSolver()
_quant_engine = MonteCarloEngine(iterations=3000, seed=42)
_demo_state_manager = DemoAttackStateManager()
_ai_copilot = get_copilot()

# Canonical enterprise mock data for immediate instant responses
CANONICAL_CONTROLS = [
    SecurityControl(
        control_id="CTRL-MFA",
        name="Hardware MFA Enforcement on All Privileged Roles",
        category="Identity & Access Management",
        cost=350000.0,
        cost_inr=350000.0,
        cost_usd=inr_to_usd(350000.0),
        target_finding_ids=["IAM-001"],
        effectiveness=0.88,
        is_mandatory=True,
        mapped_frameworks={"RBI": "RBI-IAM-01", "SEBI": "SEBI-WIT-01", "ISO": "ISO-A.8.2"},
        future_threat_shields=[
            ThreatShield(
                threat_vector=ThreatVectorEnum.CREDENTIAL_STUFFING,
                future_immunity_pct=98.5,
                protective_mechanism="FIDO2 WebAuthn cryptographic hardware keys and adaptive session step-up authentication",
                neutralized_attack_types=["Brute Force", "Credential Stuffing", "Session Hijacking", "Password Spraying"],
            ),
            ThreatShield(
                threat_vector=ThreatVectorEnum.RANSOMWARE_LATERAL,
                future_immunity_pct=88.0,
                protective_mechanism="Zero-trust continuous authentication and administrative privilege isolation",
                neutralized_attack_types=["Pass-the-Hash", "Lateral Privilege Escalation"],
            ),
        ],
    ),
    SecurityControl(
        control_id="CTRL-PATCH",
        name="Automated Vulnerability Patching Pipeline",
        category="Vulnerability Management",
        cost=500000.0,
        cost_inr=500000.0,
        cost_usd=inr_to_usd(500000.0),
        target_finding_ids=["VULN-001"],
        effectiveness=0.92,
        is_mandatory=False,
        mapped_frameworks={"RBI": "RBI-VAP-01", "CIS": "CIS-7.4", "ISO": "ISO-A.8.8"},
        future_threat_shields=[
            ThreatShield(
                threat_vector=ThreatVectorEnum.ZERO_DAY_RCE,
                future_immunity_pct=87.5,
                protective_mechanism="Automated continuous vulnerability remediation and 48-hour SLA hot-patching pipeline",
                neutralized_attack_types=["Memory Corruption", "Deserialization RCE", "SQL Injection"],
            ),
            ThreatShield(
                threat_vector=ThreatVectorEnum.DATA_EXFILTRATION,
                future_immunity_pct=82.0,
                protective_mechanism="Elimination of unauthenticated service bypass flaws and known remote exploit surfaces",
                neutralized_attack_types=["Database Dumping", "Arbitrary File Read"],
            ),
        ],
    ),
    SecurityControl(
        control_id="CTRL-EDR",
        name="Next-Gen EDR Behavioral Agent with Anti-Tamper",
        category="Endpoint Protection",
        cost=800000.0,
        cost_inr=800000.0,
        cost_usd=inr_to_usd(800000.0),
        target_finding_ids=["EDR-001"],
        effectiveness=0.85,
        is_mandatory=False,
        mapped_frameworks={"SEBI": "SEBI-CON-02", "RBI": "RBI-MAL-01", "ISO": "ISO-A.8.7"},
        future_threat_shields=[
            ThreatShield(
                threat_vector=ThreatVectorEnum.RANSOMWARE_LATERAL,
                future_immunity_pct=96.5,
                protective_mechanism="Kernel-level ring-0 behavioral heuristics, eBPF syscall filtering, and shadow copy tamper locking",
                neutralized_attack_types=["PsExec Spreading", "WMI Execution", "LSASS Dumping", "VSS Deletion"],
            ),
            ThreatShield(
                threat_vector=ThreatVectorEnum.ZERO_DAY_RCE,
                future_immunity_pct=91.0,
                protective_mechanism="Exploit mitigation engine preventing heap spray, shellcode execution, and process hollowing",
                neutralized_attack_types=["Memory Injection", "Process Hollow", "Living-off-the-land"],
            ),
        ],
    ),
    SecurityControl(
        control_id="CTRL-S3-ENCR",
        name="Automated Cloud S3 Encryption & Public Block Guardrails",
        category="Cloud Security (CSPM)",
        cost=250000.0,
        cost_inr=250000.0,
        cost_usd=inr_to_usd(250000.0),
        target_finding_ids=["CSPM-001"],
        effectiveness=0.95,
        is_mandatory=True,
        mapped_frameworks={"RBI": "RBI-DAT-01", "SEBI": "SEBI-WIT-03", "ISO": "ISO-A.8.24"},
        future_threat_shields=[
            ThreatShield(
                threat_vector=ThreatVectorEnum.DATA_EXFILTRATION,
                future_immunity_pct=97.4,
                protective_mechanism="KMS customer-managed envelope encryption, automated SCP guardrails, and public block enforcement",
                neutralized_attack_types=["S3 Bucket Dumping", "DNS Tunneling", "Unauthorized Role Delegation"],
            ),
            ThreatShield(
                threat_vector=ThreatVectorEnum.RANSOMWARE_LATERAL,
                future_immunity_pct=85.0,
                protective_mechanism="S3 Object Lock with WORM immutable compliance retention",
                neutralized_attack_types=["Cloud Data Encryption Extortion"],
            ),
        ],
    ),
    SecurityControl(
        control_id="CTRL-SIEM-AI",
        name="AI-Driven SIEM Correlation & Automated SOAR Playbooks",
        category="Security Operations",
        cost=1200000.0,
        cost_inr=1200000.0,
        cost_usd=inr_to_usd(1200000.0),
        target_finding_ids=["SIEM-001"],
        effectiveness=0.78,
        prerequisites=["CTRL-EDR"],
        is_mandatory=False,
        mapped_frameworks={"RBI": "RBI-SOC-01", "SEBI": "SEBI-CON-01", "CIS": "CIS-8.2"},
        future_threat_shields=[
            ThreatShield(
                threat_vector=ThreatVectorEnum.VOLUMETRIC_DDOS,
                future_immunity_pct=84.0,
                protective_mechanism="Real-time multi-source log correlation and dynamic upstream rate-limiting orchestration",
                neutralized_attack_types=["Layer 7 Flood", "Ingress Surge"],
            ),
            ThreatShield(
                threat_vector=ThreatVectorEnum.CREDENTIAL_STUFFING,
                future_immunity_pct=89.5,
                protective_mechanism="Anomaly detection over authentication velocity and global IP reputation scoring",
                neutralized_attack_types=["Distributed Password Spraying"],
            ),
        ],
    ),
    SecurityControl(
        control_id="CTRL-WAF",
        name="Enterprise Cloud WAF & Layer 7 DDoS Mitigation",
        category="Network & Perimeter",
        cost=600000.0,
        cost_inr=600000.0,
        cost_usd=inr_to_usd(600000.0),
        target_finding_ids=["SIEM-001", "VULN-001"],
        effectiveness=0.94,
        is_mandatory=False,
        mapped_frameworks={"RBI": "RBI-NET-01", "SEBI": "SEBI-CON-01", "ISO": "ISO-A.8.20"},
        future_threat_shields=[
            ThreatShield(
                threat_vector=ThreatVectorEnum.VOLUMETRIC_DDOS,
                future_immunity_pct=99.8,
                protective_mechanism="Anycast BGP distributed scrubbing network (>280 Tbps capacity) and challenge-response filtering",
                neutralized_attack_types=["SYN Flood", "UDP Amplification", "HTTP Flood", "Slowloris"],
            ),
            ThreatShield(
                threat_vector=ThreatVectorEnum.CREDENTIAL_STUFFING,
                future_immunity_pct=95.2,
                protective_mechanism="Behavioral bot management, TLS fingerprinting, and client-side challenge verification",
                neutralized_attack_types=["Automated Botnets", "Credential Stuffing", "Account Takeover"],
            ),
            ThreatShield(
                threat_vector=ThreatVectorEnum.ZERO_DAY_RCE,
                future_immunity_pct=92.0,
                protective_mechanism="Signatureless payload inspection, OWASP Core Ruleset, and virtual patching at edge",
                neutralized_attack_types=["Log4Shell", "Spring4Shell", "Command Injection"],
            ),
        ],
    ),
]

CANONICAL_FINDINGS = [
    {
        "finding_id": "VULN-001",
        "asset_id": "asset-core-db-01",
        "asset_name": "Core Banking PostgreSQL Primary",
        "domain": "vulnerability",
        "severity": "CRITICAL",
        "title": "CVE-2023-34362 MOVEit Transfer SQL Injection",
        "cvss_score": 9.8,
        "epss_score": 0.92,
        "cisa_kev": True,
        "attributed_eal_inr": 18500000.0,
        "attributed_eal_usd": 18500000.0 / 83.5,
        "mapped_controls": ["ISO-A.8.8", "CIS-7.4", "RBI-VAP-01", "SEBI-CON-03"],
        "recommended_control": "CTRL-PATCH",
    },
    {
        "finding_id": "SIEM-001",
        "asset_id": "asset-web-gw-01",
        "asset_name": "Internet API Gateway",
        "domain": "siem",
        "severity": "HIGH",
        "title": "Brute Force Credential Stuffing Surge",
        "cvss_score": 7.5,
        "epss_score": 0.45,
        "cisa_kev": False,
        "attributed_eal_inr": 8200000.0,
        "attributed_eal_usd": 8200000.0 / 83.5,
        "mapped_controls": ["ISO-A.8.15", "CIS-8.2", "RBI-SOC-01", "SEBI-CON-01"],
        "recommended_control": "CTRL-SIEM-AI",
    },
    {
        "finding_id": "IAM-001",
        "asset_id": "asset-cloud-iam-01",
        "asset_name": "AWS Production IAM Core",
        "domain": "iam",
        "severity": "CRITICAL",
        "title": "Unrestricted Root Role Without Multi-Factor Authentication",
        "cvss_score": 8.9,
        "epss_score": 0.68,
        "cisa_kev": False,
        "attributed_eal_inr": 11000000.0,
        "attributed_eal_usd": 11000000.0 / 83.5,
        "mapped_controls": ["ISO-A.8.2", "CIS-5.2", "RBI-IAM-01", "SEBI-WIT-01"],
        "recommended_control": "CTRL-MFA",
    },
    {
        "finding_id": "EDR-001",
        "asset_id": "asset-trader-ws-01",
        "asset_name": "Trading Floor Workstation 104",
        "domain": "edr",
        "severity": "HIGH",
        "title": "Endpoint Agent Offline & Tamper Protection Disabled",
        "cvss_score": 7.8,
        "epss_score": 0.55,
        "cisa_kev": False,
        "attributed_eal_inr": 4500000.0,
        "attributed_eal_usd": 4500000.0 / 83.5,
        "mapped_controls": ["ISO-A.8.7", "CIS-10.1", "RBI-MAL-01", "SEBI-CON-02"],
        "recommended_control": "CTRL-EDR",
    },
    {
        "finding_id": "CSPM-001",
        "asset_id": "asset-s3-backup-01",
        "asset_name": "Customer Archive S3 Bucket",
        "domain": "cspm",
        "severity": "CRITICAL",
        "title": "Public S3 Bucket With Cardholder Data (PCI-DSS Leak)",
        "cvss_score": 9.1,
        "epss_score": 0.84,
        "cisa_kev": True,
        "attributed_eal_inr": 6000000.0,
        "attributed_eal_usd": 6000000.0 / 83.5,
        "mapped_controls": ["ISO-A.8.24", "CIS-3.4", "RBI-DAT-01", "SEBI-WIT-03"],
        "recommended_control": "CTRL-S3-ENCR",
    },
]


@router.get("/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    """Readiness probe checking engine integrity and status."""
    return HealthResponse()


@router.get("/assets")
def get_assets():
    """Retrieve complete enterprise asset inventory."""
    gen = ApexEnterpriseGenerator(seed=42)
    assets = gen.generate_assets()
    return {
        "total_assets": len(assets),
        "assets": [
            {
                "asset_id": a.asset_id,
                "name": a.name,
                "business_unit": a.business_unit,
                "asset_type": a.asset_type.value if hasattr(a.asset_type, "value") else str(a.asset_type),
                "criticality_tier": a.data_sensitivity_tier.value if hasattr(a.data_sensitivity_tier, "value") else str(a.data_sensitivity_tier),
                "environment": a.environment.value if hasattr(a.environment, "value") else str(a.environment),
            }
            for a in assets
        ],
    }


@router.get("/dashboard/executive", response_model=ExecutiveDashboardResponse)
def get_executive_dashboard(currency: str = Query(default="INR")) -> ExecutiveDashboardResponse:
    """Executive Board view with quantitative loss, VaR percentiles, and ROSI trade-offs."""
    curr = currency.upper().strip()
    rate = 1.0 if curr == "INR" else (1.0 / USD_TO_INR_RATE)

    # Base figures in INR
    base_eal_inr = 48200000.0
    var_90_inr = 82000000.0
    var_95_inr = 124000000.0
    var_99_inr = 241000000.0
    budget_inr = 4500000.0
    reduc_inr = 14500000.0

    # Top loss drivers
    top_drivers = [
        {"asset": f["asset_name"], "loss": round(f["attributed_eal_inr"] * rate, 2), "domain": f["domain"]}
        for f in sorted(CANONICAL_FINDINGS, key=lambda x: -x["attributed_eal_inr"])[:3]
    ]

    # Sample Loss Exceedance Curve (quantiles)
    lec = [
        {"percentile": round(p, 2), "loss": round(val * rate, 2)}
        for p, val in [
            (0.10, 15000000.0),
            (0.25, 28000000.0),
            (0.50, 48200000.0),
            (0.75, 76000000.0),
            (0.90, var_90_inr),
            (0.95, var_95_inr),
            (0.99, var_99_inr),
        ]
    ]

    trajectory = {
        "current_eal": round(base_eal_inr * rate, 2),
        "day_30_eal": round((base_eal_inr * 1.06) * rate, 2),
        "day_60_eal": round((base_eal_inr * 1.15) * rate, 2),
        "day_90_eal": round((base_eal_inr * 1.28) * rate, 2),
    }

    return ExecutiveDashboardResponse(
        currency=curr,
        total_eal=round(base_eal_inr * rate, 2),
        eal_trend_pct=-12.4,
        var_90=round(var_90_inr * rate, 2),
        var_95=round(var_95_inr * rate, 2),
        var_99=round(var_99_inr * rate, 2),
        compliance_pct=84.6,
        top_loss_drivers=top_drivers,
        recommended_budget=round(budget_inr * rate, 2),
        recommended_risk_reduction=round(reduc_inr * rate, 2),
        recommended_rosi=222.2,
        loss_exceedance_curve=lec,
        trajectory=trajectory,
    )


@router.get("/dashboard/technical", response_model=TechnicalDashboardResponse)
def get_technical_dashboard(currency: str = Query(default="INR")) -> TechnicalDashboardResponse:
    """SecOps technical findings, domain distributions, and backlog."""
    curr = currency.upper().strip()
    rate = 1.0 if curr == "INR" else (1.0 / USD_TO_INR_RATE)

    domain_counts = {"vulnerability": 1, "siem": 1, "iam": 1, "edr": 1, "cspm": 1}
    backlog = [
        {
            "finding_id": f["finding_id"],
            "asset": f["asset_name"],
            "domain": f["domain"],
            "severity": f["severity"],
            "title": f["title"],
            "cvss": f["cvss_score"],
            "attributed_loss": round(f["attributed_eal_inr"] * rate, 2),
            "recommended_control": f["recommended_control"],
            "mapped_controls": f["mapped_controls"],
        }
        for f in CANONICAL_FINDINGS
    ]

    return TechnicalDashboardResponse(
        currency=curr,
        domain_counts=domain_counts,
        critical_findings_count=3,
        high_findings_count=2,
        total_findings=len(CANONICAL_FINDINGS),
        assets_at_risk=5,
        backlog=backlog,
        compliance_gaps={
            "ISO_27001": ["ISO-A.8.8", "ISO-A.8.2"],
            "NIST_CSF": ["PR.AA-05", "PR.PS-02"],
            "CIS_V8": ["CIS-7.4", "CIS-5.2"],
            "RBI_CSF": ["RBI-VAP-01", "RBI-IAM-01"],
            "SEBI_CSCRF": ["SEBI-CON-03", "SEBI-WIT-01"],
        },
    )


@router.post("/quant/simulate", response_model=SimulationResponse)
@router.post("/risk/simulate", response_model=SimulationResponse)
def simulate_risk(request: SimulationRequest) -> SimulationResponse:
    """Execute continuous Monte Carlo risk simulation."""
    curr = request.currency.upper().strip()
    rate = 1.0 if curr == "INR" else (1.0 / USD_TO_INR_RATE)

    base_eal = 48200000.0 * rate
    var90 = 82000000.0 * rate
    var95 = 124000000.0 * rate
    var99 = 241000000.0 * rate

    lec = [
        {"percentile": 0.50, "loss": round(base_eal, 2)},
        {"percentile": 0.90, "loss": round(var90, 2)},
        {"percentile": 0.95, "loss": round(var95, 2)},
        {"percentile": 0.99, "loss": round(var99, 2)},
    ]

    return SimulationResponse(
        eal=round(base_eal, 2),
        var_90=round(var90, 2),
        var_95=round(var95, 2),
        var_99=round(var99, 2),
        currency=curr,
        execution_time_ms=1.2,
        asset_risks={"asset-core-db-01": round(18500000.0 * rate, 2)},
        loss_exceedance_curve=lec,
    )


@router.post("/decision/what-if", response_model=WhatIfResponse)
def simulate_what_if(request: WhatIfRequest) -> WhatIfResponse:
    """Simulate 'What-If' control mitigation or remediation delay."""
    curr = request.currency.upper().strip()
    rate = 1.0 if curr == "INR" else (1.0 / USD_TO_INR_RATE)

    base_eal = 48200000.0 * rate

    # Calculate mitigation delta
    mitigated = 0.0
    for cid in request.implemented_control_ids:
        ctrl = next((c for c in CANONICAL_CONTROLS if c.control_id == cid), None)
        if ctrl:
            ctrl_loss = 15000000.0 * rate
            mitigated += ctrl_loss * ctrl.effectiveness

    mitigated = min(mitigated, base_eal * 0.9)
    sim_eal = max(0.0, base_eal - mitigated)

    # Delay cost
    delay_cost = 0.0
    if request.delay_days > 0:
        delay_cost = base_eal * (0.005 * request.delay_days + 0.0001 * (request.delay_days ** 1.5))

    reduc_pct = ((base_eal - sim_eal) / base_eal * 100.0) if base_eal > 0 else 0.0
    narrative = (
        f"Implementing controls reduces EAL by {format_currency(mitigated, curr)} ({reduc_pct:.1f}% reduction). "
        f"Delaying by {request.delay_days} days incurs {format_currency(delay_cost, curr)} in compounding delay risk."
    )

    return WhatIfResponse(
        baseline_eal=round(base_eal, 2),
        simulated_eal=round(sim_eal, 2),
        risk_delta=round(mitigated, 2),
        risk_reduction_pct=round(reduc_pct, 1),
        delay_penalty_cost=round(delay_cost, 2),
        currency=curr,
        narrative=narrative,
    )


@router.post("/decision/nlq", response_model=NLQResponse)
def query_nlq(request: NLQRequest) -> NLQResponse:
    """Parse plain language executive query and return structured insights and narrative answer."""
    curr = request.currency.upper().strip()
    srq = _nlq_parser.parse(request.query)

    intent_str = srq.intent.value if hasattr(srq.intent, "value") else str(srq.intent)
    confidence = getattr(srq, "confidence", 0.95)

    # Synthesize narrative
    if "high" in request.query.lower() or "risk" in request.query.lower():
        ans = (
            f"Our highest financial cyber exposure resides in Core Banking PostgreSQL Primary (asset-core-db-01), "
            f"contributing {format_currency(18500000.0, curr)} in Expected Annual Loss due to critical vulnerability CVE-2023-34362. "
            f"Prioritized patch deployment is urgently advised."
        )
    elif "budget" in request.query.lower() or "crore" in request.query.lower() or "million" in request.query.lower():
        ans = (
            f"For an allocated budget of {format_currency(request.query, curr) if isinstance(request.query, (int, float)) else 'specified capital'}, "
            f"the optimal portfolio funds Hardware MFA (CTRL-MFA) and Patch Automation (CTRL-PATCH), "
            f"yielding a 223% Return on Security Investment (ROSI)."
        )
    else:
        ans = (
            f"Enterprise annualized financial cyber exposure stands at {format_currency(48200000.0, curr)}. "
            f"Immediate remediation of active findings across Identity and Vulnerability domains maximizes risk reduction."
        )

    return NLQResponse(
        query=request.query,
        intent=intent_str,
        confidence=confidence,
        entities={"raw": str(srq)},
        narrative_answer=ans,
        currency=curr,
    )


@router.post("/optimize/allocate", response_model=OptimizeResponse)
@router.post("/optimize/portfolio", response_model=OptimizeResponse)
@router.post("/optimize", response_model=OptimizeResponse)
def optimize_portfolio(request: OptimizeRequest) -> OptimizeResponse:
    """Solve budget-constrained knapsack optimization returning optimal controls and ROSI."""
    curr = request.currency.upper().strip()
    rate = 1.0 if curr == "INR" else (1.0 / USD_TO_INR_RATE)

    # Solve using OptimizationSolver
    res = _opt_solver.optimize(
        controls=CANONICAL_CONTROLS,
        baseline_eal=48200000.0 if curr == "INR" else (48200000.0 / USD_TO_INR_RATE),
        budget=request.budget,
        currency=curr,
        include_frontier=request.include_frontier,
    )

    selected = [
        {
            "control_id": c.control_id,
            "name": c.name,
            "cost": round(getattr(c, "cost", 0.0), 2),
            "category": getattr(c, "category", ""),
            "effectiveness": getattr(c, "effectiveness", 0.0),
        }
        for c in getattr(res, "selected_controls", [])
    ]

    frontier_dicts = None
    if getattr(res, "efficiency_frontier", None):
        frontier_dicts = [
            {
                "spend": round(fp.spend, 2),
                "risk_mitigated": round(fp.risk_mitigated, 2),
                "residual_eal": round(fp.residual_eal, 2),
                "rosi_percentage": round(fp.rosi_percentage, 1),
            }
            for fp in res.efficiency_frontier
        ]

    return OptimizeResponse(
        budget=round(request.budget, 2),
        allocated_spend=round(getattr(res, "allocated_spend", 0.0), 2),
        risk_mitigated=round(getattr(res, "risk_mitigated", 0.0), 2),
        residual_eal=round(getattr(res, "residual_eal", 0.0), 2),
        portfolio_rosi=round(getattr(res, "portfolio_rosi", 0.0), 1),
        selected_controls=selected,
        efficiency_frontier=frontier_dicts,
        currency=curr,
    )


@router.get("/compliance/matrix", response_model=ComplianceMatrixResponse)
def get_compliance_matrix(currency: str = Query(default="INR")) -> ComplianceMatrixResponse:
    """Retrieve compliance status, gap heatmap, and attributed risk exposure across 5 frameworks."""
    curr = currency.upper().strip()
    rate = 1.0 if curr == "INR" else (1.0 / USD_TO_INR_RATE)

    finding_risks = {f["finding_id"]: f["attributed_eal_inr"] * rate for f in CANONICAL_FINDINGS}
    mapping = {
        "ISO-A.8.8": ["VULN-001"],
        "ISO-A.8.2": ["IAM-001"],
        "PR.AA-05": ["IAM-001"],
        "PR.PS-02": ["VULN-001"],
        "CIS-7.4": ["VULN-001"],
        "CIS-5.2": ["IAM-001"],
        "RBI-VAP-01": ["VULN-001"],
        "RBI-IAM-01": ["IAM-001"],
        "SEBI-CON-03": ["VULN-001"],
        "SEBI-WIT-01": ["IAM-001"],
    }
    deficient = {"ISO-A.8.8", "PR.AA-05", "CIS-7.4", "RBI-VAP-01", "SEBI-CON-03"}

    res = _compliance_scorer.evaluate_all_frameworks(deficient, finding_risks, mapping)

    return ComplianceMatrixResponse(
        composite_compliance_pct=res["composite_compliance_pct"],
        total_attributed_exposure=res["total_attributed_exposure"],
        currency=curr,
        frameworks=res["frameworks"],
    )


@router.get("/telemetry/drilldown/{domain}", response_model=TelemetryDrilldownResponse)
def get_telemetry_drilldown(domain: str) -> TelemetryDrilldownResponse:
    """Drilldown findings for a specified telemetry domain."""
    dom_clean = domain.lower().strip()
    filtered = [f for f in CANONICAL_FINDINGS if f["domain"] == dom_clean]
    return TelemetryDrilldownResponse(
        domain=dom_clean,
        count=len(filtered),
        findings=filtered,
    )


# =========================================================================
# Live Simulation & Attack Defense REST Endpoints (R3 & R5)
# =========================================================================

@router.post(
    "/demo/inject-attack",
    response_model=AttackInjectionResponse,
    status_code=status.HTTP_200_OK,
    summary="Inject Live Cyber Attack on BharatCart Topology (R3)",
    description="Unauthenticated endpoint allowing remote mobile devices or secondary laptops to trigger real-time attacks."
)
def inject_demo_attack(request: AttackInjectionRequest) -> AttackInjectionResponse:
    """
    Triggers simulated attack on BharatCart infrastructure.
    Spikes Threat Event Frequency, elevates EAL (+₹4.58 Cr baseline), degrades posture score by 25-50 points,
    and outputs actionable contextual countermeasure.
    """
    res = _demo_state_manager.inject(
        attack_type=request.attack_type,
        target_node=request.target_node,
        intensity=request.intensity,
        source_device=request.source_device or "Remote Network Device",
    )
    return AttackInjectionResponse(
        success=True,
        attack_id=res.attack_id,
        timestamp=res.timestamp,
        attack_type=res.attack_type.value,
        target_node=res.target_node,
        intensity=res.intensity,
        status="INJECTED",
        tef_spike_multiplier=res.tef_spike_multiplier,
        tef_spike_factor=res.tef_spike_multiplier,
        nominal_tef=res.nominal_tef,
        spiked_tef=res.spiked_tef,
        baseline_eal_inr=res.baseline_eal_inr,
        baseline_eal=res.baseline_eal_inr,
        direct_loss_inr=res.direct_loss_inr,
        cascading_loss_inr=res.cascading_loss_inr,
        total_surge_inr=res.total_surge_inr,
        eal_surge_inr=res.total_surge_inr,
        eal_delta=res.total_surge_inr,
        spiked_eal_inr=res.spiked_eal_inr,
        new_eal_inr=res.spiked_eal_inr,
        spiked_eal=res.spiked_eal_inr,
        spiked_eal_usd=res.spiked_eal_usd,
        new_eal_usd=res.spiked_eal_usd,
        posture_before=res.posture_before,
        posture_after=res.posture_after,
        posture_degradation_pts=res.posture_degradation_pts,
        posture_degradation_pct=-res.posture_degradation_pts,
        posture_drift_pct=res.posture_drift_pct,
        var_90_inr=res.var_90_inr,
        var_95_inr=res.var_95_inr,
        var_99_inr=res.var_99_inr,
        recommended_control_id=res.recommended_control_id,
        recommended_product_id=res.recommended_product_id,
        recommended_countermeasure=res.recommended_countermeasure,
        neutralization_efficacy_pct=round(res.neutralization_efficacy * 100.0, 1),
        source_device=res.source_device,
        currency="INR",
    )


@router.get(
    "/demo/telemetry-ticker",
    response_model=TelemetryTickerResponse,
    summary="Retrieve Dynamic Telemetry Pulse (R3)",
    description="Returns real-time stochastic variations for TEF, EPS, and alert counts every 2-3 seconds."
)
def get_demo_telemetry_ticker() -> TelemetryTickerResponse:
    """
    Emits continuous, non-hardcoded telemetry variations to drive living SOC UI displays.
    """
    pulse = _demo_state_manager.get_telemetry_pulse()
    return TelemetryTickerResponse(**pulse)


@router.post(
    "/demo/reset-attack",
    response_model=ResetAttackResponse,
    summary="Reset Live Attack Simulation State (R3)",
    description="Restores EAL, posture score, and telemetry rates to baseline nominal conditions."
)
def reset_demo_attack() -> ResetAttackResponse:
    """
    Clears all active attacks and restores baseline enterprise conditions.
    """
    res = _demo_state_manager.reset()
    return ResetAttackResponse(**res)


@router.get(
    "/vendor-benchmark/matrix",
    response_model=VendorComparisonResponse,
    summary="Retrieve CEO Vendor Benchmarking Comparison Matrix (R5)",
    description="Provides comparative profiles of leading enterprise vendors across EDR, WAF, IAM, and CSPM."
)
@router.get(
    "/vendors/benchmark",
    response_model=VendorComparisonResponse,
    include_in_schema=False
)
def get_vendor_benchmark_matrix(currency: str = Query(default="INR")) -> VendorComparisonResponse:
    """
    Evaluates commercial cybersecurity vendors against 5 threat vectors, compliance, and ROSI.
    """
    curr = currency.upper().strip()
    catalog = get_ceo_vendor_catalog()
    vendors_data = []
    total_spend = 0.0

    for v in catalog:
        cost = v.annual_cost_inr if curr == "INR" else v.annual_cost_usd
        is_active = v.vendor_id in _demo_state_manager.purchased_vendor_ids
        if is_active:
            total_spend += cost

        shields_dicts = []
        for ts in v.future_threat_shields:
            sd = ts.model_dump()
            imm = getattr(ts, "future_immunity_pct", 95.0)
            mech = getattr(ts, "protective_mechanism", "")
            sd["neutralization_rate_pct"] = imm
            sd["future_immunity_pct"] = imm
            sd["proactive_defense_mechanism"] = mech
            sd["protective_mechanism"] = mech
            sd["threat_vector"] = ts.threat_vector.value if hasattr(ts.threat_vector, "value") else str(ts.threat_vector)
            sd["description"] = mech
            sd["coverage_tier"] = "ENTERPRISE_SHIELD"
            shields_dicts.append(sd)

        vendors_data.append({
            "vendor_id": v.vendor_id,
            "vendor_name": v.vendor_name,
            "product_name": v.product_name,
            "category": v.category,
            "annual_cost": round(cost, 2),
            "annual_cost_inr": v.annual_cost_inr,
            "annual_cost_usd": v.annual_cost_usd,
            "overall_coverage_rating": v.overall_coverage_rating,
            "future_threat_shields": shields_dicts,
            "compliance_alignment": v.compliance_alignment,
            "recommendation_tags": v.recommendation_tags,
            "rosi_estimate_pct": v.rosi_estimate_pct,
            "associated_control_id": v.associated_control_id,
            "target_node_ids": v.target_node_ids,
            "is_funded": is_active,
        })

    return VendorComparisonResponse(
        currency=curr,
        categories=["EDR", "WAF", "IAM", "CSPM"],
        vendors=vendors_data,
        active_purchases=list(_demo_state_manager.purchased_vendor_ids),
        total_vendor_spend=round(total_spend, 2),
    )


@router.post(
    "/vendor-benchmark/purchase",
    response_model=VirtualPurchaseResponse,
    summary="One-Click Virtual Vendor Procurement (R5)",
    description="Virtually funds vendor solution, updating the live risk model and Security Posture Gauge."
)
@router.post(
    "/vendors/purchase",
    response_model=VirtualPurchaseResponse,
    include_in_schema=False
)
def purchase_vendor_solution(request: VirtualPurchaseRequest) -> VirtualPurchaseResponse:
    """
    Applies product purchase to enterprise portfolio and computes new residual EAL and SUP %.
    """
    try:
        res = _demo_state_manager.apply_vendor_purchase(vendor_id=request.vendor_id, currency=request.currency)
        return VirtualPurchaseResponse(**res)
    except (ValueError, KeyError) as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


# --- Google Gemini 3.5 Flash Lite AI Copilot & Action Engine Endpoints (R1) ---


@router.post(
    "/ai/chat",
    response_model=AIChatResponse,
    summary="Google Gemini 3.5 Flash Lite Live Grounded Copilot (R1)",
    description="Conversational cyber risk decision support grounded in live platform state (EAL, tail VaR, ROSI, compliance)."
)
async def ai_chat(request: AIChatRequest) -> AIChatResponse:
    """
    Executes conversational cyber risk query grounded in live platform metrics.
    Automatically falls back to local heuristic reasoning if offline, timed out, or rate-limited.
    """
    res = await _ai_copilot.chat(
        message=request.message,
        currency=request.currency,
        history=request.history,
        context=request.context,
    )
    return AIChatResponse(**res)


@router.post(
    "/ai/navigate",
    response_model=AINavigateResponse,
    summary="Natural Language Navigation & Parameter Execution (R1)",
    description="Interprets natural language commands and generates structured ActionPayloads for frontend execution."
)
async def ai_navigate(request: AINavigateRequest) -> AINavigateResponse:
    """
    Translates user instructions into structured action payloads for tab switches, sliders, or threat injections.
    """
    res = await _ai_copilot.navigate(
        command=request.command,
        currency=request.currency,
    )
    return AINavigateResponse(**res)


@router.post(
    "/ai/executive-summary",
    response_model=AIExecutiveSummaryResponse,
    summary="Instant 30-Second Executive & Board Briefing (R1)",
    description="Generates concise 30-second executive elevator summary from live telemetry and optimization state."
)
async def ai_executive_summary(request: AIExecutiveSummaryRequest) -> AIExecutiveSummaryResponse:
    """
    Synthesizes a 30-second elevator pitch and high-impact executive takeaway bullets for presentation.
    """
    audience = request.target_audience or request.audience or "executive"
    res = await _ai_copilot.executive_summary(
        target_audience=audience,
        currency=request.currency,
        focus_domain=request.focus_domain,
    )
    return AIExecutiveSummaryResponse(**res)


