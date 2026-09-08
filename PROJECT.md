# Project: CyberRiskQuant — Enterprise Cyber Risk Quantification & Investment Optimization Platform

## Architecture
CyberRiskQuant is an AI-powered, continuous cyber risk quantification and investment optimization platform. It bridges technical security telemetry across 5 domains with business financial reality using the Factor Analysis of Information Risk (FAIR) standard, high-performance vectorized Monte Carlo simulation, Mixed-Integer Linear Programming (MILP) budget optimization, and predictive AI decision support.

```
+-----------------------------------------------------------------------------------+
|                           Dual Responsive Dashboard                                |
|   [Executive / Board View]                    [Technical SecOps View]             |
|   - Monetary Exposure (EAL, VaR 90/95/99)      - 5-Domain Telemetry Drill-Downs    |
|   - Loss Exceedance Curve (LEC)               - Asset Criticality Matrix          |
|   - 90-Day Trajectory Forecast                - Prioritized Remediation Backlog   |
|   - Investment Trade-Off Slider / ROSI        - Regulatory Control Gap Heatmap    |
|   - Plain-Language Executive Summary          - INR (₹) / USD ($) Currency Switch |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                             FastAPI REST API Layer                                |
|   /api/v1/telemetry  /api/v1/assets  /api/v1/quant  /api/v1/decision  /api/v1/optimize |
|   /api/v1/compliance /api/v1/dashboard/executive   /api/v1/dashboard/technical    |
+-----------------------------------------------------------------------------------+
        |                      |                         |                   |
        v                      v                         v                   v
+---------------+      +---------------+         +---------------+   +--------------+
| Ingestion &   |      | FAIR Vector   |         | AI Decision   |   | Budget MILP  |
| Telemetry (5) |----->| Monte Carlo   |-------->| Support & NLQ |-->| Optimization |
| - CVE/EPSS    |      | Engine        |         | - What-If     |   | & ROSI Curve |
| - SIEM Alerts |      | - EAL & VaR   |         | - Trajectory  |   | - HiGHS MILP |
| - IAM Priv    |      | - Poisson/LogN|         | - Delay Cost  |   | - Constraints|
| - EDR Health  |      | - Portfolio   |         | - Intent NLQ  |   | - Pareto     |
| - CSPM Cloud  |      |   Aggregation |         |   Engine      |   |   Frontier   |
+---------------+      +---------------+         +---------------+   +--------------+
        ^                      ^                         ^                   ^
        |                      |                         |                   |
+-----------------------------------------------------------------------------------+
|               Asset Criticality DAG & Business Dependency Engine                  |
|   - NetworkX Dependency Graph & Upstream Revenue-at-Risk Percolation              |
|   - Data Sensitivity Tiers (Public, Internal, Confidential, Restricted/PCI-DSS)   |
|   - Dynamic Asset Criticality Score (ACS) altering Finding Impact (>7,000x)       |
+-----------------------------------------------------------------------------------+
        ^
        |
+-----------------------------------------------------------------------------------+
|            Bidirectional Regulatory Compliance Framework Catalog                  |
|   - ISO/IEC 27001 (A.5, A.8, A.12, A.14)      - RBI Cyber Security Framework      |
|   - NIST CSF 2.0 (Govern, Protect, etc.)      - SEBI CSCRF (Anticipate, etc.)     |
|   - CIS Controls v8 (18 Control Categories)   - Financial Exposure (sum EAL)      |
+-----------------------------------------------------------------------------------+
```

---

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F01 | Multi-Domain Telemetry Schemas | Pydantic v2 schemas for CVE/EPSS, SIEM, IAM, EDR, CSPM | M1 | R1 |
| F02 | Extensible Telemetry Ingestion Adapters | Abstract base adapter supporting JSON, CSV, and REST ingestion | M1 | R1 |
| F03 | Synthetic Telemetry Data Generator | ApexGlobal Financial Corp realistic multi-BU telemetry dataset | M1 | R1 |
| F04 | Business Asset Valuation & Sensitivity Model | 4-tier data sensitivity multipliers & financial asset valuation | M1 | R1 |
| F05 | Business Service Dependency DAG | NetworkX dependency graph with upstream revenue percolation | M1 | R1 |
| F06 | Dynamic Criticality Impact Modifier | Dynamic finding impact modifier altering identical findings | M1 | R1 |
| F07 | Telemetry to FAIR Parameter Translation | Conversion of telemetry signals into TEF, TCap, RS, Vuln, LEF | M2 | R2 |
| F08 | Vectorized Monte Carlo Loss Simulation | Compound Poisson-LogNormal / Beta-PERT simulation (<2ms/10k) | M2 | R2 |
| F09 | Financial Risk Metrics (EAL & VaR) | Positive EAL, strictly ordered VaR 90 < VaR 95 < VaR 99 | M2 | R2 |
| F10 | Multi-Level Portfolio Aggregation | Asset, BU, and Enterprise portfolio aggregation with tail risk | M2 | R2 |
| F11 | Deterministic Seed Reproducibility | Bit-exact reproducibility when seeded with identical seed | M2 | R2 |
| F12 | Predictive Threat Trajectory Forecasting | 30/60/90-day risk forecasting with EPSS velocity/acceleration | M3 | R3 |
| F13 | Interactive What-If Scenario Simulation | Concrete monetary delta (delta EAL/VaR) using Common Random Numbers | M3 | R3 |
| F14 | Compounding Delayed Remediation Cost | Cost of delay modeling cumulative loss + breach hazard surge | M3 | R3 |
| F15 | Deterministic Natural Language Query Parser | Leadership query intent & currency slot extraction (INR/USD) | M3 | R3 |
| F16 | Executive Narrative Summary Generator | Plain-language risk overview and actionable recommendations | M3 | R3 |
| F17 | Multi-Constraint MILP Knapsack Solver | SciPy HiGHS MILP solver with pure-Python fallback | M4 | R4 |
| F18 | Strict Budget Ceiling Enforcement | Allocations strictly obey user-defined budget limits | M4 | R4 |
| F19 | Advanced Control Constraint System | Dependencies, mutual exclusivity, and mandatory baselines | M4 | R4 |
| F20 | Financial Optimization Metrics | Explicit ROSI %, Net Financial Benefit, and marginal cost-benefit | M4 | R4 |
| F21 | Pareto Efficiency Frontier Generator | Parametric budget sweep generating diminishing returns curve | M4 | R4 |
| F22 | ISO/IEC 27001 Control Catalog & Mapping | Complete control definitions and bidirectional telemetry mapping | M5 | R5 |
| F23 | NIST CSF 2.0 Control Catalog & Mapping | 6 functions (Govern, Identify, Protect, Detect, Respond, Recover) | M5 | R5 |
| F24 | CIS Controls v8 Catalog & Mapping | 18 control categories mapped to finding mitigations | M5 | R5 |
| F25 | RBI Cyber Security Framework Mapping | Governance, IAM, network security for financial institutions | M5 | R5 |
| F26 | SEBI CSCRF Regulatory Mapping | Anticipate, Withstand, Contain, Recover, Evolve cyber resilience | M5 | R5 |
| F27 | Compliance Scoring & Exposure Attribution | Quantitative compliance score and non-compliant sum(EAL) attribution | M5 | R5 |
| F28 | Executive / Board View Dashboard | Financial KPIs, VaR distribution, LEC, trends, ROSI slider | M5 | R5 |
| F29 | Technical SecOps View Dashboard | 5-domain drilldowns, asset matrix, backlog, regulatory heatmap | M5 | R5 |
| F30 | Currency Switch & Responsive UI | INR (₹ Lakhs/Crores) and USD ($ Millions) toggle, dark/light theme | M5 | R5 |
| F31 | Unified FastAPI REST API Backend | Comprehensive Pydantic endpoints serving all engines | M5 | R5 |
| F32 | Automated Pytest Verification Suite | 100% passing tests across all functional & mathematical invariants | M-Final | R6 |

---

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Telemetry Ingestion & Asset Criticality Engine | F01-F06: 5-domain schemas, ingestion adapters, synthetic generator, NetworkX asset DAG, dynamic impact modifier | none | DONE |
| M2 | FAIR Continuous Risk Quantification Engine | F07-F11: FAIR ontology translation, vectorized Monte Carlo loss engine, EAL, VaR 90/95/99, portfolio aggregation, seed determinism | M1 | DONE |
| M3 | AI Decision Support, What-If & NLQ Engine | F12-F16: 30/60/90d threat trajectory, What-If monetary delta with CRN, delay cost, deterministic NLQ parser, narrative generator | M2 | DONE |
| M4 | Budget-Constrained Optimization (ROSI) Engine | F17-F21: SciPy HiGHS MILP knapsack, budget enforcement, control constraints, ROSI %, Pareto frontier with diminishing returns | M2 | DONE |
| M5 | Dashboards, Compliance Frameworks & API Layer | F22-F31: 5 regulatory catalogs & scoring, dual responsive dashboard (Executive + SecOps), INR/USD currency, FastAPI backend | M1, M2, M3, M4 | PLANNED |
| M-Final | E2E 100% Test Pass & Adversarial Hardening | F32: Pass 100% E2E test suites (Tiers 1-4) & adversarial test hardening (Tier 5) | M1, M2, M3, M4, M5, E2E-Track | PLANNED |

---

## Interface Contracts

### M1 ↔ M2 (Telemetry & Assets -> FAIR Monte Carlo)
- `AssetCatalog`: Dict[str, AssetRecord] where `AssetRecord` includes `asset_id`, `name`, `business_unit`, `asset_criticality_score: float`, `data_sensitivity_tier: str`, `replacement_cost: float`, `downtime_cost_per_hour: float`, `dependent_services: List[str]`.
- `NormalizedFinding`: `finding_id`, `asset_id`, `domain: TelemetryDomain`, `severity: SeverityLevel`, `cvss_score: float`, `epss_score: float`, `cisa_kev: bool`, `threat_event_frequency: float`, `resistance_strength: float`, `exploit_maturity: str`.
- Output of M2: `SimulationResult` containing `eal: float`, `var_90: float`, `var_95: float`, `var_99: float`, `loss_distribution: List[float]`, `loss_exceedance_curve: List[Tuple[float, float]]`, `asset_risks: Dict[str, AssetRiskSummary]`.

### M2 ↔ M3 (FAIR Engine -> What-If & Decision Support)
- Function `run_counterfactual_simulation(baseline_findings, mitigated_findings, seed=42) -> WhatIfResult`:
  Returns `delta_eal: float`, `delta_var_95: float`, `baseline_eal: float`, `mitigated_eal: float`, `risk_reduction_pct: float`.
- Function `calculate_delay_cost(findings, days_delay: int) -> DelayCostResult`:
  Returns `total_delay_penalty: float`, `breach_probability_surge: float`, `daily_loss_gradient: float`.

### M2 ↔ M4 (FAIR Engine -> Optimization & ROSI)
- `CandidateControl`: `control_id: str`, `name: str`, `category: str`, `cost: float`, `target_finding_ids: List[str]`, `effectiveness: float (0-1)`, `prerequisites: List[str]`, `conflicts: List[str]`, `is_mandatory: bool`.
- Function `optimize_investments(controls: List[CandidateControl], budget: float, baseline_eal: float) -> OptimizationResult`:
  Returns `allocated_spend: float`, `selected_controls: List[CandidateControl]`, `risk_mitigated: float`, `residual_eal: float`, `portfolio_rosi: float`, `efficiency_frontier: List[FrontierPoint]`.

### M1..M4 ↔ M5 (Engines -> Dashboards & API)
- FastAPI endpoints exposed under `/api/v1/`:
  - `GET /api/v1/dashboard/executive` -> `ExecutiveDashboardResponse`
  - `GET /api/v1/dashboard/technical` -> `TechnicalDashboardResponse`
  - `POST /api/v1/decision/what-if` -> `WhatIfResponse`
  - `POST /api/v1/decision/nlq` -> `NLQQueryResponse`
  - `POST /api/v1/optimize/portfolio` -> `OptimizationResponse`
  - `GET /api/v1/compliance/matrix` -> `ComplianceMatrixResponse`
  - `GET /api/v1/telemetry/drilldown/{domain}` -> `TelemetryDrilldownResponse`

---

## Code Layout
```
src/
├── __init__.py
├── config.py
├── telemetry/
│   ├── __init__.py
│   ├── models.py             # Pydantic schemas for 5 domains
│   ├── adapters.py           # Base and format-specific adapters
│   ├── normalizer.py         # Data normalization logic
│   └── generator.py          # ApexGlobal synthetic dataset generator
├── assets/
│   ├── __init__.py
│   ├── models.py             # Asset valuation and criticality schemas
│   ├── graph.py              # NetworkX DAG dependency & percolation engine
│   └── scoring.py            # Dynamic Asset Criticality Scoring (ACS)
├── quant/
│   ├── __init__.py
│   ├── fair_mapper.py        # Telemetry to FAIR parameter mapping
│   ├── monte_carlo.py        # Vectorized Compound Poisson-LogNormal engine
│   └── portfolio.py          # Multi-level asset, BU, and enterprise aggregation
├── decision_support/
│   ├── __init__.py
│   ├── trajectory.py         # 30/60/90-day predictive threat trajectory
│   ├── what_if.py            # What-If scenario simulation with CRN
│   ├── delay_cost.py         # Compound delayed remediation cost model
│   └── nlq_parser.py         # Deterministic grammar & regex query parser
├── optimization/
│   ├── __init__.py
│   ├── solver.py             # SciPy HiGHS MILP knapsack & B&B fallback
│   ├── rosi.py               # Financial ROSI and marginal cost-benefit
│   └── frontier.py           # Pareto efficiency frontier curve generator
├── compliance/
│   ├── __init__.py
│   ├── catalog.py            # ISO 27001, NIST CSF, CIS, RBI, SEBI catalogs
│   ├── mapper.py             # Telemetry-to-control bidirectional mapping
│   └── scoring.py            # Compliance percentage & financial risk attribution
├── api/
│   ├── __init__.py
│   ├── app.py                # FastAPI application setup
│   ├── routes.py             # REST API routes
│   └── schemas.py            # Request/Response Pydantic DTOs
└── dashboard/
    ├── __init__.py
    ├── app.py                # UI static file & template server
    ├── templates/
    │   └── index.html        # Unified Executive & SecOps Responsive Dashboard
    └── static/
        ├── css/dashboard.css # Clean dark/light enterprise CSS (self-contained)
        └── js/dashboard.js   # Interactive charts, currency toggle, NLQ, sliders (self-contained)
tests/
├── conftest.py               # Shared fixtures and mock datasets
├── unit/
│   ├── test_telemetry.py
│   ├── test_assets.py
│   ├── test_quant.py
│   ├── test_decision_support.py
│   ├── test_optimization.py
│   └── test_compliance.py
├── invariants/
│   ├── test_monte_carlo_invariants.py
│   └── test_optimization_invariants.py
├── e2e/
│   ├── test_tier1_feature_coverage.py
│   ├── test_tier2_boundary_corner.py
│   ├── test_tier3_pairwise_combinations.py
│   └── test_tier4_real_world_scenarios.py
└── api/
    └── test_api_contracts.py
```
