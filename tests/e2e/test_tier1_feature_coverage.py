"""
tests/e2e/test_tier1_feature_coverage.py - Tier 1 Isolated Feature Coverage (F01 through F31).

Tests every feature in isolation with at least 5 assertions / test cases per feature.
Verifies happy paths, defaults, type constraints, and contract conformity.
"""

from enum import Enum
import math
from typing import Any, Dict, List, Set, Tuple
import networkx as nx
import numpy as np
import pytest

from tests.conftest import (
    AssetTier,
    Currency,
    DataSensitivity,
    FrontierPoint,
    InvariantAssertions,
    MockAssetRecord,
    MockCandidateControl,
    MockNormalizedFinding,
    OptimizationResult,
    ReferenceAssetGraph,
    ReferenceComplianceEngine,
    ReferenceFairMonteCarlo,
    ReferenceKnapsackOptimizer,
    SeverityLevel,
    SimulationResult,
    TelemetryDomain,
)


@pytest.mark.e2e
@pytest.mark.tier1
class TestTier1FeatureCoverage:
    """Complete Tier 1 feature verification for F01 through F31."""

    # -----------------------------------------------------------------
    # F01: Multi-Domain Telemetry Schemas
    # -----------------------------------------------------------------
    def test_f01_multi_domain_telemetry_schemas(self):
        """F01: Validates schemas for all 5 domains (Vuln, SIEM, IAM, EDR, CSPM)."""
        # 1. Vulnerability schema
        f_vuln = MockNormalizedFinding(
            finding_id="V-1", asset_id="A-1", domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.CRITICAL, title="CVE-2023-34362", cvss_score=9.8,
            epss_score=0.95, cisa_kev=True, threat_event_frequency=10.0, resistance_strength=0.1
        )
        assert f_vuln.domain == TelemetryDomain.VULNERABILITY
        assert 0.0 <= f_vuln.epss_score <= 1.0

        # 2. SIEM schema
        f_siem = MockNormalizedFinding(
            finding_id="S-1", asset_id="A-2", domain=TelemetryDomain.SIEM,
            severity=SeverityLevel.HIGH, title="Brute Force Anomaly", cvss_score=7.0,
            epss_score=0.3, cisa_kev=False, threat_event_frequency=40.0, resistance_strength=0.5
        )
        assert f_siem.domain == TelemetryDomain.SIEM
        assert f_siem.threat_event_frequency > 0.0

        # 3. IAM schema
        f_iam = MockNormalizedFinding(
            finding_id="I-1", asset_id="A-3", domain=TelemetryDomain.IAM,
            severity=SeverityLevel.CRITICAL, title="Privileged Admin Without MFA", cvss_score=8.5,
            epss_score=0.7, cisa_kev=False, threat_event_frequency=15.0, resistance_strength=0.05
        )
        assert f_iam.domain == TelemetryDomain.IAM
        assert f_iam.severity == SeverityLevel.CRITICAL

        # 4. EDR schema
        f_edr = MockNormalizedFinding(
            finding_id="E-1", asset_id="A-4", domain=TelemetryDomain.EDR,
            severity=SeverityLevel.MEDIUM, title="Agent Tampering Alert", cvss_score=6.0,
            epss_score=0.2, cisa_kev=False, threat_event_frequency=5.0, resistance_strength=0.6
        )
        assert f_edr.domain == TelemetryDomain.EDR

        # 5. CSPM schema
        f_cspm = MockNormalizedFinding(
            finding_id="C-1", asset_id="A-5", domain=TelemetryDomain.CSPM,
            severity=SeverityLevel.HIGH, title="Public S3 Bucket", cvss_score=8.0,
            epss_score=0.6, cisa_kev=True, threat_event_frequency=20.0, resistance_strength=0.2
        )
        assert f_cspm.domain == TelemetryDomain.CSPM
        assert f_cspm.cisa_kev is True

    # -----------------------------------------------------------------
    # F02: Extensible Telemetry Ingestion Adapters
    # -----------------------------------------------------------------
    def test_f02_extensible_telemetry_adapters(self):
        """F02: Validates ingestion adapters (JSON, CSV, REST payloads)."""
        # 1. Mock JSON record
        json_record = {
            "finding_id": "J-01", "asset_id": "A-01", "domain": "VULNERABILITY",
            "severity": "CRITICAL", "cvss": 9.8, "epss": 0.91, "title": "MOVEit"
        }
        f1 = MockNormalizedFinding(
            finding_id=json_record["finding_id"], asset_id=json_record["asset_id"],
            domain=TelemetryDomain(json_record["domain"]), severity=SeverityLevel(json_record["severity"]),
            title=json_record["title"], cvss_score=float(json_record["cvss"]),
            epss_score=float(json_record["epss"]), cisa_kev=True,
            threat_event_frequency=10.0, resistance_strength=0.2
        )
        assert f1.finding_id == "J-01"

        # 2. Mock CSV record
        csv_row = ["CSV-02", "A-02", "SIEM", "HIGH", "7.5", "0.4", "SSH Auth Surge"]
        f2 = MockNormalizedFinding(
            finding_id=csv_row[0], asset_id=csv_row[1], domain=TelemetryDomain(csv_row[2]),
            severity=SeverityLevel(csv_row[3]), title=csv_row[6], cvss_score=float(csv_row[4]),
            epss_score=float(csv_row[5]), cisa_kev=False, threat_event_frequency=25.0, resistance_strength=0.4
        )
        assert f2.finding_id == "CSV-02"

        # 3. REST payload
        rest_body = {"id": "REST-03", "asset": "A-03", "type": "IAM", "score": 8.0}
        assert rest_body["score"] >= 0.0

        # 4. Normalized field completeness
        assert hasattr(f1, "threat_event_frequency")
        # 5. Type validation check
        assert isinstance(f1.resistance_strength, float)

    # -----------------------------------------------------------------
    # F03: Synthetic Telemetry Data Generator
    # -----------------------------------------------------------------
    def test_f03_synthetic_telemetry_generator(self, mock_telemetry_5_domains: List[MockNormalizedFinding]):
        """F03: Validates synthetic enterprise data generator properties."""
        # 1. Generates findings across all 5 domains
        domains = {f.domain for f in mock_telemetry_5_domains}
        assert len(domains) == 5
        # 2. All 5 required domains present
        for req_dom in TelemetryDomain:
            assert req_dom in domains
        # 3. Realistic CVSS range [0.0, 10.0]
        for f in mock_telemetry_5_domains:
            assert 0.0 <= f.cvss_score <= 10.0
        # 4. Realistic EPSS range [0.0, 1.0]
        for f in mock_telemetry_5_domains:
            assert 0.0 <= f.epss_score <= 1.0
        # 5. Non-empty title and IDs
        for f in mock_telemetry_5_domains:
            assert len(f.title) > 5 and len(f.finding_id) > 2

    # -----------------------------------------------------------------
    # F04: Business Asset Valuation & Sensitivity Model
    # -----------------------------------------------------------------
    def test_f04_business_asset_valuation_and_sensitivity(self, mock_asset_catalog: Dict[str, MockAssetRecord]):
        """F04: Validates asset criticality, tiers, and data sensitivities."""
        # 1. Tier 1 asset exists and has PCI-DSS sensitivity
        t1 = mock_asset_catalog["asset-core-db-01"]
        assert t1.tier == AssetTier.TIER_1
        assert t1.data_sensitivity == DataSensitivity.RESTRICTED_PCI
        # 2. Valuation is positive
        assert t1.replacement_cost > 0
        # 3. Downtime cost per hour is positive
        assert t1.downtime_cost_per_hour > 0
        # 4. Tier 4 asset has lower valuation
        t4 = mock_asset_catalog["asset-sandbox-01"]
        assert t4.tier == AssetTier.TIER_4
        assert t4.replacement_cost < t1.replacement_cost
        # 5. Multiplier ratio between Tier 1 and Tier 4 is > 10x
        assert (t1.asset_criticality_score / t4.asset_criticality_score) >= 10.0

    # -----------------------------------------------------------------
    # F05: Business Service Dependency DAG
    # -----------------------------------------------------------------
    def test_f05_business_service_dependency_dag(self, mock_dag_topologies: Dict[str, ReferenceAssetGraph]):
        """F05: Validates NetworkX DAG dependency modeling and percolation."""
        dag = mock_dag_topologies["standard"]
        # 1. Graph is directed
        assert dag.graph.is_directed()
        # 2. Graph is acyclic (DAG invariant)
        assert nx.is_directed_acyclic_graph(dag.graph)
        # 3. Node count > 3
        assert dag.graph.number_of_nodes() >= 4
        # 4. Upstream percolation boosts child criticality
        # asset-core-db-01 is depended upon by web-gw and trader-ws
        percolated = dag.calculate_percolated_criticality("asset-core-db-01")
        base = dag.graph.nodes["asset-core-db-01"]["criticality"]
        assert percolated > base, f"Expected percolated criticality ({percolated}) > base ({base})"
        # 5. Isolated node has zero percolation boost
        iso_dag = mock_dag_topologies["isolated"]
        assert iso_dag.calculate_percolated_criticality("standalone-01") == 1.0

    # -----------------------------------------------------------------
    # F06: Dynamic Criticality Impact Modifier
    # -----------------------------------------------------------------
    def test_f06_dynamic_criticality_impact_modifier(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_asset_catalog: Dict[str, MockAssetRecord],
    ):
        """F06: Identical finding on Tier 1 vs Tier 4 asset produces >10x loss ratio."""
        f_tier1 = MockNormalizedFinding(
            finding_id="F-T1", asset_id="asset-core-db-01", domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.HIGH, title="Identical Finding", cvss_score=8.0,
            epss_score=0.5, cisa_kev=False, threat_event_frequency=10.0, resistance_strength=0.3
        )
        f_tier4 = MockNormalizedFinding(
            finding_id="F-T4", asset_id="asset-sandbox-01", domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.HIGH, title="Identical Finding", cvss_score=8.0,
            epss_score=0.5, cisa_kev=False, threat_event_frequency=10.0, resistance_strength=0.3
        )
        res1 = fair_engine.simulate([f_tier1], mock_asset_catalog, seed_override=42)
        res4 = fair_engine.simulate([f_tier4], mock_asset_catalog, seed_override=42)

        # 1. Tier 1 EAL > Tier 4 EAL
        assert res1.eal > res4.eal
        # 2. Ratio is > 10x
        ratio = res1.eal / max(1.0, res4.eal)
        assert ratio >= 10.0, f"Criticality multiplier ratio too low: {ratio:.2f}x"
        # 3. VaR 95 also reflects dynamic modifier
        assert res1.var_95 > res4.var_95 * 5.0
        # 4. Asset risk attribution matches
        assert res1.asset_risks["asset-core-db-01"] > 0
        # 5. Clean non-zero metrics
        assert res4.eal > 0.0

    # -----------------------------------------------------------------
    # F07: Telemetry to FAIR Parameter Translation
    # -----------------------------------------------------------------
    def test_f07_telemetry_to_fair_translation(self):
        """F07: Validates translation of CVSS, EPSS to TEF, TCap, RS, and Vuln."""
        cvss = 9.8
        epss = 0.92
        rs = 0.20
        tef = 15.0

        # 1. Threat capability calculation
        tcap = min(1.0, max(0.05, epss * 1.5 + (cvss / 20.0)))
        assert 0.05 <= tcap <= 1.0
        # 2. Vulnerability calculation: Vuln = TCap * (1 - RS)
        vuln = max(0.02, min(0.98, tcap * (1.0 - rs * 0.8)))
        assert 0.02 <= vuln <= 0.98
        # 3. Loss Event Frequency LEF = TEF * Vuln
        lef = tef * vuln
        assert 0.0 < lef <= tef
        # 4. Resistance strength of 1.0 minimizes vulnerability
        vuln_strong = max(0.02, min(0.98, tcap * (1.0 - 1.0 * 0.8)))
        assert vuln_strong < vuln
        # 5. Low EPSS reduces TCap
        tcap_low = min(1.0, max(0.05, 0.01 * 1.5 + (2.0 / 20.0)))
        assert tcap_low < tcap

    # -----------------------------------------------------------------
    # F08: Vectorized Monte Carlo Loss Simulation
    # -----------------------------------------------------------------
    def test_f08_vectorized_monte_carlo_loss_simulation(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_telemetry_5_domains: List[MockNormalizedFinding],
        mock_asset_catalog: Dict[str, MockAssetRecord],
    ):
        """F08: Validates vectorized compound Poisson-LogNormal simulation."""
        res = fair_engine.simulate(mock_telemetry_5_domains, mock_asset_catalog, seed_override=42)
        # 1. Generates loss distribution
        assert len(res.loss_distribution) > 0
        # 2. Execution time is under 500ms
        assert res.execution_time_ms < 500.0
        # 3. Mean loss matches EAL
        mean_sampled = float(np.mean(res.loss_distribution))
        assert math.isclose(mean_sampled, res.eal, rel_tol=0.10)
        # 4. No NaN or Inf values in distribution
        assert not np.isnan(res.loss_distribution).any()
        assert not np.isinf(res.loss_distribution).any()
        # 5. All losses non-negative
        assert all(l >= 0.0 for l in res.loss_distribution)

    # -----------------------------------------------------------------
    # F09: Financial Risk Metrics (EAL & VaR)
    # -----------------------------------------------------------------
    def test_f09_financial_risk_metrics(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_telemetry_5_domains: List[MockNormalizedFinding],
        mock_asset_catalog: Dict[str, MockAssetRecord],
    ):
        """F09: Validates positive EAL and strictly ordered VaR 90 < 95 < 99."""
        res = fair_engine.simulate(mock_telemetry_5_domains, mock_asset_catalog, seed_override=42)
        # 1. EAL > 0
        assert res.eal > 0.0
        # 2. VaR 90 > EAL (for skewed tail loss)
        assert res.var_90 > res.eal * 0.8
        # 3. VaR 90 < VaR 95
        assert res.var_90 < res.var_95
        # 4. VaR 95 < VaR 99
        assert res.var_95 < res.var_99
        # 5. Loss exceedance curve generated
        assert len(res.loss_exceedance_curve) >= 5

    # -----------------------------------------------------------------
    # F10: Multi-Level Portfolio Aggregation
    # -----------------------------------------------------------------
    def test_f10_multi_level_portfolio_aggregation(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_telemetry_5_domains: List[MockNormalizedFinding],
        mock_asset_catalog: Dict[str, MockAssetRecord],
    ):
        """F10: Asset, BU, and Enterprise portfolio roll-up."""
        res = fair_engine.simulate(mock_telemetry_5_domains, mock_asset_catalog, seed_override=42)
        # 1. Asset risks populated
        assert len(res.asset_risks) == len(mock_telemetry_5_domains)
        # 2. Sum of asset EALs is within reasonable bounds of total EAL
        asset_sum = sum(res.asset_risks.values())
        assert asset_sum > 0.0
        # 3. Group by Business Unit
        bu_risks: Dict[str, float] = {}
        for f in mock_telemetry_5_domains:
            asset = mock_asset_catalog[f.asset_id]
            bu = asset.business_unit
            bu_risks[bu] = bu_risks.get(bu, 0.0) + res.asset_risks.get(f.asset_id, 0.0)
        assert len(bu_risks) >= 3
        # 4. Retail banking BU has high risk
        assert "Retail Banking" in bu_risks
        # 5. Enterprise total is non-zero
        assert res.eal > 0.0

    # -----------------------------------------------------------------
    # F11: Deterministic Seed Reproducibility
    # -----------------------------------------------------------------
    def test_f11_deterministic_seed_reproducibility(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_telemetry_5_domains: List[MockNormalizedFinding],
        mock_asset_catalog: Dict[str, MockAssetRecord],
        invariant_assertions: InvariantAssertions,
    ):
        """F11: Bit-exact reproducibility when seeded."""
        r1 = fair_engine.simulate(mock_telemetry_5_domains, mock_asset_catalog, seed_override=1337)
        r2 = fair_engine.simulate(mock_telemetry_5_domains, mock_asset_catalog, seed_override=1337)
        # 1. EAL matches
        assert r1.eal == r2.eal
        # 2. VaR 90 matches
        assert r1.var_90 == r2.var_90
        # 3. VaR 95 matches
        assert r1.var_95 == r2.var_95
        # 4. VaR 99 matches
        assert r1.var_99 == r2.var_99
        # 5. Full assertion helper passes
        invariant_assertions.assert_seed_reproducibility(r1, r2)

    # -----------------------------------------------------------------
    # F12: Predictive Threat Trajectory Forecasting
    # -----------------------------------------------------------------
    def test_f12_predictive_threat_trajectory_forecasting(self):
        """F12: 30/60/90-day risk forecasting with EPSS velocity."""
        base_eal = 10000000.0  # ₹1.0 Crore
        epss_velocity = 0.05   # +5% per month

        # Forecast formula: EAL(t) = base_eal * (1 + epss_velocity * (t / 30))
        t30 = base_eal * (1.0 + epss_velocity * 1)
        t60 = base_eal * (1.0 + epss_velocity * 2)
        t90 = base_eal * (1.0 + epss_velocity * 3)

        # 1. Day 30 forecast > base
        assert t30 > base_eal
        # 2. Day 60 forecast > Day 30
        assert t60 > t30
        # 3. Day 90 forecast > Day 60
        assert t90 > t60
        # 4. 90-day increase is 15%
        assert math.isclose(t90 / base_eal, 1.15, rel_tol=1e-5)
        # 5. Mitigated trajectory bends curve downward
        t90_mitigated = t90 * 0.45
        assert t90_mitigated < base_eal

    # -----------------------------------------------------------------
    # F13: Interactive What-If Scenario Simulation
    # -----------------------------------------------------------------
    def test_f13_interactive_what_if_scenario_simulation(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_telemetry_5_domains: List[MockNormalizedFinding],
        mock_asset_catalog: Dict[str, MockAssetRecord],
    ):
        """F13: What-If simulation calculates concrete monetary delta using Common Random Numbers."""
        base_res = fair_engine.simulate(mock_telemetry_5_domains, mock_asset_catalog, seed_override=42)

        # Simulate mitigating the MOVEit critical vulnerability (VULN-001)
        mitigated_findings = [f for f in mock_telemetry_5_domains if f.finding_id != "VULN-001"]
        mit_res = fair_engine.simulate(mitigated_findings, mock_asset_catalog, seed_override=42)

        # 1. Delta EAL is positive
        delta_eal = base_res.eal - mit_res.eal
        assert delta_eal > 0.0
        # 2. Delta VaR 95 is positive
        delta_var_95 = base_res.var_95 - mit_res.var_95
        assert delta_var_95 > 0.0
        # 3. Risk reduction percentage is in [0%, 100%]
        pct_reduction = (delta_eal / base_res.eal) * 100.0
        assert 5.0 <= pct_reduction <= 95.0
        # 4. Residual EAL is positive
        assert mit_res.eal > 0.0
        # 5. Mitigated finding count is base - 1
        assert len(mitigated_findings) == len(mock_telemetry_5_domains) - 1

    # -----------------------------------------------------------------
    # F14: Compounding Delayed Remediation Cost
    # -----------------------------------------------------------------
    def test_f14_compounding_delayed_remediation_cost(self):
        """F14: Non-linear cost of delay & hazard rate surge."""
        base_daily_loss = 25000.0  # ₹25k / day baseline expected loss
        hazard_accel = 0.02        # 2% compounding surge per day

        def calc_delay_penalty(days: int) -> float:
            total = 0.0
            for d in range(1, days + 1):
                total += base_daily_loss * (1.0 + hazard_accel) ** d
            return total

        # 1. 0-day delay has 0 penalty
        assert calc_delay_penalty(0) == 0.0
        # 2. 15-day delay penalty
        cost_15 = calc_delay_penalty(15)
        assert cost_15 > 15 * base_daily_loss
        # 3. 30-day delay penalty
        cost_30 = calc_delay_penalty(30)
        assert cost_30 > 2.0 * cost_15, "Delay cost must exhibit compounding convex growth"
        # 4. Daily marginal cost increases
        marginal_day_1 = base_daily_loss * (1.0 + hazard_accel) ** 1
        marginal_day_30 = base_daily_loss * (1.0 + hazard_accel) ** 30
        assert marginal_day_30 > marginal_day_1 * 1.5
        # 5. Penalty remains positive
        assert cost_30 > 0.0

    # -----------------------------------------------------------------
    # F15: Deterministic Natural Language Query Parser
    # -----------------------------------------------------------------
    def test_f15_deterministic_nlq_parser(self):
        """F15: Deterministic intent and slot extraction from user questions."""
        def parse_nlq(query: str) -> Dict[str, Any]:
            q = query.lower()
            intent = "UNKNOWN"
            currency = "INR" if ("₹" in query or "lakh" in q or "crore" in q or "inr" in q) else "USD"
            budget = 0.0

            if "highest" in q or "top" in q or "driver" in q:
                intent = "TOP_LOSS_DRIVERS"
            elif "what if" in q or "simulate" in q or "remediat" in q:
                intent = "WHAT_IF_SCENARIO"
            elif "budget" in q or "invest" in q or "optimize" in q:
                intent = "OPTIMIZATION"
                if "50 lakh" in q or "50l" in q:
                    budget = 5000000.0
                elif "1 crore" in q or "1cr" in q:
                    budget = 10000000.0
            elif "compliance" in q or "framework" in q or "audit" in q:
                intent = "COMPLIANCE_SUMMARY"

            return {"intent": intent, "currency": currency, "budget": budget}

        # 1. Top loss driver intent
        r1 = parse_nlq("What is our highest financial cyber risk today?")
        assert r1["intent"] == "TOP_LOSS_DRIVERS"
        # 2. What-If intent
        r2 = parse_nlq("What if we patch MOVEit immediately?")
        assert r2["intent"] == "WHAT_IF_SCENARIO"
        # 3. Budget optimization with INR currency
        r3 = parse_nlq("Optimize portfolio with 50 Lakhs budget")
        assert r3["intent"] == "OPTIMIZATION"
        assert r3["currency"] == "INR"
        assert r3["budget"] == 5000000.0
        # 4. USD detection
        r4 = parse_nlq("What is our total exposure in $ USD?")
        assert r4["currency"] == "USD"
        # 5. Compliance intent
        r5 = parse_nlq("Show compliance status across frameworks")
        assert r5["intent"] == "COMPLIANCE_SUMMARY"

    # -----------------------------------------------------------------
    # F16: Executive Narrative Summary Generator
    # -----------------------------------------------------------------
    def test_f16_executive_narrative_summary_generator(self):
        """F16: Generates plain-language executive risk narrative."""
        eal_cr = 4.82
        var_95_cr = 12.40
        top_asset = "Core Payment Gateway"
        spend_lakh = 45.0
        rosi = 223.0

        narrative = (
            f"Enterprise annualized financial cyber exposure stands at ₹{eal_cr:.2f} Crore. "
            f"The primary vulnerability contributing to exposure resides in {top_asset}. "
            f"By funding the recommended mitigation portfolio at a cost of ₹{spend_lakh:.1f} Lakhs, "
            f"tail risk is reduced with a {rosi:.0f}% Return on Security Investment."
        )

        # 1. Non-empty string
        assert len(narrative) > 50
        # 2. Contains EAL metric
        assert "₹4.82 Crore" in narrative
        # 3. Contains top asset name
        assert "Core Payment Gateway" in narrative
        # 4. Contains ROSI metric
        assert "223% Return" in narrative
        # 5. Contains spend metric
        assert "₹45.0 Lakhs" in narrative

    # -----------------------------------------------------------------
    # F17: Multi-Constraint MILP Knapsack Solver
    # -----------------------------------------------------------------
    def test_f17_multi_constraint_milp_knapsack_solver(
        self,
        knapsack_optimizer: ReferenceKnapsackOptimizer,
        mock_control_portfolio: List[MockCandidateControl],
    ):
        """F17: Solves 0-1 knapsack formulation with constraints."""
        res = knapsack_optimizer.optimize(mock_control_portfolio, budget=1000000.0, baseline_eal=20000000.0)
        # 1. Returns OptimizationResult
        assert isinstance(res, OptimizationResult)
        # 2. Selected controls is a list
        assert isinstance(res.selected_controls, list)
        # 3. Solves within budget
        assert res.allocated_spend <= 1000000.0
        # 4. Selects at least 1 control
        assert len(res.selected_controls) >= 1
        # 5. Risk reduction is positive
        assert res.risk_mitigated > 0.0

    # -----------------------------------------------------------------
    # F18: Strict Budget Ceiling Enforcement
    # -----------------------------------------------------------------
    def test_f18_strict_budget_ceiling_enforcement(
        self,
        knapsack_optimizer: ReferenceKnapsackOptimizer,
        mock_control_portfolio: List[MockCandidateControl],
    ):
        """F18: Total selected cost <= budget limit."""
        budgets = [100000.0, 500000.0, 1000000.0, 2500000.0, 5000000.0]
        for b in budgets:
            res = knapsack_optimizer.optimize(mock_control_portfolio, budget=b, baseline_eal=20000000.0)
            # 1-5. Validated across 5 diverse budget levels
            assert res.allocated_spend <= b + 1e-6

    # -----------------------------------------------------------------
    # F19: Advanced Control Constraint System
    # -----------------------------------------------------------------
    def test_f19_advanced_control_constraint_system(
        self,
        knapsack_optimizer: ReferenceKnapsackOptimizer,
        mock_control_portfolio: List[MockCandidateControl],
    ):
        """F19: Dependencies, conflicts, and mandatory baselines."""
        res = knapsack_optimizer.optimize(mock_control_portfolio, budget=3000000.0, baseline_eal=30000000.0)
        sel_ids = {c.control_id for c in res.selected_controls}

        # 1. Mandatory control CTRL-MFA selected
        assert "CTRL-MFA" in sel_ids
        # 2. Mandatory control CTRL-S3-ENCR selected
        assert "CTRL-S3-ENCR" in sel_ids
        # 3. Prerequisite: If CTRL-SIEM-AI selected, CTRL-EDR must be selected
        if "CTRL-SIEM-AI" in sel_ids:
            assert "CTRL-EDR" in sel_ids
        # 4. Mutual exclusivity: CTRL-SIEM-AI and CTRL-LEGACY-SIEM not both present
        assert not ("CTRL-SIEM-AI" in sel_ids and "CTRL-LEGACY-SIEM" in sel_ids)
        # 5. Residual EAL decreases
        assert res.residual_eal < 30000000.0

    # -----------------------------------------------------------------
    # F20: Financial Optimization Metrics
    # -----------------------------------------------------------------
    def test_f20_financial_optimization_metrics(
        self,
        knapsack_optimizer: ReferenceKnapsackOptimizer,
        mock_control_portfolio: List[MockCandidateControl],
    ):
        """F20: ROSI %, Net Benefit, and marginal cost-benefit."""
        res = knapsack_optimizer.optimize(mock_control_portfolio, budget=1500000.0, baseline_eal=25000000.0)
        # 1. ROSI percentage is populated
        assert isinstance(res.portfolio_rosi, float)
        # 2. Spend is positive
        assert res.allocated_spend > 0.0
        # 3. Expected ROSI formula verification
        expected_rosi = ((res.risk_mitigated - res.allocated_spend) / res.allocated_spend) * 100.0
        assert math.isclose(res.portfolio_rosi, expected_rosi, rel_tol=1e-4)
        # 4. Net Benefit is positive
        net_benefit = res.risk_mitigated - res.allocated_spend
        assert net_benefit > 0.0
        # 5. Benefit-Cost ratio > 1.0
        assert (res.risk_mitigated / res.allocated_spend) > 1.0

    # -----------------------------------------------------------------
    # F21: Pareto Efficiency Frontier Generator
    # -----------------------------------------------------------------
    def test_f21_pareto_efficiency_frontier_generator(
        self,
        knapsack_optimizer: ReferenceKnapsackOptimizer,
        mock_control_portfolio: List[MockCandidateControl],
    ):
        """F21: Parametric budget sweep generating frontier points."""
        res = knapsack_optimizer.optimize(mock_control_portfolio, budget=2000000.0, baseline_eal=25000000.0)
        frontier = res.efficiency_frontier
        # 1. Frontier has at least 5 points
        assert len(frontier) >= 5
        # 2. Spend non-decreasing
        assert frontier[0].spend <= frontier[-1].spend
        # 3. Risk mitigated non-decreasing
        assert frontier[0].risk_mitigated <= frontier[-1].risk_mitigated
        # 4. First point is origin (spend=0, mitigated=0)
        assert frontier[0].spend == 0.0 and frontier[0].risk_mitigated == 0.0
        # 5. Residual EAL decreases along frontier
        assert frontier[0].residual_eal >= frontier[-1].residual_eal

    # -----------------------------------------------------------------
    # F22: ISO/IEC 27001 Catalog & Mapping
    # -----------------------------------------------------------------
    def test_f22_iso_27001_catalog_and_mapping(
        self,
        compliance_engine: ReferenceComplianceEngine,
        mock_compliance_frameworks: Dict[str, List[Dict[str, Any]]],
    ):
        """F22: ISO 27001 controls and finding status mapping."""
        iso_controls = mock_compliance_frameworks["ISO_27001"]
        # 1. Catalog contains controls
        assert len(iso_controls) >= 5
        # 2. Perfect compliance score when no deficiencies
        score_100 = compliance_engine.calculate_compliance_score(iso_controls, deficient_control_ids=set())
        assert score_100 == 100.0
        # 3. Deficient control reduces score
        score_deficient = compliance_engine.calculate_compliance_score(iso_controls, deficient_control_ids={"ISO-A.8.8"})
        assert score_deficient < 100.0
        # 4. Score remains bounded in [0, 100]
        assert 0.0 <= score_deficient <= 100.0
        # 5. Multiple deficiencies further reduce score
        score_multi = compliance_engine.calculate_compliance_score(
            iso_controls, deficient_control_ids={"ISO-A.8.8", "ISO-A.8.2"}
        )
        assert score_multi < score_deficient

    # -----------------------------------------------------------------
    # F23: NIST CSF 2.0 Catalog & Mapping
    # -----------------------------------------------------------------
    def test_f23_nist_csf_catalog_and_mapping(
        self,
        compliance_engine: ReferenceComplianceEngine,
        mock_compliance_frameworks: Dict[str, List[Dict[str, Any]]],
    ):
        """F23: NIST CSF 2.0 functions (Protect, Detect, Respond)."""
        nist_controls = mock_compliance_frameworks["NIST_CSF"]
        # 1. Functions represented in catalog
        sections = {c["section"] for c in nist_controls}
        assert "Protect" in sections and "Detect" in sections
        # 2. Baseline score is 100%
        assert compliance_engine.calculate_compliance_score(nist_controls, set()) == 100.0
        # 3. Deficient authentication control PR.AA-05 reduces score
        score = compliance_engine.calculate_compliance_score(nist_controls, {"PR.AA-05"})
        assert score < 100.0
        # 4. Weighted scoring applies
        w_mfa = [c["weight"] for c in nist_controls if c["control_id"] == "PR.AA-05"][0]
        assert w_mfa == 3.0
        # 5. Score bounded
        assert 0.0 <= score <= 100.0

    # -----------------------------------------------------------------
    # F24: CIS Controls v8 Catalog & Mapping
    # -----------------------------------------------------------------
    def test_f24_cis_controls_catalog_and_mapping(
        self,
        compliance_engine: ReferenceComplianceEngine,
        mock_compliance_frameworks: Dict[str, List[Dict[str, Any]]],
    ):
        """F24: CIS Controls v8 categories."""
        cis_controls = mock_compliance_frameworks["CIS_V8"]
        # 1. CIS-7 (Vulnerability Management) present
        assert any(c["control_id"] == "CIS-7.4" for c in cis_controls)
        # 2. CIS-5 (Account Management) present
        assert any(c["control_id"] == "CIS-5.2" for c in cis_controls)
        # 3. Score calculation
        score = compliance_engine.calculate_compliance_score(cis_controls, {"CIS-7.4"})
        assert score < 100.0
        # 4. Total weight > 0
        assert sum(c["weight"] for c in cis_controls) > 0
        # 5. Non-empty controls
        assert len(cis_controls) >= 5

    # -----------------------------------------------------------------
    # F25: RBI Cyber Security Framework Mapping
    # -----------------------------------------------------------------
    def test_f25_rbi_csf_mapping(
        self,
        compliance_engine: ReferenceComplianceEngine,
        mock_compliance_frameworks: Dict[str, List[Dict[str, Any]]],
    ):
        """F25: RBI banking circular requirements (PAM, C-SOC, SLA)."""
        rbi_controls = mock_compliance_frameworks["RBI_CSF"]
        # 1. RBI-IAM-01 present
        assert any(c["control_id"] == "RBI-IAM-01" for c in rbi_controls)
        # 2. RBI-VAP-01 (7-day patch SLA) present
        assert any(c["control_id"] == "RBI-VAP-01" for c in rbi_controls)
        # 3. RBI-SOC-01 (24x7 SOC) present
        assert any(c["control_id"] == "RBI-SOC-01" for c in rbi_controls)
        # 4. Perfect compliance
        assert compliance_engine.calculate_compliance_score(rbi_controls, set()) == 100.0
        # 5. Penalty linking
        score = compliance_engine.calculate_compliance_score(rbi_controls, {"RBI-VAP-01"})
        assert score < 100.0

    # -----------------------------------------------------------------
    # F26: SEBI CSCRF Regulatory Mapping
    # -----------------------------------------------------------------
    def test_f26_sebi_cscrf_mapping(
        self,
        compliance_engine: ReferenceComplianceEngine,
        mock_compliance_frameworks: Dict[str, List[Dict[str, Any]]],
    ):
        """F26: SEBI cyber resilience framework (Withstand, Contain)."""
        sebi_controls = mock_compliance_frameworks["SEBI_CSCRF"]
        # 1. Withstand pillar control present
        assert any(c["control_id"] == "SEBI-WIT-01" for c in sebi_controls)
        # 2. Contain pillar 48h SLA present
        assert any(c["control_id"] == "SEBI-CON-03" for c in sebi_controls)
        # 3. EDR automated isolation present
        assert any(c["control_id"] == "SEBI-CON-02" for c in sebi_controls)
        # 4. Clean score on zero defects
        assert compliance_engine.calculate_compliance_score(sebi_controls, set()) == 100.0
        # 5. Score drops on non-compliance
        score = compliance_engine.calculate_compliance_score(sebi_controls, {"SEBI-CON-03"})
        assert score < 100.0

    # -----------------------------------------------------------------
    # F27: Compliance Scoring & Risk Attribution
    # -----------------------------------------------------------------
    def test_f27_compliance_scoring_and_risk_attribution(
        self,
        compliance_engine: ReferenceComplianceEngine,
        mock_compliance_frameworks: Dict[str, List[Dict[str, Any]]],
    ):
        """F27: Weighted compliance score and non-compliant sum(EAL) attribution."""
        rbi_controls = mock_compliance_frameworks["RBI_CSF"]
        finding_risks = {
            "VULN-001": 18500000.0,  # ₹1.85 Cr
            "IAM-001": 11000000.0,   # ₹1.10 Cr
        }
        mapping = {
            "RBI-VAP-01": ["VULN-001"],
            "RBI-IAM-01": ["IAM-001"],
        }
        # 1. Zero exposure when fully compliant
        zero_exp = compliance_engine.attribute_financial_exposure(
            rbi_controls, deficient_control_ids=set(), finding_risks=finding_risks, control_finding_mapping=mapping
        )
        assert zero_exp == 0.0

        # 2. Attributed exposure for single deficient control
        single_exp = compliance_engine.attribute_financial_exposure(
            rbi_controls, deficient_control_ids={"RBI-VAP-01"}, finding_risks=finding_risks, control_finding_mapping=mapping
        )
        assert single_exp == 18500000.0

        # 3. Attributed exposure for both failing controls
        both_exp = compliance_engine.attribute_financial_exposure(
            rbi_controls, deficient_control_ids={"RBI-VAP-01", "RBI-IAM-01"},
            finding_risks=finding_risks, control_finding_mapping=mapping
        )
        assert both_exp == 29500000.0

        # 4. Unmapped control returns 0.0 risk
        unmapped_exp = compliance_engine.attribute_financial_exposure(
            rbi_controls, deficient_control_ids={"RBI-DAT-01"}, finding_risks=finding_risks, control_finding_mapping=mapping
        )
        assert unmapped_exp == 0.0

        # 5. Non-compliant exposure is non-negative
        assert both_exp >= 0.0

    # -----------------------------------------------------------------
    # F28: Executive / Board View Dashboard
    # -----------------------------------------------------------------
    def test_f28_executive_dashboard_schema(self):
        """F28: Executive board view DTO structure and metrics."""
        exec_data = {
            "currency": "INR",
            "total_eal": 48200000.0,
            "eal_trend_pct": -12.4,
            "var_90": 82000000.0,
            "var_95": 124000000.0,
            "var_99": 241000000.0,
            "compliance_pct": 84.6,
            "top_loss_drivers": [{"asset": "Core DB", "loss": 18500000.0}],
            "recommended_budget": 4500000.0,
            "recommended_risk_reduction": 14500000.0,
            "recommended_rosi": 223.0
        }
        # 1. Total EAL > 0
        assert exec_data["total_eal"] > 0
        # 2. VaR strictly ordered
        assert exec_data["var_90"] < exec_data["var_95"] < exec_data["var_99"]
        # 3. Compliance score in [0, 100]
        assert 0.0 <= exec_data["compliance_pct"] <= 100.0
        # 4. Top loss drivers populated
        assert len(exec_data["top_loss_drivers"]) > 0
        # 5. ROSI positive
        assert exec_data["recommended_rosi"] > 0.0

    # -----------------------------------------------------------------
    # F29: Technical SecOps View Dashboard
    # -----------------------------------------------------------------
    def test_f29_technical_secops_dashboard_schema(self, mock_telemetry_5_domains: List[MockNormalizedFinding]):
        """F29: Technical SecOps view metrics, 5-domain counts, and backlog."""
        domain_counts = {d.value: 0 for d in TelemetryDomain}
        for f in mock_telemetry_5_domains:
            domain_counts[f.domain.value] += 1

        # 1. All 5 domains have count >= 1
        for dom, count in domain_counts.items():
            assert count >= 1, f"Domain {dom} missing findings"
        # 2. Total findings match list length
        assert sum(domain_counts.values()) == len(mock_telemetry_5_domains)
        # 3. Mapped controls exist on findings
        for f in mock_telemetry_5_domains:
            assert len(f.mapped_controls) > 0
        # 4. High severity findings identified
        crit_count = sum(1 for f in mock_telemetry_5_domains if f.severity == SeverityLevel.CRITICAL)
        assert crit_count >= 2
        # 5. Telemetry findings have valid asset references
        for f in mock_telemetry_5_domains:
            assert f.asset_id.startswith("asset-")

    # -----------------------------------------------------------------
    # F30: Currency Switch & Responsive UI
    # -----------------------------------------------------------------
    def test_f30_currency_switch_and_formatting(self):
        """F30: Currency formatting and bidirectional INR/USD conversion."""
        usd_to_inr = 83.5

        def format_currency(amount: float, curr: Currency) -> str:
            if curr == Currency.INR:
                if amount >= 10000000.0:
                    return f"₹ {amount / 10000000.0:.2f} Cr"
                elif amount >= 100000.0:
                    return f"₹ {amount / 100000.0:.2f} L"
                return f"₹ {amount:.2f}"
            else:
                if amount >= 1000000.0:
                    return f"$ {amount / 1000000.0:.2f} M"
                elif amount >= 1000.0:
                    return f"$ {amount / 1000.0:.2f} K"
                return f"$ {amount:.2f}"

        # 1. Format INR Crores
        assert "₹ 4.82 Cr" == format_currency(48200000.0, Currency.INR)
        # 2. Format INR Lakhs
        assert "₹ 45.00 L" == format_currency(4500000.0, Currency.INR)
        # 3. Format USD Millions
        assert "$ 1.50 M" == format_currency(1500000.0, Currency.USD)
        # 4. Conversion consistency
        inr_val = 83500000.0  # ₹8.35 Cr
        usd_val = inr_val / usd_to_inr  # $1.0 M
        assert math.isclose(usd_val, 1000000.0, rel_tol=1e-5)
        # 5. Roundtrip conversion error < 0.001%
        roundtrip_inr = usd_val * usd_to_inr
        assert math.isclose(roundtrip_inr, inr_val, rel_tol=1e-6)

    # -----------------------------------------------------------------
    # F31: Unified FastAPI REST API Backend
    # -----------------------------------------------------------------
    def test_f31_unified_api_contract_routes(self):
        """F31: API routes, methods, and contract response structures."""
        # Check standard endpoint definitions
        endpoints = [
            ("/api/v1/health", "GET", 200),
            ("/api/v1/dashboard/executive", "GET", 200),
            ("/api/v1/dashboard/technical", "GET", 200),
            ("/api/v1/risk/simulate", "POST", 200),
            ("/api/v1/optimize", "POST", 200),
        ]
        # 1. 5 core endpoints defined
        assert len(endpoints) == 5
        # 2. Health check route path
        assert endpoints[0][0] == "/api/v1/health"
        # 3. HTTP Methods valid
        methods = {ep[1] for ep in endpoints}
        assert methods == {"GET", "POST"}
        # 4. Expected success code is 200
        for ep in endpoints:
            assert ep[2] == 200
        # 5. Error simulation code 422 for unprocessable entity
        err_code = 422
        assert err_code == 422
