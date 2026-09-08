"""
tests/unit/test_decision_support.py - Comprehensive Unit Tests for AI Decision Support, NLQ & What-If Engine.

Validates:
1. Threat trajectory forecasting across 30/60/90-day horizons with EPSS velocity & acceleration.
2. What-If scenario simulation: positive/negative deltas, CRN variance reduction, reproducibility.
3. Delayed remediation cost compounding: convexity, hazard surge, gradient growth, dual currencies.
4. NLQ parser: Indian & Western currencies, 6 intent categories, entity extraction, router dispatch.
5. Executive narrative generator: plain-language summaries, currency formatting, ROSI metrics.
"""

import math
from typing import Dict, List
import numpy as np
import pytest

from src.config import USD_TO_INR_RATE
from src.decision_support.delay_cost import (
    DelayCostResult,
    DelayedRemediationModel,
    DelayPoint,
    calculate_delay_cost,
)
from src.decision_support.narrative import (
    ExecutiveNarrativeGenerator,
    NarrativeReport,
    format_currency,
    generate_executive_narrative,
)
from src.decision_support.nlq_parser import (
    ExtractedEntities,
    NLQParser,
    NLQRouter,
    QueryIntent,
    StructuredRiskQuery,
    parse_nlq_query,
)
from src.decision_support.trajectory import (
    ThreatTrajectoryForecaster,
    TrajectoryForecast,
    TrajectoryPoint,
    TrajectoryScenario,
)
from src.decision_support.what_if import (
    WhatIfEngine,
    WhatIfRequest,
    WhatIfResult,
    run_counterfactual_simulation,
)
from src.telemetry.models import NormalizedFinding, SeverityLevel, TelemetryDomain


# =====================================================================
# Fixtures
# =====================================================================

@pytest.fixture
def sample_findings() -> List[NormalizedFinding]:
    """Provides standard sample findings for unit tests."""
    return [
        NormalizedFinding(
            finding_id="VULN-001",
            asset_id="asset-core-db-01",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.CRITICAL,
            title="CVE-2023-34362 MOVEit Transfer SQL Injection",
            cvss_score=9.8,
            epss_score=0.92,
            cisa_kev=True,
            threat_event_frequency=12.0,
            resistance_strength=0.15,
        ),
        NormalizedFinding(
            finding_id="SIEM-001",
            asset_id="asset-web-gw-01",
            domain=TelemetryDomain.SIEM,
            severity=SeverityLevel.HIGH,
            title="Brute Force Credential Stuffing",
            cvss_score=7.5,
            epss_score=0.45,
            cisa_kev=False,
            threat_event_frequency=20.0,
            resistance_strength=0.40,
        ),
        NormalizedFinding(
            finding_id="IAM-001",
            asset_id="asset-cloud-iam-01",
            domain=TelemetryDomain.IAM,
            severity=SeverityLevel.CRITICAL,
            title="Root Role Missing Multi-Factor Authentication",
            cvss_score=8.9,
            epss_score=0.68,
            cisa_kev=False,
            threat_event_frequency=15.0,
            resistance_strength=0.10,
        ),
    ]


# =====================================================================
# 1. Threat Trajectory Forecasting Tests
# =====================================================================

class TestThreatTrajectoryForecasting:
    """Tests for F12: Predictive Threat Scoring & Risk Trajectory Forecasting."""

    def test_epss_velocity_and_acceleration_derivatives(self):
        """Validates discrete 1st and 2nd derivatives of EPSS."""
        forecaster = ThreatTrajectoryForecaster()

        # EPSS moves from 0.20 to 0.50 in 30 days
        vel = forecaster.calculate_epss_velocity(epss_current=0.50, epss_previous=0.20, delta_t_days=30.0)
        assert math.isclose(vel, 0.01, rel_tol=1e-5)

        # Velocity moves from 0.005 to 0.01 in 30 days
        acc = forecaster.calculate_epss_acceleration(vel_current=0.01, vel_previous=0.005, delta_t_days=30.0)
        assert math.isclose(acc, 0.005 / 30.0, rel_tol=1e-5)

    def test_project_epss_logistic_growth(self):
        """Validates bounded logistic growth trajectory for EPSS."""
        forecaster = ThreatTrajectoryForecaster(c1=1.0, c2=0.5, omega_kev=0.05)

        e0 = 0.30
        e30 = forecaster.project_epss(e0, velocity=0.01, acceleration=0.001, cisa_kev=True, tau_days=30)
        e60 = forecaster.project_epss(e0, velocity=0.01, acceleration=0.001, cisa_kev=True, tau_days=60)
        e90 = forecaster.project_epss(e0, velocity=0.01, acceleration=0.001, cisa_kev=True, tau_days=90)

        # Monotonic escalation under active campaign
        assert e30 > e0
        assert e60 > e30
        assert e90 > e60
        assert e90 <= 1.0

    def test_trajectory_forecasting_horizons(self, sample_findings: List[NormalizedFinding]):
        """Validates multi-horizon trajectory generation across t=0, 30, 60, 90 days."""
        forecaster = ThreatTrajectoryForecaster(monte_carlo_trials=1000)
        forecast = forecaster.forecast_trajectory(
            findings=sample_findings,
            horizons=[0, 30, 60, 90],
            seed=42,
            default_velocity=0.003,
            default_acceleration=0.0002,
        )

        assert len(forecast.baseline_trajectory) == 4
        assert [pt.days for pt in forecast.baseline_trajectory] == [0, 30, 60, 90]

        t0, t30, t60, t90 = forecast.baseline_trajectory

        # 1. Base EAL is strictly positive
        assert t0.eal > 0.0
        # 2. Risk trajectory strictly increases when threat velocity > 0
        assert t30.eal > t0.eal
        assert t60.eal > t30.eal
        assert t90.eal > t60.eal
        # 3. VaR strictly ordered at each horizon (VaR 90 < VaR 95 < VaR 99)
        for pt in forecast.baseline_trajectory:
            assert pt.var_90 < pt.var_95 < pt.var_99, f"VaR ordering violated at day {pt.days}"
        # 4. Confidence bounds encompass EAL
        for pt in forecast.baseline_trajectory:
            assert pt.eal_lower_ci <= pt.eal <= pt.eal_upper_ci
        # 5. Currency conversions populated
        assert t90.eal_inr == pytest.approx(t90.eal * USD_TO_INR_RATE, rel=1e-2)

    def test_trajectory_scenarios_comparison(self, sample_findings: List[NormalizedFinding]):
        """Validates that Pessimistic > Baseline > Optimistic exposure at 90 days."""
        forecaster = ThreatTrajectoryForecaster(monte_carlo_trials=1000)
        forecast = forecaster.forecast_trajectory(
            findings=sample_findings,
            horizons=[0, 90],
            seed=42,
            default_velocity=0.002,
        )

        base_90 = forecast.baseline_trajectory[-1].eal
        pess_90 = forecast.pessimistic_trajectory[-1].eal
        opt_90 = forecast.optimistic_trajectory[-1].eal

        assert pess_90 > base_90, "Pessimistic scenario must produce higher risk than baseline"
        assert opt_90 < base_90, "Optimistic scenario must produce lower risk than baseline"
        assert len(forecast.summary) > 20

    def test_trajectory_empty_findings(self):
        """Boundary test: empty findings list yields 0.0 exposure across all horizons."""
        forecaster = ThreatTrajectoryForecaster()
        forecast = forecaster.forecast_trajectory(findings=[], horizons=[0, 30, 60, 90])
        for pt in forecast.baseline_trajectory:
            assert pt.eal == 0.0
            assert pt.var_95 == 0.0


# =====================================================================
# 2. What-If Scenario Simulation Tests
# =====================================================================

class TestWhatIfScenarioSimulation:
    """Tests for F13: Interactive What-If Scenario Simulation with CRN."""

    def test_what_if_mitigation_positive_delta(self, sample_findings: List[NormalizedFinding]):
        """Validates positive monetary risk reduction delta when mitigating vulnerabilities."""
        engine = WhatIfEngine(iterations=2000, seed=42)
        req = WhatIfRequest(
            cves_to_patch=["CVE-2023-34362"],
            control_cost=25000.0,
            currency="USD",
        )
        res = engine.simulate(baseline_findings=sample_findings, request=req)

        # 1. Delta EAL is strictly positive
        assert res.delta_eal > 0.0
        # 2. Residual EAL equals baseline - delta
        assert math.isclose(res.simulated_eal, res.baseline_eal - res.delta_eal, abs_tol=0.01)
        # 3. Delta VaR 95 is positive
        assert res.delta_var_95 > 0.0
        # 4. Risk reduction percentage in sensible range
        assert 5.0 <= res.risk_reduction_pct <= 95.0
        # 5. Net financial benefit and ROSI % computed correctly
        assert res.net_financial_benefit == pytest.approx(res.delta_eal - 25000.0, rel=1e-2)
        assert res.rosi_percent is not None
        # 6. Actionable summary is informative
        assert "reduces Expected Annual Loss" in res.actionable_summary

    def test_what_if_degradation_negative_delta(self, sample_findings: List[NormalizedFinding]):
        """Validates negative delta (risk surge) when controls are removed or fail."""
        engine = WhatIfEngine(iterations=2000, seed=42)
        req = WhatIfRequest(
            controls_to_remove=["EDR", "MFA"],
            currency="USD",
        )
        res = engine.simulate(baseline_findings=sample_findings, request=req)

        # Removing controls escalates threat frequency and lowers RS -> risk surges
        assert res.delta_eal < 0.0
        assert res.simulated_eal > res.baseline_eal
        assert res.simulated_var_95 > res.baseline_var_95
        assert "escalates Expected Annual Loss" in res.actionable_summary

    def test_what_if_crn_variance_reduction(self, sample_findings: List[NormalizedFinding]):
        """
        Validates that Common Random Numbers (CRN) dramatically shrinks delta variance
        compared to independent random seeds.
        """
        engine = WhatIfEngine(iterations=1000)
        mitigated_findings = [f for f in sample_findings if f.finding_id != "VULN-001"]

        # Run 10 paired simulations under Common Random Numbers (identical seed per pair)
        crn_deltas: List[float] = []
        for i in range(10):
            pair_seed = 100 + i
            res = engine.simulate_pair(
                sample_findings, mitigated_findings, seed=pair_seed, trials=1000
            )
            crn_deltas.append(res.delta_eal)

        # Run 10 paired simulations under Independent Seeds
        indep_deltas: List[float] = []
        mc_engine = engine.mc_engine
        for i in range(10):
            seed_base = 1000 + i * 2
            seed_mit = 1000 + i * 2 + 1
            r_base = mc_engine.simulate(sample_findings, seed_override=seed_base)
            r_mit = mc_engine.simulate(mitigated_findings, seed_override=seed_mit)
            indep_deltas.append(r_base.eal - r_mit.eal)

        var_crn = float(np.var(crn_deltas))
        var_indep = float(np.var(indep_deltas))

        # CRN variance must be significantly lower than independent seeds variance
        assert var_crn < var_indep, (
            f"Expected CRN variance to be smaller than independent seeds variance! "
            f"var_crn={var_crn:.2f}, var_indep={var_indep:.2f}"
        )

    def test_what_if_reference_function_interface(self, sample_findings: List[NormalizedFinding]):
        """Validates authoritative reference function run_counterfactual_simulation."""
        mitigated = [f for f in sample_findings if f.finding_id != "VULN-001"]
        res = run_counterfactual_simulation(
            baseline_findings=sample_findings,
            mitigated_findings=mitigated,
            seed=42,
            trials=1000,
        )
        assert isinstance(res, WhatIfResult)
        assert res.delta_eal > 0.0
        assert res.mitigated_eal == res.simulated_eal
        assert res.delta_eal_percent == res.risk_reduction_pct


# =====================================================================
# 3. Delayed Remediation Cost Tests
# =====================================================================

class TestDelayedRemediationCost:
    """Tests for F14: Compounding Delayed Remediation Cost."""

    def test_delay_cost_zero_days_is_zero(self, sample_findings: List[NormalizedFinding]):
        """Delay of 0 days incurs exact 0.0 delayed remediation penalty."""
        res = calculate_delay_cost(findings=sample_findings, days_delay=0)
        assert res.total_delay_penalty == 0.0
        assert res.total_delay_penalty_usd == 0.0
        assert res.total_delay_penalty_inr == 0.0
        assert res.breach_probability_surge == 0.0

    def test_delay_cost_compounding_convexity(self, sample_findings: List[NormalizedFinding]):
        """
        Validates compounding convexity:
        Cost(30d) > Cost(15d)
        Cost(60d) > 2 * Cost(30d)
        Cost(90d) > Cost(60d)
        """
        model = DelayedRemediationModel(base_hazard_accel=0.02)
        curve = model.compute_daily_curve(findings=sample_findings, max_days=90)

        cost_15 = curve[15].total_cost_of_delay_usd
        cost_30 = curve[30].total_cost_of_delay_usd
        cost_60 = curve[60].total_cost_of_delay_usd
        cost_90 = curve[90].total_cost_of_delay_usd

        # Strict monotonic increase
        assert cost_15 > 0.0
        assert cost_30 > cost_15
        assert cost_60 > cost_30
        assert cost_90 > cost_60

        # Convexity: cost at 60 days exceeds double of 30 days due to accelerating hazard
        assert cost_60 > 2.0 * cost_30, (
            f"Expected Cost(60d) > 2 * Cost(30d). cost_60={cost_60}, cost_30={cost_30}"
        )

    def test_delay_cost_daily_gradient_growth(self, sample_findings: List[NormalizedFinding]):
        """Validates that marginal daily loss gradient d(Cost)/dt increases over delay time."""
        model = DelayedRemediationModel(base_hazard_accel=0.02)
        curve = model.compute_daily_curve(findings=sample_findings, max_days=60)

        grad_day_1 = curve[1].daily_loss_gradient_usd
        grad_day_30 = curve[30].daily_loss_gradient_usd
        grad_day_60 = curve[60].daily_loss_gradient_usd

        assert grad_day_30 > grad_day_1
        assert grad_day_60 > grad_day_30

    def test_delay_cost_poisson_breach_probability_surge(self, sample_findings: List[NormalizedFinding]):
        """Validates non-homogeneous Poisson breach probability increases with delay."""
        res_30 = calculate_delay_cost(findings=sample_findings, days_delay=30)
        res_60 = calculate_delay_cost(findings=sample_findings, days_delay=60)

        assert 0.0 < res_30.breach_probability_surge < 1.0
        assert res_60.breach_probability_surge > res_30.breach_probability_surge

    def test_delay_cost_currency_conversion(self, sample_findings: List[NormalizedFinding]):
        """Validates INR conversion matches USD_TO_INR_RATE."""
        res_usd = calculate_delay_cost(findings=sample_findings, days_delay=30, currency="USD")
        res_inr = calculate_delay_cost(findings=sample_findings, days_delay=30, currency="INR")

        assert res_inr.total_delay_penalty == pytest.approx(
            res_usd.total_delay_penalty * USD_TO_INR_RATE, rel=1e-2
        )
        assert res_inr.daily_loss_gradient == pytest.approx(
            res_usd.daily_loss_gradient * USD_TO_INR_RATE, rel=1e-2
        )

    def test_delay_cost_expedite_decision_rule(self, sample_findings: List[NormalizedFinding]):
        """Validates emergency off-cycle recommendation when delay penalty exceeds threshold."""
        model = DelayedRemediationModel(expedite_cost_usd=5000.0)
        res = model.evaluate_delay(findings=sample_findings, days_delay=60)

        assert res.expedite_warranted is True
        assert "Emergency Off-Cycle Remediation Warranted" in res.executive_recommendation


# =====================================================================
# 4. Deterministic NLQ Parser Tests
# =====================================================================

class TestDeterministicNLQParser:
    """Tests for F15: Deterministic Natural Language Query Parser."""

    @pytest.fixture
    def parser(self) -> NLQParser:
        return NLQParser()

    @pytest.mark.parametrize(
        "query_text, expected_inr",
        [
            ("Optimize portfolio with ₹50 Lakhs budget", 5_000_000.0),
            ("Allocate 50 lacs for security mitigations", 5_000_000.0),
            ("What controls can we buy with 50L inr?", 5_000_000.0),
            ("Budget is ₹1 Crore for cyber risk reduction", 10_000_000.0),
            ("How to allocate 2 Cr budget?", 20_000_000.0),
            ("With 1.5 crores spend, which projects should we fund?", 15_000_000.0),
            ("Spend ₹75,000 immediately", 75_000.0),
        ],
    )
    def test_nlq_indian_currency_parsing(self, parser: NLQParser, query_text: str, expected_inr: float):
        """Validates Indian currency slot extraction (Lakhs, Lacs, Crores, Cr)."""
        srq = parser.parse(query_text)
        assert srq.currency == "INR"
        assert srq.budget_amount is not None
        assert math.isclose(srq.budget_amount, expected_inr, rel_tol=1e-4)
        assert srq.budget_amount_inr is not None
        assert math.isclose(srq.budget_amount_inr, expected_inr, rel_tol=1e-4)

    @pytest.mark.parametrize(
        "query_text, expected_usd",
        [
            ("Allocate $1M budget for risk reduction", 1_000_000.0),
            ("How to spend $ 2.5 Million?", 2_500_000.0),
            ("Budget of $500k for cloud security", 500_000.0),
            ("With 250 K USD, what is our optimal portfolio?", 250_000.0),
            ("What is our exposure under a $1B scenario?", 1_000_000_000.0),
            ("Spend $50,000 on EDR", 50_000.0),
        ],
    )
    def test_nlq_western_currency_parsing(self, parser: NLQParser, query_text: str, expected_usd: float):
        """Validates Western currency slot extraction (Millions, Thousands, Billions)."""
        srq = parser.parse(query_text)
        assert srq.currency == "USD"
        assert srq.budget_amount is not None
        assert math.isclose(srq.budget_amount, expected_usd, rel_tol=1e-4)
        assert srq.budget_amount_usd is not None
        assert math.isclose(srq.budget_amount_usd, expected_usd, rel_tol=1e-4)

    @pytest.mark.parametrize(
        "query_text, expected_intent",
        [
            ("What is our highest financial cyber risk today?", QueryIntent.HIGHEST_RISK),
            ("Where is our greatest exposure?", QueryIntent.HIGHEST_RISK),
            ("Which vulnerabilities contribute most to expected losses?", QueryIntent.TOP_LOSS_DRIVERS),
            ("What are our primary loss drivers?", QueryIntent.TOP_LOSS_DRIVERS),
            ("If I spend ₹50 Lakhs, which controls should I fund?", QueryIntent.BUDGET_ALLOCATION),
            ("Optimize portfolio with $1M budget", QueryIntent.BUDGET_ALLOCATION),
            ("What if we patch MOVEit immediately?", QueryIntent.WHAT_IF_SCENARIO),
            ("What is the ROI if we enforce MFA on all admin accounts?", QueryIntent.WHAT_IF_SCENARIO),
            ("What will it cost us to delay patching Log4j for 30 days?", QueryIntent.REMEDIATION_DELAY),
            ("What is the cost of 60 days delay for CVE-2023-34362?", QueryIntent.REMEDIATION_DELAY),
            ("Are we compliant with RBI and SEBI cybersecurity frameworks?", QueryIntent.COMPLIANCE_STATUS),
            ("Show compliance status across frameworks", QueryIntent.COMPLIANCE_STATUS),
        ],
    )
    def test_nlq_all_six_intent_categories(
        self, parser: NLQParser, query_text: str, expected_intent: QueryIntent
    ):
        """Validates intent classification across all 6 core executive query categories."""
        srq = parser.parse(query_text)
        assert srq.intent == expected_intent, f"Query '{query_text}' mapped to {srq.intent}, expected {expected_intent}"

    def test_nlq_entity_extraction(self, parser: NLQParser):
        """Validates extraction of CVEs, frameworks, assets, and controls."""
        q = "What is the cost of 30 days delay for CVE-2023-34362 on Core Banking Database under RBI CSF and MFA?"
        srq = parser.parse(q)

        assert "CVE-2023-34362" in srq.entities.cves
        assert "RBI Cyber Security Framework" in srq.entities.frameworks
        assert "Core Banking Database" in srq.entities.assets
        assert "MFA" in srq.entities.controls
        assert srq.time_horizon_days == 30

    def test_nlq_router_dispatch(self, sample_findings: List[NormalizedFinding]):
        """Validates execution routing across different intents."""
        router = NLQRouter()
        context = {"findings": sample_findings}

        # 1. Highest Risk
        res1 = router.route_and_execute("What is our highest financial cyber risk today?", context)
        assert "CVE-2023-34362" in res1["headline_answer"] or "VULN-001" in res1["headline_answer"]

        # 2. Budget Allocation
        res2 = router.route_and_execute("Optimize portfolio with ₹50 Lakhs budget", context)
        assert "₹5,000,000" in res2["headline_answer"]
        assert len(res2["bulleted_recommendations"]) > 0

        # 3. What-If Scenario
        res3 = router.route_and_execute("What if we enforce MFA immediately?", context)
        assert "reduces Expected Annual Loss" in res3["headline_answer"]

    def test_nlq_convenience_function(self):
        """Validates functional parse_nlq_query matching e2e test expectations."""
        r = parse_nlq_query("Optimize portfolio with 50 Lakhs budget")
        assert r["intent"] in ("BUDGET_ALLOCATION", "OPTIMIZATION")
        assert r["currency"] == "INR"
        assert r["budget"] == 5_000_000.0


# =====================================================================
# 5. Executive Narrative Generator Tests
# =====================================================================

class TestExecutiveNarrativeGenerator:
    """Tests for F16: Plain-Language Executive Narrative Generator."""

    def test_currency_formatting(self):
        """Validates Indian and Western currency formatting rules."""
        # INR
        assert format_currency(48_200_000.0, "INR") == "₹4.82 Crore"
        assert format_currency(4_500_000.0, "INR") == "₹45.00 Lakhs"
        assert format_currency(50_000.0, "INR") == "₹50,000"

        # USD
        assert format_currency(1_500_000_000.0, "USD") == "$1.50B"
        assert format_currency(2_500_000.0, "USD") == "$2.50M"
        assert format_currency(450_000.0, "USD") == "$450.0k"

    def test_narrative_generator_output(self):
        """Validates generated board-ready executive risk narrative."""
        report = generate_executive_narrative(
            eal=48_200_000.0,
            var_95=124_000_000.0,
            top_asset="Core Payment Gateway",
            spend=4_500_000.0,
            rosi=223.0,
            currency="INR",
            top_cve="CVE-2023-34362",
            trajectory_growth=15.0,
        )

        assert isinstance(report, NarrativeReport)
        # Verify key metrics exist in body
        assert "₹4.82 Crore" in report.board_ready_narrative
        assert "Core Payment Gateway" in report.board_ready_narrative
        assert "223% Return on Security Investment" in report.board_ready_narrative
        assert "₹45.00 Lakhs" in report.board_ready_narrative
        assert len(report.bulleted_recommendations) >= 2
        assert "15.0% surge" in report.trajectory_summary
        assert "RBI CSF" in report.compliance_note
