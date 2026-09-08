"""
tests/adversarial/test_m3_decision_support_stress.py - Adversarial Stress Tests for Milestone 3.

Empirical Challenger 2 Test Suite probing:
1. Deterministic NLQ parser and query router under complex colloquial executive phrasing.
2. Extreme Indian and Western financial notations, including raw ISO currency codes (10000000 INR),
   leading decimals (.5M, .5 Crore), and mixed/conflicting currency symbols.
3. Spurious currency detection (e.g., English plural 'rs ' triggering INR).
4. Malformed, empty, None, and ambiguous queries: router fallback and exception resilience.
5. Threat trajectory forecasting stability under rapid zero-day acceleration, extreme velocity,
   and boundary EPSS/resistance values (including 0.0 falsy imputation).
6. Compounding delayed remediation and What-If counterfactual stability.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List
import numpy as np
import pytest

from src.config import USD_TO_INR_RATE
from src.decision_support.delay_cost import (
    DelayedRemediationModel,
    calculate_delay_cost,
)
from src.decision_support.narrative import (
    ExecutiveNarrativeGenerator,
    format_currency,
)
from src.decision_support.nlq_parser import (
    NLQParser,
    NLQRouter,
    QueryIntent,
    StructuredRiskQuery,
    parse_nlq_query,
)
from src.decision_support.trajectory import (
    ThreatTrajectoryForecaster,
    TrajectoryForecast,
    TrajectoryScenario,
)
from src.decision_support.what_if import (
    WhatIfEngine,
    run_counterfactual_simulation,
)
from src.telemetry.models import NormalizedFinding, SeverityLevel, TelemetryDomain


# =====================================================================
# Fixtures
# =====================================================================

@pytest.fixture
def parser() -> NLQParser:
    return NLQParser()


@pytest.fixture
def router() -> NLQRouter:
    return NLQRouter()


@pytest.fixture
def mock_findings() -> List[NormalizedFinding]:
    return [
        NormalizedFinding(
            finding_id="VULN-MOVEIT-01",
            asset_id="asset-core-db-01",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.CRITICAL,
            title="CVE-2023-34362 MOVEit Transfer SQL Injection",
            cvss_score=9.8,
            epss_score=0.92,
            cisa_kev=True,
            threat_event_frequency=15.0,
            resistance_strength=0.15,
        ),
        NormalizedFinding(
            finding_id="SIEM-STUFFING-01",
            asset_id="asset-payment-gw-01",
            domain=TelemetryDomain.SIEM,
            severity=SeverityLevel.HIGH,
            title="Credential Stuffing Campaign on Payment Gateway",
            cvss_score=7.8,
            epss_score=0.45,
            cisa_kev=False,
            threat_event_frequency=25.0,
            resistance_strength=0.35,
        ),
        NormalizedFinding(
            finding_id="IAM-ROOT-NO-MFA",
            asset_id="asset-cloud-iam-01",
            domain=TelemetryDomain.IAM,
            severity=SeverityLevel.CRITICAL,
            title="Root Account Without Multi-Factor Authentication",
            cvss_score=9.0,
            epss_score=0.70,
            cisa_kev=False,
            threat_event_frequency=12.0,
            resistance_strength=0.10,
        ),
    ]


# =====================================================================
# 1. Financial Notation Stress Tests
# =====================================================================

class TestAdversarialCurrencyNotations:
    """Stress tests parsing of extreme and colloquial Indian and Western financial notations."""

    def test_standard_indian_notations(self, parser: NLQParser):
        """Validates canonical Indian currency parsing."""
        cases = [
            ("₹1.5 Crore", "INR", 15_000_000.0),
            ("1.5 Crores", "INR", 15_000_000.0),
            ("2 Cr", "INR", 20_000_000.0),
            ("25 Lacs", "INR", 2_500_000.0),
            ("25 Lakhs", "INR", 2_500_000.0),
            ("25L", "INR", 2_500_000.0),
            ("₹50,00,000", "INR", 5_000_000.0),
        ]
        for text, exp_curr, exp_val in cases:
            curr, b_src, b_inr, b_usd = parser.extract_currency_and_budget(text)
            assert curr == exp_curr, f"Failed currency for '{text}': got {curr}, expected {exp_curr}"
            assert b_src is not None, f"Failed budget extraction for '{text}'"
            assert math.isclose(b_src, exp_val, rel_tol=1e-3), f"Failed value for '{text}': got {b_src}, expected {exp_val}"

    def test_standard_western_notations(self, parser: NLQParser):
        """Validates canonical Western currency parsing."""
        cases = [
            ("$0.5M", "USD", 500_000.0),
            ("0.5 Million", "USD", 500_000.0),
            ("$1M", "USD", 1_000_000.0),
            ("$500k", "USD", 500_000.0),
            ("250 K", "USD", 250_000.0),
            ("$1B", "USD", 1_000_000_000.0),
            ("$1,000,000", "USD", 1_000_000.0),
        ]
        for text, exp_curr, exp_val in cases:
            curr, b_src, b_inr, b_usd = parser.extract_currency_and_budget(text)
            assert curr == exp_curr, f"Failed currency for '{text}': got {curr}, expected {exp_curr}"
            assert b_src is not None, f"Failed budget extraction for '{text}'"
            assert math.isclose(b_src, exp_val, rel_tol=1e-3), f"Failed value for '{text}': got {b_src}, expected {exp_val}"

    def test_raw_iso_currency_codes_investigation(self, parser: NLQParser):
        """
        Adversarial Finding 1:
        Queries containing raw ISO currency codes without ₹ or $ symbols
        (e.g., '10000000 INR', '10,000,000 INR', '1000000 USD') are detected as the correct currency,
        but budget_amount fails to extract and drops to None.
        """
        # Test 10000000 INR
        curr, b_src, b_inr, b_usd = parser.extract_currency_and_budget("Optimize with 10000000 INR")
        assert curr == "INR"
        # Empirical finding: current implementation returns None because regex requires literal '₹'
        # Documenting actual behavior:
        is_none = (b_src is None)
        assert is_none, "Observed: 10000000 INR fails to match direct numeric regex which requires '₹'"

        # Test 1000000 USD
        curr_u, b_src_u, _, _ = parser.extract_currency_and_budget("Budget of 1000000 USD")
        assert curr_u == "USD"
        assert b_src_u is None, "Observed: 1000000 USD fails to match numeric regex which requires '$'"

    def test_leading_decimal_financial_shorthand_investigation(self, parser: NLQParser):
        """
        Adversarial Finding 2:
        Leading decimal notation without leading zero (e.g., '.5M', '$.5M', '₹.5 Crore')
        is parsed with a 10x inflation error because (\\d+(?:\\.\\d+)?) requires a leading digit,
        skipping '.' and matching '5M' ($5M instead of $0.5M).
        """
        curr, b_src, _, _ = parser.extract_currency_and_budget("Budget of .5M")
        # Empirical finding: .5M matches '5M', resulting in 5,000,000 instead of 500,000
        assert b_src == 5_000_000.0, f"Observed 10x inflation: .5M matched as 5M ({b_src})"

        curr_cr, b_cr, _, _ = parser.extract_currency_and_budget("Budget of ₹.5 Crore")
        # Empirical finding: ₹.5 Crore matches '5 Crore', resulting in 50,000,000 instead of 5,000,000
        assert b_cr == 50_000_000.0, f"Observed 10x inflation: ₹.5 Crore matched as 5 Crore ({b_cr})"

    def test_spurious_inr_detection_from_english_plurals(self, parser: NLQParser):
        """
        Adversarial Finding 3:
        In src/decision_support/nlq_parser.py:199:
        'has_inr_symbol = ... or "rs " in q ...'
        Because 'rs ' is checked as a raw substring in lowercase query, any English plural word
        ending in 'rs' followed by a space (e.g. 'drivers ', 'users ', 'servers ', 'members ')
        falsely flags INR currency!
        """
        # Query contains zero Indian currency cues, but contains word 'drivers '
        curr_drivers, _, _, _ = parser.extract_currency_and_budget("Who are the top loss drivers driving losses?")
        assert curr_drivers == "INR", (
            f"Observed spurious INR: 'drivers ' contains substring 'rs ', forcing INR instead of USD"
        )

        curr_users, _, _, _ = parser.extract_currency_and_budget("How many privileged users are unmonitored?")
        assert curr_users == "INR", (
            f"Observed spurious INR: 'users ' contains substring 'rs '"
        )

        curr_servers, _, _, _ = parser.extract_currency_and_budget("Check database servers vulnerability posture")
        assert curr_servers == "INR", (
            f"Observed spurious INR: 'servers ' contains substring 'rs '"
        )

    def test_conflicting_currency_symbol_precedence(self, parser: NLQParser):
        """
        Adversarial Finding 4:
        Conflicting cues like '$50 Lakhs' or '₹10M'.
        Disambiguation logic at lines 261-265 overrides detected_currency without a 'budget_amount is None'
        guard, causing unit magnitude and currency symbol mismatches.
        """
        curr_lakh, b_lakh, _, _ = parser.extract_currency_and_budget("$50 Lakhs")
        # '50 Lakhs' extracted 5,000,000, but '$' overrode detected_currency to USD
        assert curr_lakh == "USD"
        assert b_lakh == 5_000_000.0

        curr_m, b_m, _, _ = parser.extract_currency_and_budget("₹10M")
        # '10M' extracted 10,000,000, but '₹' overrode detected_currency to INR
        assert curr_m == "INR"
        assert b_m == 10_000_000.0


# =====================================================================
# 2. Colloquial & Executive Phrasing Stress Tests
# =====================================================================

class TestAdversarialColloquialAndExecutivePhrasing:
    """Stress tests real-world phrasing from non-technical C-suite and board members."""

    @pytest.mark.parametrize(
        "query, expected_intent",
        [
            ("Where are our biggest financial bleeding points?", QueryIntent.HIGHEST_RISK),
            ("Can we afford to delay patching the database server by 2 months?", QueryIntent.REMEDIATION_DELAY),
            ("How much risk do we buy down if we invest ₹1.5 Crore in MFA and EDR?", QueryIntent.BUDGET_ALLOCATION),
            ("Does our current cloud posture pass muster with SEBI and RBI auditors?", QueryIntent.COMPLIANCE_STATUS),
            ("Who are the worst offenders driving expected annual loss?", QueryIntent.TOP_LOSS_DRIVERS),
            ("Can you model a counterfactual if MOVEit is remediated by Friday?", QueryIntent.WHAT_IF_SCENARIO),
        ],
    )
    def test_robust_executive_phrasings(self, parser: NLQParser, query: str, expected_intent: QueryIntent):
        """Verifies that key executive queries are correctly classified."""
        srq = parser.parse(query)
        assert srq.intent == expected_intent, f"Query '{query}' classified as {srq.intent}, expected {expected_intent}"
        assert srq.confidence >= 0.90

    @pytest.mark.parametrize(
        "query",
        [
            ("What is our single worst vulnerability in dollar terms?"),
            ("What keeps the CISO awake at night regarding cyber loss?"),
            ("Tell me our bottom line cyber VaR."),
            ("What is our 90-day exposure if an unpatched zero-day explodes?"),
        ],
    )
    def test_edge_case_executive_phrasing_gap_investigation(self, parser: NLQParser, query: str):
        """
        Adversarial Finding 5:
        Executive phrasing using terms like 'dollar terms', 'cyber loss', 'bottom line cyber VaR'
        fails regex patterns and falls back to UNKNOWN with 0.30 confidence.
        """
        srq = parser.parse(query)
        # Empirical finding: these colloquial phrasings are currently UNKNOWN
        assert srq.intent == QueryIntent.UNKNOWN
        assert math.isclose(srq.confidence, 0.30)

    def test_extracted_entities_in_colloquial_queries(self, parser: NLQParser):
        """Validates entity extraction under complex conversational phrasing."""
        q = (
            "Under RBI CSF and SEBI CSCRF guidelines, simulate the impact of enforcing MFA and EDR "
            "on Core Banking Database for CVE-2023-34362."
        )
        srq = parser.parse(q)
        assert "CVE-2023-34362" in srq.entities.cves
        assert "RBI Cyber Security Framework" in srq.entities.frameworks
        assert "SEBI CSCRF" in srq.entities.frameworks
        assert "MFA" in srq.entities.controls
        assert "EDR" in srq.entities.controls
        assert "Core Banking Database" in srq.entities.assets


# =====================================================================
# 3. Malformed, Empty & Edge-Case Queries Stress Tests
# =====================================================================

class TestAdversarialMalformedAndBoundaryQueries:
    """Stress tests parser and router against empty, malformed, injection, and non-string inputs."""

    def test_empty_and_whitespace_query(self, parser: NLQParser, router: NLQRouter):
        """Validates that empty and whitespace queries return gracefully without crashing."""
        for empty_q in ["", "   ", "\t\n\r  "]:
            srq = parser.parse(empty_q)
            assert srq.intent == QueryIntent.UNKNOWN
            assert srq.confidence == 0.0

            resp = router.route_and_execute(srq)
            assert isinstance(resp, dict)
            assert "headline_answer" in resp
            assert "board_ready_narrative" in resp
            assert "Query received" in resp["headline_answer"]

    def test_malicious_and_injection_strings(self, parser: NLQParser, router: NLQRouter):
        """Validates resilience against SQLi, XSS, and non-alphanumeric payloads."""
        malicious = [
            "' OR '1'='1; DROP TABLE findings; --",
            "<script>alert('XSS vulnerability')</script>",
            "???!!! @#$%^&*()_+~`|}{[]:;?><,./",
            "🚨💰💸💀🔥🎯",
            "\x00\x01\x02\x03\x04\x05",
        ]
        for payload in malicious:
            srq = parser.parse(payload)
            assert isinstance(srq, StructuredRiskQuery)
            resp = router.route_and_execute(srq)
            assert isinstance(resp, dict)
            assert resp["query"] == payload

    def test_massive_length_query_performance(self, parser: NLQParser, router: NLQRouter):
        """Stress tests parsing with a 10,000-character repetitive query."""
        massive_q = "What is our highest risk today? " * 350  # ~11,000 chars
        srq = parser.parse(massive_q)
        assert srq.intent == QueryIntent.HIGHEST_RISK
        resp = router.route_and_execute(srq)
        assert isinstance(resp, dict)

    def test_none_input_handling_investigation(self, parser: NLQParser, router: NLQRouter):
        """
        Adversarial Finding 6:
        Passing None to NLQParser.parse() raises AttributeError: 'NoneType' object has no attribute 'strip'.
        Passing None to NLQRouter.route_and_execute() raises AttributeError: 'NoneType' object has no attribute 'currency'.
        Neither method has defensive type-checking for null inputs.
        """
        with pytest.raises(AttributeError) as excinfo_parser:
            parser.parse(None)  # type: ignore
        assert "has no attribute 'strip'" in str(excinfo_parser.value)

        with pytest.raises(AttributeError) as excinfo_router:
            router.route_and_execute(None)  # type: ignore
        assert "has no attribute 'currency'" in str(excinfo_router.value)

    def test_off_topic_ambiguous_queries_router_fallback(self, router: NLQRouter, mock_findings):
        """
        Validates router response when query is completely ambiguous.
        Confirms graceful response dictionary is produced.
        """
        ambiguous_queries = [
            "What is the weather in New Delhi?",
            "Can you tell me a good joke?",
            "System status check 1 2 3",
            "Random uncalibrated sentence",
        ]
        for q in ambiguous_queries:
            resp = router.route_and_execute(q, context={"findings": mock_findings})
            assert resp["intent"] == QueryIntent.UNKNOWN.value
            assert "Query received. Please specify your risk" in resp["headline_answer"]
            assert "board_ready_narrative" in resp


# =====================================================================
# 4. Trajectory Forecasting Under Rapid Zero-Day Acceleration
# =====================================================================

class TestAdversarialZeroDayTrajectoryForecasting:
    """Stress tests threat trajectory forecasting under extreme zero-day acceleration."""

    def test_rapid_zero_day_weaponization_surge(self, mock_findings: List[NormalizedFinding]):
        """
        Simulates an emergency zero-day discovery with rapid weaponization:
        Initial EPSS = 0.01, velocity = 0.05/day (25x normal), acceleration = 0.01/day^2.
        CISA KEV weaponization triggered.
        """
        zero_day = NormalizedFinding(
            finding_id="0DAY-RCE-CORE-01",
            asset_id="asset-core-db-01",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.CRITICAL,
            title="Zero-Day Remote Code Execution in Core Banking",
            cvss_score=10.0,
            epss_score=0.01,
            cisa_kev=False,
            threat_event_frequency=5.0,
            resistance_strength=0.10,
        )

        forecaster = ThreatTrajectoryForecaster(
            c1=1.0, c2=0.5, omega_kev=0.10, gamma_ext=1.5, monte_carlo_trials=1000
        )
        forecast = forecaster.forecast_trajectory(
            findings=[zero_day],
            horizons=[0, 30, 60, 90],
            seed=42,
            default_velocity=0.05,
            default_acceleration=0.01,
        )

        pess = forecast.pessimistic_trajectory
        assert len(pess) == 4

        # 1. Numerical stability: All values are finite and positive
        for pt in pess:
            assert not math.isnan(pt.eal) and pt.eal > 0.0
            assert not math.isnan(pt.var_90) and pt.var_90 > 0.0
            assert not math.isnan(pt.var_95) and pt.var_95 > 0.0
            assert not math.isnan(pt.var_99) and pt.var_99 > 0.0
            # VaR strict monotonic ordering: VaR 90 < VaR 95 < VaR 99
            assert pt.var_90 < pt.var_95 < pt.var_99, (
                f"VaR ordering violated at day {pt.days}: {pt.var_90} < {pt.var_95} < {pt.var_99}"
            )
            # EPSS remains within [0.0, 1.0]
            assert 0.0 <= pt.epss_mean <= 1.0

        # 2. Monotonic risk escalation under pessimistic surge
        t0, t30, t60, t90 = pess
        assert t30.eal > t0.eal
        assert t60.eal > t30.eal
        assert t90.eal > t60.eal

        # 3. Scenario ordering across horizons: Pessimistic >= Baseline >= Optimistic
        base = forecast.baseline_trajectory
        opt = forecast.optimistic_trajectory
        for i in range(1, 4):  # horizons 30, 60, 90
            assert pess[i].eal >= base[i].eal, f"Pessimistic EAL must exceed baseline at horizon {pess[i].days}"
            assert base[i].eal >= opt[i].eal, f"Baseline EAL must exceed optimistic at horizon {base[i].days}"

    def test_extreme_velocity_and_acceleration_clamping(self):
        """Stress tests numerical clamping when velocity and acceleration are absurdly huge."""
        forecaster = ThreatTrajectoryForecaster()

        # Extreme positive velocity & acceleration
        proj_huge = forecaster.project_epss(
            epss_current=0.5, velocity=100.0, acceleration=1000.0, cisa_kev=True, tau_days=30
        )
        assert proj_huge == 0.999, f"Expected upper clamping at 0.999, got {proj_huge}"

        # Extreme negative velocity & acceleration
        proj_neg = forecaster.project_epss(
            epss_current=0.5, velocity=-100.0, acceleration=-1000.0, cisa_kev=False, tau_days=30
        )
        assert proj_neg == 0.001, f"Expected lower clamping at 0.001, got {proj_neg}"

    def test_zero_epss_falsy_imputation_investigation(self):
        """
        Adversarial Finding 7:
        In src/decision_support/trajectory.py:149:
        current_epss = float(getattr(finding, 'epss_score', 0.1) or 0.1)
        Because 0.0 is falsy in Python, if a vulnerability has epss_score = 0.0,
        it evaluates to 0.1!
        Similarly, resistance_strength = 0.0 evaluates to 0.5 (line 152)!
        """
        zero_finding = NormalizedFinding(
            finding_id="ZERO-EPSS-01",
            asset_id="asset-core-db-01",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.LOW,
            title="Finding with true 0.0 EPSS",
            cvss_score=3.0,
            epss_score=0.0,
            threat_event_frequency=1.0,
            resistance_strength=0.0,
        )

        forecaster = ThreatTrajectoryForecaster(monte_carlo_trials=500)
        proj = forecaster.project_finding(zero_finding, tau_days=30, scenario=TrajectoryScenario.BASELINE)

        # Empirical finding: epss_score became 0.1 (not 0.0)
        assert proj.epss_score >= 0.1, (
            f"Observed: epss_score=0.0 was overwritten with 0.1 due to '0.0 or 0.1' falsy check"
        )
        # Empirical finding: resistance_strength became 0.5 (not 0.0)
        assert proj.resistance_strength >= 0.5, (
            f"Observed: resistance_strength=0.0 was overwritten with 0.5 due to '0.0 or 0.5'"
        )


# =====================================================================
# 5. Compounding Delayed Remediation & What-If Stress Tests
# =====================================================================

class TestAdversarialDelayCostAndWhatIfStress:
    """Stress tests delayed remediation cost model and What-If counterfactual engine."""

    def test_extreme_delay_horizons_convexity(self, mock_findings: List[NormalizedFinding]):
        """Validates compounding convexity over 180 and 365-day delays without float overflow."""
        model = DelayedRemediationModel(base_hazard_accel=0.015)
        curve = model.compute_daily_curve(findings=mock_findings, max_days=365)

        assert len(curve) == 366  # day 0 to 365
        c0 = curve[0].total_cost_of_delay_usd
        c90 = curve[90].total_cost_of_delay_usd
        c180 = curve[180].total_cost_of_delay_usd
        c365 = curve[365].total_cost_of_delay_usd

        assert c0 == 0.0
        assert c90 > 0.0
        assert c180 > 2.0 * c90, f"Convexity failed: c180={c180}, c90={c90}"
        assert c365 > 2.0 * c180, f"Convexity failed: c365={c365}, c180={c180}"

        # Breach probability surge remains strictly within [0.0, 1.0)
        for d in [30, 90, 180, 365]:
            p = curve[d].breach_probability_in_window
            assert 0.0 < p < 1.0, f"Breach probability surge {p} out of bounds at day {d}"

    def test_what_if_complete_portfolio_elimination(self, mock_findings: List[NormalizedFinding]):
        """Validates counterfactual simulation when 100% of vulnerabilities are patched."""
        res = run_counterfactual_simulation(
            baseline_findings=mock_findings,
            mitigated_findings=[],  # All findings patched
            seed=42,
            trials=1000,
        )
        assert res.mitigated_eal == 0.0
        assert res.delta_eal == res.baseline_eal
        assert math.isclose(res.risk_reduction_pct, 100.0, rel_tol=1e-5)
        assert res.delta_var_95 > 0.0
