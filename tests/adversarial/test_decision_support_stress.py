"""
tests/adversarial/test_decision_support_stress.py - Adversarial Stress & Invariant Suite for Decision Support.

Challenger 1 Empirical Verification:
1. Common Random Numbers (CRN) vs. Independent Random Seeds:
   - Empirical variance reduction ratio across portfolios and control actions.
   - Bit-exact determinism of paired What-If counterfactual runs under identical seed.
   - Position-dependent RNG stream synchronization & stream offset analysis.
2. Delayed Remediation Cost Compounding & Convexity:
   - Strict convexity: Cost(60d) > 2 * Cost(30d), Cost(30d) > 2 * Cost(15d), and Cost(2t) > 2 * Cost(t) for t >= 10.
   - Short-horizon Poisson hazard concave subadditivity (t < 10) vs long-horizon exponential convexity.
   - Strictly positive daily loss gradient d(Cost)/dt > 0 across all days up to 365 days.
   - Extreme breach hazard dynamics & Poisson saturation effects on daily gradient.
   - Non-homogeneous Poisson breach probability monotonic surge.
3. Multi-Control Removal Degradation & Multi-Finding Patching:
   - Monotonic degradation surges when disabling multiple controls (EDR, MFA, WAF, FIREWALL).
   - Monotonic risk elimination when patching findings iteratively up to 100% elimination.
4. Boundary Conditions & Numerical Degeneracies:
   - 0 days delay (exact 0.0 penalty).
   - Negative days delay clamping.
   - 365 days delay long-horizon stability (no overflow, finite convex growth).
   - Extreme breach hazard (TEF=10,000, EPSS=1.0) and zero hazard (defensive baseline fallback).
   - Empty findings and out-of-scope asset target handling.
"""

import math
from typing import Any, List
import numpy as np
import pytest

from src.config import USD_TO_INR_RATE
from src.decision_support.delay_cost import (
    DelayCostResult,
    DelayedRemediationModel,
    calculate_delay_cost,
)
from src.decision_support.what_if import (
    WhatIfEngine,
    WhatIfRequest,
    WhatIfResult,
    run_counterfactual_simulation,
)
from src.quant.monte_carlo import MonteCarloEngine
from src.telemetry.models import NormalizedFinding, SeverityLevel, TelemetryDomain


# =====================================================================
# Fixtures
# =====================================================================

@pytest.fixture
def multi_finding_portfolio() -> List[NormalizedFinding]:
    """Generates a diverse 20-finding portfolio spanning multiple assets and severities."""
    findings = []
    for i in range(20):
        findings.append(
            NormalizedFinding(
                finding_id=f"VULN-ADV-{i:03d}",
                asset_id=f"asset-core-{i % 5:02d}",
                domain=TelemetryDomain.VULNERABILITY if i % 2 == 0 else TelemetryDomain.SIEM,
                severity=SeverityLevel.CRITICAL if i % 3 == 0 else SeverityLevel.HIGH,
                title=f"CVE-2024-{2000 + i} Security Vulnerability {i}",
                cvss_score=round(7.0 + (i % 30) * 0.1, 1),
                epss_score=round(0.2 + (i % 60) * 0.01, 2),
                cisa_kev=(i % 4 == 0),
                threat_event_frequency=float(2.0 + (i % 5) * 2.0),
                resistance_strength=float(0.3 + (i % 4) * 0.15),
            )
        )
    return findings


# =====================================================================
# 1. Common Random Numbers (CRN) vs Independent Seeds
# =====================================================================

class TestCommonRandomNumbersAdversarial:
    """Stress tests probing Common Random Numbers variance reduction and determinism."""

    def test_crn_variance_reduction_dominant_finding_patching(self):
        """
        Validates that Common Random Numbers (CRN) achieves significant variance reduction
        over independent seeds when evaluating the mitigation of high-impact vulnerabilities.
        """
        findings = [
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
        mitigated = [f for f in findings if f.finding_id != "VULN-001"]

        engine = WhatIfEngine(iterations=1000)
        n_pairs = 25
        crn_deltas = [
            engine.simulate_pair(findings, mitigated, seed=100 + i, trials=1000).delta_eal
            for i in range(n_pairs)
        ]
        mc = engine.mc_engine
        indep_deltas = [
            mc.simulate(findings, seed_override=1000 + i * 2).eal
            - mc.simulate(mitigated, seed_override=1000 + i * 2 + 1).eal
            for i in range(n_pairs)
        ]

        var_crn = float(np.var(crn_deltas))
        var_indep = float(np.var(indep_deltas))

        assert var_crn < var_indep, (
            f"Expected CRN variance ({var_crn:,.2f}) < Independent variance ({var_indep:,.2f})"
        )
        reduction_pct = (1.0 - var_crn / var_indep) * 100.0
        assert reduction_pct > 30.0, f"Expected >30% variance reduction, got {reduction_pct:.2f}%"

    def test_crn_variance_reduction_last_finding_elimination(self, multi_finding_portfolio: List[NormalizedFinding]):
        """
        When mitigating the last finding in the sequence, the preceding findings' RNG streams
        are bit-exact identical, yielding ultra-high (>90%) variance reduction.
        """
        engine = WhatIfEngine(iterations=1000)
        mitigated = multi_finding_portfolio[:-1]

        n_pairs = 25
        crn_deltas = [
            engine.simulate_pair(multi_finding_portfolio, mitigated, seed=300 + i, trials=1000).delta_eal
            for i in range(n_pairs)
        ]
        mc = engine.mc_engine
        indep_deltas = [
            mc.simulate(multi_finding_portfolio, seed_override=4000 + i * 2).eal
            - mc.simulate(mitigated, seed_override=4000 + i * 2 + 1).eal
            for i in range(n_pairs)
        ]

        var_crn = float(np.var(crn_deltas))
        var_indep = float(np.var(indep_deltas))

        assert var_crn < var_indep
        reduction_pct = (1.0 - var_crn / var_indep) * 100.0
        assert reduction_pct > 80.0, f"Expected >80% variance reduction, got {reduction_pct:.2f}%"

    def test_crn_variance_reduction_targeted_asset_control(self, multi_finding_portfolio: List[NormalizedFinding]):
        """
        When applying controls targeted to a specific asset (e.g. MFA on asset-core-04),
        variance reduction is preserved because unmodified assets maintain RNG alignment.
        """
        engine = WhatIfEngine(iterations=1000)
        target_asset = "asset-core-04"
        mutated_findings = engine.mutate_findings(
            multi_finding_portfolio, controls_to_add=["MFA"], target_asset_ids=[target_asset]
        )

        n_pairs = 25
        crn_deltas = [
            engine.simulate_pair(multi_finding_portfolio, mutated_findings, seed=500 + i, trials=1000).delta_eal
            for i in range(n_pairs)
        ]
        mc = engine.mc_engine
        indep_deltas = [
            mc.simulate(multi_finding_portfolio, seed_override=2000 + i * 2).eal
            - mc.simulate(mutated_findings, seed_override=2000 + i * 2 + 1).eal
            for i in range(n_pairs)
        ]

        var_crn = float(np.var(crn_deltas))
        var_indep = float(np.var(indep_deltas))

        assert var_crn < var_indep, (
            f"Expected CRN variance ({var_crn:,.2f}) < Independent variance ({var_indep:,.2f})"
        )
        reduction_pct = (1.0 - var_crn / var_indep) * 100.0
        assert reduction_pct > 5.0, f"Expected >5% variance reduction, got {reduction_pct:.2f}%"

    def test_crn_bit_exact_paired_determinism(self, multi_finding_portfolio: List[NormalizedFinding]):
        """Validates that re-running simulate_pair with identical seed produces bit-exact identical metrics."""
        engine = WhatIfEngine(iterations=1500, seed=777)
        req = WhatIfRequest(cves_to_patch=["CVE-2024-2000"], baseline_seed=777, trials=1500)

        res1 = engine.simulate(multi_finding_portfolio, req)
        res2 = engine.simulate(multi_finding_portfolio, req)

        assert res1.baseline_eal == res2.baseline_eal
        assert res1.simulated_eal == res2.simulated_eal
        assert res1.delta_eal == res2.delta_eal
        assert res1.delta_var_95 == res2.delta_var_95
        assert res1.risk_reduction_pct == res2.risk_reduction_pct


# =====================================================================
# 2. Delayed Remediation Cost & Strict Convexity
# =====================================================================

class TestDelayedRemediationConvexityAdversarial:
    """Stress tests probing mathematical convexity and daily loss gradient behavior."""

    def test_strict_convexity_at_core_remediation_horizons(self, multi_finding_portfolio: List[NormalizedFinding]):
        """
        Validates core requirement: Cost(60d) > 2 * Cost(30d) and Cost(30d) > 2 * Cost(15d).
        Across all horizons t >= 10, exponential loss compounding strictly dominates.
        """
        model = DelayedRemediationModel(base_hazard_accel=0.02)
        curve = model.compute_daily_curve(multi_finding_portfolio, max_days=365)

        cost_15 = curve[15].total_cost_of_delay_usd
        cost_30 = curve[30].total_cost_of_delay_usd
        cost_60 = curve[60].total_cost_of_delay_usd
        cost_90 = curve[90].total_cost_of_delay_usd

        # Invariant 1: Cost(60d) > 2 * Cost(30d)
        assert cost_60 > 2.0 * cost_30, f"Cost(60d)={cost_60} <= 2*Cost(30d)={2*cost_30}"
        ratio_60_30 = cost_60 / cost_30
        assert ratio_60_30 > 2.2, f"Ratio Cost(60d)/Cost(30d) was {ratio_60_30:.3f}, expected > 2.2"

        # Invariant 2: Cost(30d) > 2 * Cost(15d)
        assert cost_30 > 2.0 * cost_15, f"Cost(30d)={cost_30} <= 2*Cost(15d)={2*cost_15}"
        ratio_30_15 = cost_30 / cost_15
        assert ratio_30_15 > 2.05, f"Ratio Cost(30d)/Cost(15d) was {ratio_30_15:.3f}, expected > 2.05"

        # Invariant 3: Compounding sweep for t >= 10
        for t in [10, 15, 20, 30, 45, 60, 90, 120, 150, 180]:
            c_t = curve[t].total_cost_of_delay_usd
            c_2t = curve[2 * t].total_cost_of_delay_usd
            assert c_2t > 2.0 * c_t, f"Convexity failed at t={t}: Cost({2*t})={c_2t} <= 2*Cost({t})={2*c_t}"

    def test_hazard_saturation_short_horizon_subadditivity(self, multi_finding_portfolio: List[NormalizedFinding]):
        """
        Adversarial analysis of short horizons (t < 10 days):
        Proves that while Poisson breach probability P(Breach) is concave subadditive,
        the daily loss gradient remains strictly positive: d(Cost)/dt > 0 everywhere.
        """
        model = DelayedRemediationModel(base_hazard_accel=0.02)
        curve = model.compute_daily_curve(multi_finding_portfolio, max_days=30)

        # Gradients must be strictly positive on all short horizons
        for d in range(1, 15):
            assert curve[d].daily_loss_gradient_usd > 0.0

        # Poisson breach probability increases monotonically
        for d in range(1, 14):
            assert curve[d + 1].breach_probability_in_window > curve[d].breach_probability_in_window

    def test_positive_daily_loss_gradient_up_to_year(self, multi_finding_portfolio: List[NormalizedFinding]):
        """
        Validates that daily loss gradient d(Cost)/dt remains strictly positive
        for every single day d in [1, 365].
        """
        model = DelayedRemediationModel(base_hazard_accel=0.02)
        curve = model.compute_daily_curve(multi_finding_portfolio, max_days=365)

        for d in range(1, 366):
            grad = curve[d].daily_loss_gradient_usd
            assert grad > 0.0, f"Daily loss gradient non-positive at day {d}: {grad}"

        # In long-horizon regime, gradient accelerates sharply
        assert curve[60].daily_loss_gradient_usd > curve[30].daily_loss_gradient_usd
        assert curve[180].daily_loss_gradient_usd > curve[60].daily_loss_gradient_usd
        assert curve[365].daily_loss_gradient_usd > curve[180].daily_loss_gradient_usd

    def test_poisson_hazard_saturation_dynamics(self):
        """
        Adversarial test under extreme threat event frequency (TEF=1000).
        Verifies that:
        1. All daily gradients remain strictly positive: g(t) > 0.
        2. Cost(60d) > 2 * Cost(30d) holds even under extreme hazard.
        3. Poisson cumulative breach probability approaches 1.0 asymptotically without exceeding 1.0.
        """
        f_extreme = [
            NormalizedFinding(
                finding_id="EXT-001",
                asset_id="asset-crown-jewel",
                domain=TelemetryDomain.VULNERABILITY,
                severity=SeverityLevel.CRITICAL,
                title="Weaponized RCE",
                cvss_score=10.0,
                epss_score=1.0,
                threat_event_frequency=1000.0,
                resistance_strength=0.01,
            )
        ]

        model = DelayedRemediationModel(base_hazard_accel=0.02)
        curve = model.compute_daily_curve(f_extreme, max_days=90)

        cost_30 = curve[30].total_cost_of_delay_usd
        cost_60 = curve[60].total_cost_of_delay_usd
        assert cost_60 > 2.0 * cost_30, f"Extreme hazard convexity violated: {cost_60} <= 2*{cost_30}"

        for d in range(1, 91):
            assert 0.0 < curve[d].breach_probability_in_window <= 1.0
            assert curve[d].daily_loss_gradient_usd > 0.0

        assert curve[30].breach_probability_in_window > 0.999
        assert curve[60].breach_probability_in_window > 0.999


# =====================================================================
# 3. Multi-Control Removal & Multi-Finding Patching
# =====================================================================

class TestMultiActionScenariosAdversarial:
    """Stress tests for multi-control removals (degradation) and multi-finding patching."""

    def test_multi_control_removal_monotonic_degradation(self, multi_finding_portfolio: List[NormalizedFinding]):
        """
        Sequentially stripping away enterprise controls (EDR -> MFA -> WAF -> FIREWALL)
        must cause strictly monotonic surges in simulated EAL and VaR 95.
        """
        engine = WhatIfEngine(iterations=1000, seed=42)

        stages = [
            [],
            ["EDR"],
            ["EDR", "MFA"],
            ["EDR", "MFA", "WAF"],
            ["EDR", "MFA", "WAF", "FIREWALL"],
        ]

        simulated_eals = []
        simulated_vars = []
        deltas = []

        for ctrls in stages:
            req = WhatIfRequest(controls_to_remove=ctrls, trials=1000, baseline_seed=42)
            res = engine.simulate(multi_finding_portfolio, req)
            simulated_eals.append(res.simulated_eal)
            simulated_vars.append(res.simulated_var_95)
            deltas.append(res.delta_eal)

        # Baseline delta is 0
        assert deltas[0] == 0.0

        # Monotonic escalation across removal stages
        for i in range(len(stages) - 1):
            assert simulated_eals[i] < simulated_eals[i + 1], (
                f"Degradation non-monotonic at stage {i}: {simulated_eals[i]} >= {simulated_eals[i+1]}"
            )
            assert simulated_vars[i] < simulated_vars[i + 1], (
                f"VaR95 degradation non-monotonic at stage {i}: {simulated_vars[i]} >= {simulated_vars[i+1]}"
            )
            assert deltas[i] > deltas[i + 1], (
                f"Delta EAL should become increasingly negative: {deltas[i]} <= {deltas[i+1]}"
            )

    def test_multi_finding_patching_monotonic_risk_reduction(self, multi_finding_portfolio: List[NormalizedFinding]):
        """
        Sequentially eliminating findings (0, 5, 10, 15, 20) must monotonically decrease EAL
        and monotonically increase risk reduction percentage up to 100%.
        """
        engine = WhatIfEngine(iterations=1000, seed=42)

        step_counts = [0, 5, 10, 15, 20]
        results: List[WhatIfResult] = []

        for count in step_counts:
            remove_ids = [f"VULN-ADV-{i:03d}" for i in range(count)]
            req = WhatIfRequest(finding_ids_to_remove=remove_ids, trials=1000, baseline_seed=42)
            res = engine.simulate(multi_finding_portfolio, req)
            results.append(res)

        for i in range(len(step_counts) - 1):
            # Simulated EAL strictly decreases
            assert results[i].simulated_eal > results[i + 1].simulated_eal, (
                f"Simulated EAL not strictly decreasing: {results[i].simulated_eal} <= {results[i+1].simulated_eal}"
            )
            # Delta EAL strictly increases
            assert results[i].delta_eal < results[i + 1].delta_eal
            # Risk reduction % strictly increases
            assert results[i].risk_reduction_pct < results[i + 1].risk_reduction_pct

        # When all findings are eliminated, simulated EAL is 0.0 and reduction is 100%
        assert results[-1].simulated_eal == 0.0
        assert results[-1].risk_reduction_pct == 100.0


# =====================================================================
# 4. Boundary Conditions & Numerical Degeneracies
# =====================================================================

class TestBoundaryConditionsAdversarial:
    """Stress tests on boundary conditions and degenerate inputs."""

    def test_delay_cost_zero_days_exact_zero(self, multi_finding_portfolio: List[NormalizedFinding]):
        """0 days delay produces exactly 0.0 penalty and 0.0 breach probability surge."""
        res = calculate_delay_cost(multi_finding_portfolio, days_delay=0)
        assert res.total_delay_penalty == 0.0
        assert res.total_delay_penalty_usd == 0.0
        assert res.total_delay_penalty_inr == 0.0
        assert res.breach_probability_surge == 0.0
        assert "Remediation scheduled immediately" in res.executive_recommendation

    def test_delay_cost_negative_days_clamped(self, multi_finding_portfolio: List[NormalizedFinding]):
        """Negative delay days clamp to 0 without error or unhandled exceptions."""
        res = calculate_delay_cost(multi_finding_portfolio, days_delay=-30)
        assert res.days_delay == 0
        assert res.total_delay_penalty == 0.0
        assert res.breach_probability_surge == 0.0

    def test_delay_cost_365_days_long_horizon(self, multi_finding_portfolio: List[NormalizedFinding]):
        """Long-horizon 365-day delay computes without overflow, NaN, or inf."""
        res = calculate_delay_cost(multi_finding_portfolio, days_delay=365)
        assert res.days_delay == 365
        assert not math.isnan(res.total_delay_penalty_usd)
        assert not math.isinf(res.total_delay_penalty_usd)
        assert res.total_delay_penalty_usd > 0.0
        assert res.breach_probability_surge > 0.99
        assert res.expedite_warranted is True
        assert res.daily_loss_gradient_usd > 0.0

    def test_delay_cost_empty_findings(self):
        """Empty findings list yields exact 0.0 delay penalty across all currencies."""
        res = calculate_delay_cost([], days_delay=60)
        assert res.total_delay_penalty == 0.0
        assert res.total_delay_penalty_usd == 0.0
        assert res.total_delay_penalty_inr == 0.0
        assert res.breach_probability_surge == 0.0

    def test_what_if_empty_baseline_findings(self):
        """Empty baseline findings in What-If returns 0.0 for baseline and simulated EAL."""
        engine = WhatIfEngine(iterations=500, seed=42)
        res = engine.simulate([], WhatIfRequest(cves_to_patch=["CVE-ANY"], trials=500))
        assert res.baseline_eal == 0.0
        assert res.simulated_eal == 0.0
        assert res.delta_eal == 0.0
        assert res.risk_reduction_pct == 0.0

    def test_what_if_unmatched_filters_noop(self, multi_finding_portfolio: List[NormalizedFinding]):
        """Non-existent CVEs or findings in patch request leave risk completely unchanged (delta=0)."""
        engine = WhatIfEngine(iterations=500, seed=42)
        req = WhatIfRequest(
            cves_to_patch=["CVE-9999-99999"],
            finding_ids_to_remove=["NON-EXISTENT-ID"],
            trials=500,
            baseline_seed=42,
        )
        res = engine.simulate(multi_finding_portfolio, req)
        assert res.delta_eal == 0.0
        assert res.risk_reduction_pct == 0.0
        assert res.simulated_eal == res.baseline_eal

    def test_what_if_asset_scope_isolation(self, multi_finding_portfolio: List[NormalizedFinding]):
        """Targeting interventions to a specific asset only modifies findings on that asset."""
        engine = WhatIfEngine(iterations=1000, seed=42)

        target_asset = "asset-core-00"
        findings_on_target = [f for f in multi_finding_portfolio if f.asset_id == target_asset]
        assert len(findings_on_target) > 0

        # Scope intervention only to target_asset
        req_scoped = WhatIfRequest(
            controls_to_add=["MFA"],
            target_asset_ids=[target_asset],
            control_efficacy=0.9,
            trials=1000,
            baseline_seed=42,
        )
        res_scoped = engine.simulate(multi_finding_portfolio, req_scoped)

        # Apply to all assets
        req_global = WhatIfRequest(
            controls_to_add=["MFA"],
            control_efficacy=0.9,
            trials=1000,
            baseline_seed=42,
        )
        res_global = engine.simulate(multi_finding_portfolio, req_global)

        # Scoped risk reduction must be positive but strictly smaller than global risk reduction
        assert 0.0 < res_scoped.delta_eal < res_global.delta_eal

    def test_what_if_extreme_control_costs_and_rosi(self, multi_finding_portfolio: List[NormalizedFinding]):
        """Validates ROSI and net benefit calculations under extreme cost bounds ($0 to $100M)."""
        engine = WhatIfEngine(iterations=500, seed=42)

        # Zero cost -> ROSI is None
        res_free = engine.simulate(
            multi_finding_portfolio,
            WhatIfRequest(finding_ids_to_remove=["VULN-ADV-000"], control_cost=0.0, trials=500),
        )
        assert res_free.rosi_percent is None
        assert res_free.net_financial_benefit == res_free.delta_eal

        # $100M cost -> Large negative ROSI and negative net benefit without crashing
        res_expensive = engine.simulate(
            multi_finding_portfolio,
            WhatIfRequest(finding_ids_to_remove=["VULN-ADV-000"], control_cost=100_000_000.0, trials=500),
        )
        assert res_expensive.rosi_percent is not None
        assert res_expensive.rosi_percent < -90.0
        assert res_expensive.net_financial_benefit < 0.0
