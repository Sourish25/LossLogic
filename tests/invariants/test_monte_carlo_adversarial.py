"""
tests/invariants/test_monte_carlo_adversarial.py - Adversarial Stress Tests & Mathematical Invariants.

Challenger 1 empirical stress test harness probing:
1. VaR Subadditivity Failure: Empirical proof of textbook non-subadditivity of VaR 95th
   under independent low-probability fat-tailed risks (and coherence of CVaR 95th).
2. Rare Event Finite-Sample Zero Breach: Where N * LEF << 1 leads to EAL == 0 and flat VaR.
3. Strict Percentile Ordering: VaR 90th < VaR 95th < VaR 99th across trial counts (1k, 10k, 50k).
4. Loss Exceedance Curve Monotonicity: P(Loss >= x) strictly non-increasing across trial scales.
5. Bit-Exact Seed Determinism: Multi-threaded thread-safety and PRNG repeatability.
6. FAIR Mapper CVSS=0.0 / EPSS=0.0 Falsy Coercion: Behavioral evaluation.
7. Orphan Finding Telemetry Drop: Discrepancy between MonteCarloEngine and PortfolioEngine.
8. Duplicate Asset ID Double Counting: Impact of duplicate asset records on joint loss matrix.
9. Numeric Stability Under Extreme Asset Valuation ($1 Quadrillion).
10. Empty Finding LEC Contract Discrepancy between engines.
"""

import concurrent.futures
import math
from typing import Dict, List
import numpy as np
import pytest

from src.quant.fair_mapper import FairMapper
from src.quant.monte_carlo import MonteCarloEngine, simulate_asset_loss
from src.quant.portfolio import PortfolioEngine
from src.telemetry.generator import ApexEnterpriseGenerator
from tests.conftest import (
    AssetTier,
    DataSensitivity,
    MockAssetRecord,
    MockNormalizedFinding,
    SeverityLevel,
    TelemetryDomain,
)


@pytest.mark.invariants
class TestMonteCarloAdversarialSuite:
    """Adversarial suite designed to stress-test mathematical invariants and edge cases."""

    def test_adversarial_var_subadditivity_counterexample(self):
        """
        Adversarial Challenge: Subadditivity of VaR 95th (Artzner et al. 1999).
        When individual assets have breach probability P < 0.05 (e.g. ~3.5%), individual
        VaR 95th is near-zero ($1.00 after flat adjustment), but the portfolio union has
        breach probability > 0.05, causing Portfolio VaR 95th to surge ($66,440.57).
        This empirically proves that VaR is NOT subadditive.
        In contrast, CVaR 95th is coherent and strictly subadditive.
        """
        a1 = MockAssetRecord(
            asset_id="A1",
            name="Asset 1",
            business_unit="BU1",
            tier=AssetTier.TIER_3,
            data_sensitivity=DataSensitivity.INTERNAL,
            replacement_cost=100000.0,
            downtime_cost_per_hour=1000.0,
            asset_criticality_score=1.0,
        )
        a2 = MockAssetRecord(
            asset_id="A2",
            name="Asset 2",
            business_unit="BU1",
            tier=AssetTier.TIER_3,
            data_sensitivity=DataSensitivity.INTERNAL,
            replacement_cost=100000.0,
            downtime_cost_per_hour=1000.0,
            asset_criticality_score=1.0,
        )

        f1 = MockNormalizedFinding(
            finding_id="F1",
            asset_id="A1",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            title="Finding 1",
            cvss_score=7.0,
            epss_score=0.2,
            cisa_kev=False,
            threat_event_frequency=0.1,
            resistance_strength=0.5,
        )
        f2 = MockNormalizedFinding(
            finding_id="F2",
            asset_id="A2",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            title="Finding 2",
            cvss_score=7.0,
            epss_score=0.2,
            cisa_kev=False,
            threat_event_frequency=0.1,
            resistance_strength=0.5,
        )

        pe = PortfolioEngine(trials=10000, seed=42)
        res = pe.simulate_portfolio([f1, f2], [a1, a2])

        var_a1 = res.asset_risks["A1"].var_95
        var_a2 = res.asset_risks["A2"].var_95
        sum_var_95 = res.sum_asset_var_95
        ent_var_95 = res.enterprise_var_95

        # Individual VaRs are tiny ($1.0 due to flat adjustment floor)
        assert var_a1 <= 10.0
        assert var_a2 <= 10.0
        assert sum_var_95 <= 20.0

        # Enterprise VaR 95 surges above $50,000 because union exceedance probability > 5%
        assert ent_var_95 > 50000.0

        # Subadditivity violation: Portfolio VaR 95 >> Sum of standalone VaRs
        assert ent_var_95 > sum_var_95 * 1000.0

        # PortfolioEngine defensively clamps diversification_benefit to 0.0
        assert res.diversification_benefit == 0.0

        # In contrast, CVaR 95th IS subadditive (coherent risk measure)
        cvar_a1 = res.asset_risks["A1"].cvar_95
        cvar_a2 = res.asset_risks["A2"].cvar_95
        sum_cvar = cvar_a1 + cvar_a2
        assert res.enterprise_cvar_95 <= sum_cvar

    def test_rare_event_finite_sample_zero_breach(self):
        """
        Adversarial Challenge: Invariant EAL > 0 under finite-sample rare event simulation.
        When N * LEF << 1 (e.g., N=1000, TEF=1e-5), the Poisson probability of 0 breaches
        is exp(-0.01) ~ 0.99. In finite simulation, EAL collapses to 0.0 and VaR percentiles
        collapse to 0.0, violating strict percentile ordering.
        """
        a = MockAssetRecord(
            asset_id="A1",
            name="Asset 1",
            business_unit="BU1",
            tier=AssetTier.TIER_3,
            data_sensitivity=DataSensitivity.INTERNAL,
            replacement_cost=100000.0,
            downtime_cost_per_hour=1000.0,
            asset_criticality_score=1.0,
        )
        f_rare = MockNormalizedFinding(
            finding_id="F1",
            asset_id="A1",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.LOW,
            title="Ultra Rare Vulnerability",
            cvss_score=3.0,
            epss_score=0.05,
            cisa_kev=False,
            threat_event_frequency=0.00001,
            resistance_strength=0.9,
        )

        mc = MonteCarloEngine(iterations=1000, seed=42)
        res = mc.simulate([f_rare], {"A1": a})

        # At N=1000, all drawn Poisson counts are 0
        assert res.eal == 0.0
        assert res.var_90 == 0.0
        assert res.var_95 == 0.0
        assert res.var_99 == 0.0
        # Demonstrates boundary condition where strict ordering is skipped because eal == 0

    def test_strict_percentile_ordering_across_trial_counts(self):
        """
        Verifies strict percentile ordering (VaR 90 < VaR 95 < VaR 99)
        across trial scales: 1,000, 10,000, 50,000 for realistic active threat scenarios.
        """
        gen = ApexEnterpriseGenerator(seed=42)
        assets_65, findings_24, graph = gen.generate_enterprise_dataset()

        trial_counts = [1000, 10000, 50000]

        for n in trial_counts:
            # Test PortfolioEngine
            pe = PortfolioEngine(trials=n, seed=42)
            res_pe = pe.simulate_portfolio(findings_24, assets_65, graph=graph)
            assert res_pe.enterprise_var_90 < res_pe.enterprise_var_95 < res_pe.enterprise_var_99, (
                f"PE strict ordering failed at N={n}: "
                f"{res_pe.enterprise_var_90} < {res_pe.enterprise_var_95} < {res_pe.enterprise_var_99}"
            )

            # Test MonteCarloEngine
            mc = MonteCarloEngine(iterations=n, seed=42)
            res_mc = mc.simulate(findings_24, assets_65, graph=graph)
            assert res_mc.var_90 < res_mc.var_95 < res_mc.var_99, (
                f"MC strict ordering failed at N={n}: "
                f"{res_mc.var_90} < {res_mc.var_95} < {res_mc.var_99}"
            )

    def test_loss_exceedance_curve_monotonicity_across_scales(self):
        """
        Verifies that in the Loss Exceedance Curve (LEC), as loss increases,
        exceedance probability P(Loss >= x) is monotonically non-increasing across 1k, 10k, 50k trials.
        """
        gen = ApexEnterpriseGenerator(seed=42)
        assets_65, findings_24, graph = gen.generate_enterprise_dataset()

        for n in [1000, 10000, 50000]:
            pe = PortfolioEngine(trials=n, seed=42)
            res = pe.simulate_portfolio(findings_24, assets_65, graph=graph)
            lec = res.loss_exceedance_curve
            assert len(lec) == 20

            for i in range(1, len(lec)):
                l_prev, p_prev = lec[i - 1]
                l_curr, p_curr = lec[i]
                assert l_curr >= l_prev, f"Loss decreased at index {i}: {l_prev} -> {l_curr}"
                assert p_curr <= p_prev + 1e-6, f"Exceedance prob increased at index {i}: {p_prev} -> {p_curr}"

    def test_bit_exact_seed_determinism_multi_threaded(self):
        """
        Verifies that passing identical PRNG seeds across concurrent threads produces
        bit-exact identical results (thread-safe independent Generator instances).
        """
        gen = ApexEnterpriseGenerator(seed=42)
        assets_65, findings_24, graph = gen.generate_enterprise_dataset()

        def run_sim(seed: int):
            pe = PortfolioEngine(trials=5000, seed=seed)
            return pe.simulate_portfolio(findings_24, assets_65, graph=graph)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(run_sim, 777) for _ in range(8)]
            results = [f.result() for f in futures]

        base = results[0]
        for idx, r in enumerate(results[1:], start=1):
            assert r.enterprise_eal == base.enterprise_eal, f"Worker {idx} EAL differed"
            assert r.enterprise_var_90 == base.enterprise_var_90, f"Worker {idx} VaR 90 differed"
            assert r.enterprise_var_95 == base.enterprise_var_95, f"Worker {idx} VaR 95 differed"
            assert r.enterprise_var_99 == base.enterprise_var_99, f"Worker {idx} VaR 99 differed"
            assert r.diversification_benefit == base.diversification_benefit, f"Worker {idx} Div benefit differed"

    def test_fair_mapper_falsy_zero_coercion(self):
        """
        Adversarial Finding: In fair_mapper.py line 322:
        `cvss = float(getattr(finding, 'cvss_score', 5.0) or 5.0)`
        Numeric 0.0 evaluates to falsy, silently coercing CVSS=0.0 to 5.0 (Medium)
        and EPSS=0.0 to 0.1, inflating Threat Capability and Primary Loss.
        """
        f_zero = MockNormalizedFinding(
            finding_id="F0",
            asset_id="A1",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.LOW,
            title="Informational Zero CVSS",
            cvss_score=0.0,
            epss_score=0.0,
            cisa_kev=False,
            threat_event_frequency=1.0,
            resistance_strength=0.5,
        )
        params = FairMapper.map_finding(f_zero)

        # Expected if 0.0 were respected: TCap = 0.05, IR cost mode = 0.0
        # Actual due to falsy coercion: TCap = 0.40, IR cost mode = 50000.0
        assert params.threat_capability == 0.4
        assert params.primary_loss_mode == 50000.0

    def test_orphan_finding_telemetry_drop_in_portfolio(self):
        """
        Adversarial Finding: Discrepancy between MonteCarloEngine and PortfolioEngine.
        When telemetry contains findings referencing asset IDs not in the catalog:
        - MonteCarloEngine simulates them (EAL > 0).
        - PortfolioEngine silently drops them (EAL = 0.0).
        """
        a = MockAssetRecord(
            asset_id="A1",
            name="Catalog Asset",
            business_unit="BU1",
            tier=AssetTier.TIER_2,
            data_sensitivity=DataSensitivity.CONFIDENTIAL,
            replacement_cost=200000.0,
            downtime_cost_per_hour=5000.0,
        )
        f_orphan = MockNormalizedFinding(
            finding_id="F_ORPHAN",
            asset_id="NON_CATALOG_ASSET",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.CRITICAL,
            title="Orphaned Critical Vulnerability",
            cvss_score=9.5,
            epss_score=0.8,
            cisa_kev=True,
            threat_event_frequency=10.0,
            resistance_strength=0.1,
        )

        # MonteCarloEngine simulates it
        mc = MonteCarloEngine(iterations=1000, seed=42)
        res_mc = mc.simulate([f_orphan], {"A1": a})
        assert res_mc.eal > 100000.0

        # PortfolioEngine silently drops it
        pe = PortfolioEngine(trials=1000, seed=42)
        res_pe = pe.simulate_portfolio([f_orphan], [a])
        assert res_pe.enterprise_eal == 0.0
        assert res_pe.total_findings == 1

    def test_duplicate_asset_id_double_counting(self):
        """
        Adversarial Finding: Passing duplicate asset records in the asset list
        causes duplicate columns in the joint loss matrix L (N_trials x M_assets),
        doubling enterprise risk while the asset_risks dict silently overwrites itself.
        """
        a = MockAssetRecord(
            asset_id="A1",
            name="Asset 1",
            business_unit="BU1",
            tier=AssetTier.TIER_2,
            data_sensitivity=DataSensitivity.CONFIDENTIAL,
            replacement_cost=100000.0,
            downtime_cost_per_hour=2000.0,
        )
        f = MockNormalizedFinding(
            finding_id="F1",
            asset_id="A1",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            title="High Finding",
            cvss_score=7.5,
            epss_score=0.3,
            cisa_kev=False,
            threat_event_frequency=2.0,
            resistance_strength=0.4,
        )

        pe = PortfolioEngine(trials=2000, seed=42)
        res_single = pe.simulate_portfolio([f], [a])

        # Pass duplicate asset in list
        res_double = pe.simulate_portfolio([f], [a, a])

        # Enterprise EAL is approximately double (two independent realizations of same asset)
        ratio = res_double.enterprise_eal / res_single.enterprise_eal
        assert 1.90 <= ratio <= 2.15, f"Expected ratio ~2.0, got {ratio}"
        # While asset_risks has only 1 entry because dict key 'A1' is overwritten
        assert len(res_double.asset_risks) == 1

    def test_extreme_quadrillion_valuation_numeric_stability(self):
        """
        Adversarial Stress: Tests numeric stability under $1 Quadrillion ($10^15) asset valuation.
        Verifies no float64 overflow, Inf, or NaN occur.
        """
        a_quad = MockAssetRecord(
            asset_id="QUAD",
            name="Quadrillion Asset",
            business_unit="Gov",
            tier=AssetTier.TIER_1,
            data_sensitivity=DataSensitivity.RESTRICTED_PCI,
            replacement_cost=1e15,
            downtime_cost_per_hour=1e12,
            asset_criticality_score=10.0,
        )
        f_quad = MockNormalizedFinding(
            finding_id="F_QUAD",
            asset_id="QUAD",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.CRITICAL,
            title="Critical Vuln",
            cvss_score=10.0,
            epss_score=1.0,
            cisa_kev=True,
            threat_event_frequency=50.0,
            resistance_strength=0.01,
        )

        pe = PortfolioEngine(trials=1000, seed=42)
        res = pe.simulate_portfolio([f_quad], [a_quad])

        assert math.isfinite(res.enterprise_eal)
        assert res.enterprise_eal > 1e14
        assert math.isfinite(res.enterprise_var_99)
        assert res.enterprise_var_90 < res.enterprise_var_95 < res.enterprise_var_99

    def test_empty_findings_lec_length_contract_discrepancy(self):
        """
        Adversarial Finding: Discrepancy between engines on empty findings LEC format.
        - MonteCarloEngine returns a 1-element list [(0.0, 1.0)].
        - PortfolioEngine returns a 20-element list [(0.0, 0.95), ..., (0.0, 0.01)].
        """
        a = MockAssetRecord(
            asset_id="A1",
            name="Asset 1",
            business_unit="BU1",
            tier=AssetTier.TIER_3,
            data_sensitivity=DataSensitivity.INTERNAL,
            replacement_cost=100000.0,
            downtime_cost_per_hour=1000.0,
        )

        mc = MonteCarloEngine(iterations=1000, seed=42)
        res_mc = mc.simulate([])
        assert len(res_mc.loss_exceedance_curve) == 1
        assert res_mc.loss_exceedance_curve[0] == (0.0, 1.0)

        pe = PortfolioEngine(trials=1000, seed=42)
        res_pe = pe.simulate_portfolio([], [a])
        assert len(res_pe.loss_exceedance_curve) == 20
        # In PE, for zero loss it erroneously asserts P(Loss >= 0) is 0.95 down to 0.01
        assert res_pe.loss_exceedance_curve[0][1] == 0.95
        assert res_pe.loss_exceedance_curve[-1][1] == 0.01
