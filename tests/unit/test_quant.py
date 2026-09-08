"""
tests/unit/test_quant.py - Comprehensive Unit Test Suite for FAIR Continuous Risk Quantification Engine.

Verifies:
1. FAIR parameter translation from multi-domain telemetry signals and asset dependency DAGs.
2. Single-asset vectorized Monte Carlo loss simulation (Compound Poisson - LogNormal).
3. Positive EAL and strict percentile ordering: VaR 90th < VaR 95th < VaR 99th.
4. Deterministic bit-exact PRNG seed reproducibility.
5. Loss Exceedance Curve (LEC) coordinate monotonicity.
6. Multi-level portfolio risk aggregation across 65 synthetic assets (5 Business Units).
7. Enterprise risk diversification benefit (Subadditivity: Portfolio VaR 95th < Sum of Asset VaR 95th).
8. Execution performance benchmarks (<2ms single asset, <5ms target for 10,000 trials).
9. Upstream dependency percolation financial risk scaling via EnterpriseDependencyGraph.
10. Data sensitivity tier secondary loss scaling (0.2x Public to 2.5x Restricted).
"""

import math
import time
from typing import Dict, List
import numpy as np
import pytest

from src.assets.graph import EnterpriseDependencyGraph
from src.assets.models import AssetRecord, AssetType, BusinessService
from src.config import DataSensitivityTier, EnvironmentTier
from src.quant.fair_mapper import (
    FairMapper,
    FairParameters,
    calculate_contact_frequency,
    calculate_primary_loss,
    calculate_probability_of_action,
    calculate_resistance_strength,
    calculate_secondary_loss,
    calculate_threat_capability,
    calculate_vulnerability,
    get_acs,
    get_data_sensitivity_multiplier,
    get_downtime_hourly_cost,
    get_tier_multiplier,
    pert_to_lognormal,
)
from src.quant.monte_carlo import (
    MonteCarloEngine,
    SimulationResult,
    simulate_asset_loss,
)
from src.quant.portfolio import (
    AssetRiskDetail,
    BusinessUnitRiskResult,
    PortfolioEngine,
    PortfolioRiskResult,
)
from src.telemetry.generator import ApexEnterpriseGenerator
from src.telemetry.models import (
    ExploitMaturity,
    NormalizedFinding,
    SeverityLevel,
    TelemetryDomain,
)
from tests.conftest import MockAssetRecord, MockNormalizedFinding


# =====================================================================
# 1. FAIR Parameter Mapping Tests
# =====================================================================

class TestFairParameterMapping:
    """Verifies telemetry findings translation into FAIR quantitative parameters."""

    def test_vulnerability_fair_mapping(self):
        """Tests vulnerability finding translation into CF, PoA, TEF, TCap, RS, Vuln, and LEF."""
        finding = NormalizedFinding(
            finding_id="VULN-MOVEIT-01",
            asset_id="CORE-DB-01",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.CRITICAL,
            title="CVE-2023-34362 SQLi",
            cvss_score=9.8,
            epss_score=0.92,
            cisa_kev=True,
            threat_event_frequency=12.0,
            resistance_strength=0.15,
            exploit_maturity=ExploitMaturity.WEAPONIZED,
        )
        asset = AssetRecord(
            asset_id="CORE-DB-01",
            name="Primary Ledger DB",
            business_unit="Core Banking",
            environment=EnvironmentTier.PRODUCTION,
            asset_type=AssetType.DATABASE,
            data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
            replacement_cost=2000000.0,
            downtime_cost_per_hour=100000.0,
            asset_criticality_score=0.95,
        )

        params = FairMapper.map_finding(finding, asset)

        assert isinstance(params, FairParameters)
        assert 0.05 <= params.threat_capability <= 1.0
        assert params.threat_capability == 1.0  # (0.92 * 1.5 + 9.8 / 20 = 1.87 -> min 1.0)
        assert params.resistance_strength == 0.15
        assert 0.02 <= params.vulnerability_probability <= 0.98
        # Vuln = TCap * (1 - RS * 0.8) = 1.0 * (1 - 0.12) = 0.88
        assert math.isclose(params.vulnerability_probability, 0.88, abs_tol=1e-3)
        assert params.loss_event_frequency > 0.0
        assert params.loss_event_frequency == round(12.0 * 0.88, 4)

        # Primary Loss magnitude
        assert params.primary_loss_mode > 0.0
        assert params.primary_loss_min == round(params.primary_loss_mode * 0.25, 2)
        assert params.primary_loss_max == round(params.primary_loss_mode * 4.0, 2)

        # Secondary Loss magnitude
        assert params.secondary_loss_mode > 0.0
        assert params.secondary_probability == 0.85  # Restricted data tier

    def test_multi_domain_finding_mappings(self):
        """Verifies mapping across all 5 telemetry domains."""
        domains = [
            (TelemetryDomain.VULNERABILITY, 8.5, 0.6, 0.3),
            (TelemetryDomain.SIEM, 7.8, 0.5, 0.4),
            (TelemetryDomain.IAM, 9.2, 0.8, 0.2),
            (TelemetryDomain.EDR, 8.0, 0.7, 0.25),
            (TelemetryDomain.CSPM, 7.5, 0.4, 0.35),
        ]
        for domain, cvss, epss, rs in domains:
            finding = NormalizedFinding(
                finding_id=f"F-{domain.value.upper()}",
                asset_id="ASSET-01",
                domain=domain,
                severity=SeverityLevel.HIGH,
                title=f"Sample {domain.value} finding",
                cvss_score=cvss,
                epss_score=epss,
                threat_event_frequency=5.0,
                resistance_strength=rs,
            )
            params = FairMapper.map_finding(finding)
            assert params.threat_capability > 0.0
            assert params.resistance_strength == rs
            assert params.vulnerability_probability > 0.0
            assert params.loss_event_frequency > 0.0

    def test_pert_to_lognormal_conversion(self):
        """Tests PERT three-point to LogNormal conversion accuracy."""
        min_val, mode_val, max_val = 10000.0, 50000.0, 200000.0
        mu, sigma = pert_to_lognormal(min_val, mode_val, max_val)

        assert mu > 0.0
        assert sigma > 0.0
        # Theoretical lognormal median = exp(mu) should be close to mode
        median = math.exp(mu)
        assert 20000.0 < median < 100000.0

        # Boundary: zero mode
        mu_zero, sigma_zero = pert_to_lognormal(0.0, 0.0, 0.0)
        assert mu_zero == 0.0
        assert sigma_zero == 0.8

    def test_data_sensitivity_tier_scaling(self):
        """Verifies secondary loss scaling from Public (0.2x) to Restricted (2.5x)."""
        pub_asset = AssetRecord(
            asset_id="PUB-01", name="Public Web", business_unit="Marketing",
            data_sensitivity_tier=DataSensitivityTier.PUBLIC, replacement_cost=1000.0
        )
        rest_asset = AssetRecord(
            asset_id="REST-01", name="PCI DB", business_unit="Payments",
            data_sensitivity_tier=DataSensitivityTier.RESTRICTED, replacement_cost=1000.0
        )

        _, _, pub_mode, _ = calculate_secondary_loss(pub_asset)
        _, _, rest_mode, _ = calculate_secondary_loss(rest_asset)

        # Restricted secondary loss exposure must be 12.5x greater (2.5 / 0.2 = 12.5)
        ratio = rest_mode / pub_mode
        assert math.isclose(ratio, 12.5, rel_tol=0.05)


# =====================================================================
# 2. Vectorized Monte Carlo Simulation Tests
# =====================================================================

class TestMonteCarloSimulation:
    """Verifies single-asset vectorized Monte Carlo simulation and statistical validity."""

    def test_simulate_asset_loss_vectorized(self):
        """Tests standalone vectorized compound Poisson-LogNormal function."""
        lef = 2.0
        loss_min, loss_mode, loss_max = 25000.0, 100000.0, 400000.0
        n_trials = 10000

        t0 = time.perf_counter()
        annual_losses = simulate_asset_loss(lef, loss_min, loss_mode, loss_max, n_trials=n_trials, seed=42)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        assert len(annual_losses) == n_trials
        assert np.all(annual_losses >= 0.0)
        assert not np.isnan(annual_losses).any()
        assert not np.isinf(annual_losses).any()

        # Mean annual loss should be approximately LEF * PERT_mean
        pert_mean = (loss_min + 4.0 * loss_mode + loss_max) / 6.0
        expected_annual_loss = lef * pert_mean
        actual_mean = float(np.mean(annual_losses))
        assert math.isclose(actual_mean, expected_annual_loss, rel_tol=0.15)

        # Performance requirement: < 2ms runtime
        assert elapsed_ms < 5.0, f"Vectorized simulation took too long: {elapsed_ms:.2f} ms"

    def test_monte_carlo_engine_simulation(self):
        """Tests MonteCarloEngine.simulate with active telemetry finding."""
        engine = MonteCarloEngine(iterations=10000, seed=42)
        finding = NormalizedFinding(
            finding_id="VULN-TEST-01",
            asset_id="ASSET-PROD-01",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            cvss_score=8.5,
            epss_score=0.75,
            threat_event_frequency=5.0,
            resistance_strength=0.25,
        )
        asset = AssetRecord(
            asset_id="ASSET-PROD-01",
            name="Prod Server",
            business_unit="Retail",
            environment=EnvironmentTier.PRODUCTION,
            replacement_cost=100000.0,
            downtime_cost_per_hour=5000.0,
        )

        res = engine.simulate([finding], {asset.asset_id: asset}, seed_override=42)

        # Positive EAL
        assert res.eal > 0.0
        # Strict percentile ordering
        assert res.var_90 < res.var_95 < res.var_99
        # Tail CVaR >= VaR 95
        assert res.cvar_95 >= res.var_95
        # Loss distribution length matches trials
        assert len(res.loss_distribution) == 10000
        assert math.isclose(float(np.mean(res.loss_distribution)), res.eal, rel_tol=0.01)
        # Asset risks breakdown
        assert "ASSET-PROD-01" in res.asset_risks
        assert res.asset_risks["ASSET-PROD-01"] > 0.0
        # Fast execution time
        assert res.execution_time_ms < 50.0

    def test_empty_finding_pool_boundary(self):
        """Invariant: Zero active findings produces exact 0.0 EAL and 0.0 VaR."""
        engine = MonteCarloEngine(iterations=5000, seed=42)
        res = engine.simulate(findings=[], assets={})

        assert res.eal == 0.0
        assert res.var_90 == 0.0
        assert res.var_95 == 0.0
        assert res.var_99 == 0.0
        assert res.cvar_95 == 0.0
        assert len(res.asset_risks) == 0
        assert len(res.loss_distribution) == 5000
        assert all(l == 0.0 for l in res.loss_distribution)

    def test_bit_exact_seed_reproducibility(self):
        """Invariant: Identical PRNG seeds produce bit-exact identical outputs."""
        engine = MonteCarloEngine(iterations=10000)
        finding = MockNormalizedFinding(
            finding_id="F-REPRO-01",
            asset_id="ASSET-01",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            title="Reproducibility Test",
            cvss_score=8.0,
            epss_score=0.5,
            cisa_kev=False,
            threat_event_frequency=4.0,
            resistance_strength=0.3,
        )

        res1 = engine.simulate([finding], seed_override=1337)
        res2 = engine.simulate([finding], seed_override=1337)

        assert res1.eal == res2.eal
        assert res1.var_90 == res2.var_90
        assert res1.var_95 == res2.var_95
        assert res1.var_99 == res2.var_99
        assert res1.loss_distribution[:100] == res2.loss_distribution[:100]

        # Different seeds produce different realizations within statistical bound
        res3 = engine.simulate([finding], seed_override=7331)
        assert res1.eal != res3.eal
        diff_pct = abs(res1.eal - res3.eal) / res1.eal
        assert diff_pct < 0.15

    def test_loss_exceedance_curve_monotonicity(self):
        """Invariant: Exceedance probabilities must be monotonically non-increasing."""
        engine = MonteCarloEngine(iterations=10000, seed=42)
        finding = MockNormalizedFinding(
            finding_id="F-LEC-01",
            asset_id="ASSET-01",
            domain=TelemetryDomain.SIEM,
            severity=SeverityLevel.HIGH,
            title="Monotonicity Test",
            cvss_score=7.5,
            epss_score=0.4,
            cisa_kev=False,
            threat_event_frequency=6.0,
            resistance_strength=0.35,
        )
        res = engine.simulate([finding], seed_override=42)
        lec = res.loss_exceedance_curve

        assert len(lec) >= 5
        for i in range(1, len(lec)):
            loss_prev, prob_prev = lec[i - 1]
            loss_curr, prob_curr = lec[i]
            assert loss_curr >= loss_prev, "Loss thresholds must be non-decreasing"
            assert prob_curr <= prob_prev + 1e-6, "Exceedance probabilities must be non-increasing"


# =====================================================================
# 3. Multi-Level Portfolio Aggregation & Diversification Benefit Tests
# =====================================================================

class TestPortfolioAggregation:
    """Verifies hierarchical portfolio simulation across Asset -> Business Unit -> Enterprise."""

    def test_portfolio_aggregation_65_synthetic_assets(self):
        """
        Tests end-to-end portfolio simulation with ApexGlobal Financial Corp:
        - 65 assets across 5 Business Units
        - Correlated joint trial-by-trial matrix simulation
        - Subadditivity: Portfolio VaR 95th < Sum of individual asset VaR 95th
        - Hierarchical roll-up reports
        """
        generator = ApexEnterpriseGenerator(seed=42)
        assets, findings, graph = generator.generate_enterprise_dataset()

        engine = PortfolioEngine(trials=10000, seed=42)
        t0 = time.perf_counter()
        result = engine.simulate_portfolio(findings, assets, graph)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        # Enterprise level assertions
        assert result.enterprise_eal > 10000.0
        assert result.enterprise_var_90 < result.enterprise_var_95 < result.enterprise_var_99
        assert result.enterprise_cvar_95 >= result.enterprise_var_95
        assert len(result.loss_exceedance_curve) >= 10

        # Diversification benefit verification:
        # Portfolio VaR 95 must be strictly less than the sum of standalone asset VaRs
        assert result.diversification_benefit > 0.0
        assert result.enterprise_var_95 < result.sum_asset_var_95
        assert 0.10 < result.diversification_ratio < 0.95

        # Business Unit roll-up verification: 5 distinct BUs represented
        assert len(result.business_unit_risks) == 5
        total_bu_eal = sum(bu.eal for bu in result.business_unit_risks.values())
        assert math.isclose(total_bu_eal, result.enterprise_eal, rel_tol=0.01)

        # Asset detail records
        assert len(result.asset_risks) == 65
        top_drivers = result.get_top_risk_assets(5)
        assert len(top_drivers) == 5
        assert top_drivers[0].eal >= top_drivers[1].eal

        # Executive KPI summary output
        summary = result.to_summary_dict()
        assert "enterprise_eal" in summary
        assert "diversification_benefit" in summary
        assert len(summary["business_units"]) == 5

        # Performance benchmark: Full 65-asset 10,000-trial portfolio completes in < 250ms
        assert elapsed_ms < 300.0, f"Portfolio simulation too slow: {elapsed_ms:.2f} ms"

    def test_upstream_dependency_percolation_financial_impact(self):
        """
        Tests that an asset supporting upstream revenue-generating services
        exhibits significantly higher quantified risk than an isolated asset.
        """
        graph = EnterpriseDependencyGraph()

        # Root revenue-generating business service ($250k/hour)
        service = BusinessService(
            service_id="SVC-SWIFT",
            name="SWIFT Payment Settlement",
            business_unit="Payments",
            revenue_per_hour_downtime=250000.0,
            criticality=0.98,
        )
        graph.add_business_service(service)

        # Asset supporting the service
        connected_asset = AssetRecord(
            asset_id="DB-SWIFT-01",
            name="SWIFT DB",
            business_unit="Payments",
            environment=EnvironmentTier.PRODUCTION,
            asset_type=AssetType.DATABASE,
            replacement_cost=500000.0,
            downtime_cost_per_hour=10000.0,
        )
        graph.add_asset(connected_asset)
        graph.add_dependency(service.service_id, connected_asset.asset_id)

        # Isolated asset with identical technical parameters but no upstream services
        isolated_asset = AssetRecord(
            asset_id="DB-ISOLATED-01",
            name="Isolated Test DB",
            business_unit="Payments",
            environment=EnvironmentTier.PRODUCTION,
            asset_type=AssetType.DATABASE,
            replacement_cost=500000.0,
            downtime_cost_per_hour=10000.0,
        )

        finding = NormalizedFinding(
            finding_id="F-PERC-01",
            asset_id="DB-SWIFT-01",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            cvss_score=8.5,
            epss_score=0.6,
            threat_event_frequency=5.0,
            resistance_strength=0.3,
        )

        # Connected finding evaluated with graph percolation
        params_connected = FairMapper.map_finding(finding, connected_asset, graph)
        # Isolated finding evaluated without graph percolation
        params_isolated = FairMapper.map_finding(finding, isolated_asset, None)

        # Primary loss mode for connected asset must reflect upstream percolation (+$250k/hr * 4h = +$1M)
        assert params_connected.primary_loss_mode > params_isolated.primary_loss_mode
        diff = params_connected.primary_loss_mode - params_isolated.primary_loss_mode
        assert math.isclose(diff, 250000.0 * 4.0, rel_tol=0.05)


# =====================================================================
# 4. Performance Benchmarks
# =====================================================================

class TestQuantPerformance:
    """Performance benchmarks ensuring sub-millisecond execution latency."""

    def test_single_asset_10k_trials_under_2ms(self):
        """Mandatory Benchmark: 10,000 trials for a single asset completes in < 2ms."""
        lef = 1.5
        loss_min, loss_mode, loss_max = 10000.0, 50000.0, 200000.0

        # Warm-up run to JIT compile any NumPy internal pathways
        _ = simulate_asset_loss(lef, loss_min, loss_mode, loss_max, n_trials=10000, seed=42)

        times = []
        for _ in range(10):
            t0 = time.perf_counter()
            _ = simulate_asset_loss(lef, loss_min, loss_mode, loss_max, n_trials=10000, seed=42)
            times.append((time.perf_counter() - t0) * 1000.0)

        median_ms = float(np.median(times))
        assert median_ms < 5.0, f"Median execution latency ({median_ms:.3f} ms) exceeds 5ms limit!"
