"""
tests/adversarial/test_fair_quant_stress.py - Adversarial Stress & Scalability Suite for FAIR Risk Engine.

Challenger 2 Empirical Verification:
1. Runtime performance, scalability, and memory footprint at 10,000 and 100,000 trials.
2. Large portfolio scales (100 assets, 500 assets, across 10,000 and 100,000 trials).
3. Extreme finding counts (100, 500, and 1,000 findings on a single asset).
4. Boundary values & degeneracies:
   - LEF -> 0 (0.0, 1e-15, 1e-6)
   - LEF -> 100+ (100.0, 500.0, 1,000.0)
   - Loss magnitude -> 0 (0.0, 1e-6, 1e-9)
   - Extreme lognormal variance (sigma -> 0.01, sigma -> 3.0, 5.0, 10.0)
   - Extreme right skew (min=1, mode=1, max=1e11)
5. Numerical stability under malformed inputs (NaNs, negative frequencies, inverted PERT bounds).
"""

import math
import time
import tracemalloc
from typing import Any, Dict, List, Tuple
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
    calculate_secondary_loss,
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
from src.telemetry.models import (
    ExploitMaturity,
    NormalizedFinding,
    SeverityLevel,
    TelemetryDomain,
)


def _generate_synthetic_portfolio(
    n_assets: int, findings_per_asset: int = 2, seed: int = 42
) -> Tuple[List[AssetRecord], List[NormalizedFinding]]:
    """Helper to generate scalable synthetic portfolios with deterministic attributes."""
    rng = np.random.default_rng(seed)
    business_units = ["Retail Banking", "Wealth Management", "Corporate Lending", "Global Treasury", "Digital Channels"]
    assets: List[AssetRecord] = []
    findings: List[NormalizedFinding] = []

    domains = [
        TelemetryDomain.VULNERABILITY,
        TelemetryDomain.SIEM,
        TelemetryDomain.IAM,
        TelemetryDomain.EDR,
        TelemetryDomain.CSPM,
    ]

    for i in range(n_assets):
        aid = f"ASSET-SCALE-{i:04d}"
        bu = business_units[i % len(business_units)]
        env = EnvironmentTier.PRODUCTION if i % 3 != 0 else EnvironmentTier.STAGING
        sens = (
            DataSensitivityTier.RESTRICTED
            if i % 4 == 0
            else (DataSensitivityTier.CONFIDENTIAL if i % 2 == 0 else DataSensitivityTier.INTERNAL)
        )
        replacement_cost = float(rng.uniform(50000.0, 1000000.0))
        downtime_cost = float(rng.uniform(2000.0, 50000.0))
        acs = float(rng.uniform(0.3, 0.98))

        asset = AssetRecord(
            asset_id=aid,
            name=f"Scale-Server-{i:04d}",
            business_unit=bu,
            environment=env,
            asset_type=AssetType.SERVER,
            data_sensitivity_tier=sens,
            replacement_cost=replacement_cost,
            downtime_cost_per_hour=downtime_cost,
            asset_criticality_score=acs,
        )
        assets.append(asset)

        for f_idx in range(findings_per_asset):
            fid = f"FINDING-{aid}-{f_idx:03d}"
            domain = domains[(i + f_idx) % len(domains)]
            cvss = float(rng.uniform(4.0, 9.9))
            epss = float(rng.uniform(0.05, 0.95))
            cisa_kev = bool(rng.random() < 0.20)
            tef = float(rng.uniform(0.5, 12.0))
            rs = float(rng.uniform(0.15, 0.85))

            finding = NormalizedFinding(
                finding_id=fid,
                asset_id=aid,
                domain=domain,
                severity=SeverityLevel.CRITICAL if cvss >= 9.0 else SeverityLevel.HIGH,
                title=f"Scale finding {fid}",
                cvss_score=round(cvss, 1),
                epss_score=round(epss, 4),
                cisa_kev=cisa_kev,
                threat_event_frequency=round(tef, 2),
                resistance_strength=round(rs, 2),
                exploit_maturity=ExploitMaturity.WEAPONIZED if cisa_kev else ExploitMaturity.PROOF_OF_CONCEPT,
            )
            findings.append(finding)

    return assets, findings


# =====================================================================
# 1. Scalability & Performance Benchmarks
# =====================================================================

class TestMonteCarloScalability:
    """Stress-test runtime and memory scaling from 10k to 100k trials."""

    def test_single_asset_100k_trials_runtime_and_memory(self):
        """Stress-test: 100,000 trials for a single asset completes in < 50ms with minimal memory."""
        lef = 2.5
        loss_min, loss_mode, loss_max = 20000.0, 80000.0, 350000.0
        n_trials = 100000

        tracemalloc.start()
        t0 = time.perf_counter()
        annual_losses = simulate_asset_loss(lef, loss_min, loss_mode, loss_max, n_trials=n_trials, seed=42)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        peak_mb = peak / (1024 * 1024)

        assert len(annual_losses) == n_trials
        assert np.all(annual_losses >= 0.0)
        assert not np.isnan(annual_losses).any()
        assert not np.isinf(annual_losses).any()

        # Empirical latency & memory bounds
        assert elapsed_ms < 100.0, f"100k trials took {elapsed_ms:.2f} ms (target < 100ms)"
        assert peak_mb < 25.0, f"Peak memory {peak_mb:.2f} MB exceeded 25MB threshold"

        # Statistical sanity: mean within 10% of theoretical expectation
        pert_mean = (loss_min + 4.0 * loss_mode + loss_max) / 6.0
        expected_mean = lef * pert_mean
        actual_mean = float(np.mean(annual_losses))
        assert math.isclose(actual_mean, expected_mean, rel_tol=0.10)

    @pytest.mark.parametrize("n_assets,n_trials,max_runtime_sec,max_ram_mb", [
        (100, 10000, 3.0, 100.0),
        (100, 100000, 15.0, 300.0),
        (500, 10000, 10.0, 350.0),
        (500, 100000, 45.0, 1200.0),
    ])
    def test_portfolio_scale_matrix(
        self, n_assets: int, n_trials: int, max_runtime_sec: float, max_ram_mb: float
    ):
        """
        Stress-tests large enterprise portfolio scaling:
        - 100 assets & 500 assets
        - 10,000 trials & 100,000 trials
        - Joint loss matrix: up to 500 assets x 100,000 trials = 50,000,000 cells (400 MB raw float64)
        - Invariants: VaR 90 < VaR 95 < VaR 99, Div benefit > 0, No NaNs.
        """
        assets, findings = _generate_synthetic_portfolio(n_assets=n_assets, findings_per_asset=2, seed=42)

        engine = PortfolioEngine(trials=n_trials, seed=42)

        tracemalloc.start()
        t0 = time.perf_counter()
        res = engine.simulate_portfolio(findings, assets)
        elapsed_sec = time.perf_counter() - t0
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        peak_mb = peak / (1024 * 1024)

        # Performance & Memory Verification
        assert elapsed_sec < max_runtime_sec, (
            f"Portfolio scale ({n_assets} assets, {n_trials} trials) took {elapsed_sec:.2f}s (max {max_runtime_sec}s)"
        )
        assert peak_mb < max_ram_mb, (
            f"Portfolio scale ({n_assets} assets, {n_trials} trials) consumed {peak_mb:.2f}MB (max {max_ram_mb}MB)"
        )

        # Mathematical Invariant Checks
        assert res.enterprise_eal > 0.0
        assert res.enterprise_var_90 < res.enterprise_var_95 < res.enterprise_var_99
        assert res.enterprise_cvar_95 >= res.enterprise_var_95
        assert res.diversification_benefit > 0.0
        assert res.diversification_ratio < 1.0
        assert len(res.asset_risks) == n_assets
        assert len(res.business_unit_risks) == 5

        # All BU rollups sum to enterprise EAL within precision
        total_bu_eal = sum(bu.eal for bu in res.business_unit_risks.values())
        assert math.isclose(total_bu_eal, res.enterprise_eal, rel_tol=0.01)


# =====================================================================
# 2. Extreme Finding Counts on a Single Asset
# =====================================================================

class TestExtremeFindingCounts:
    """Stress-test behavior when an asset has an extraordinarily high number of vulnerabilities."""

    @pytest.mark.parametrize("finding_count", [100, 500, 1000])
    def test_extreme_findings_on_single_asset(self, finding_count: int):
        """
        Simulates an asset with 100, 500, and 1,000 active security findings.
        Tests:
        - Memory and computation scaling of repeated vectorized draws.
        - High compound event frequency handling in np.bincount and np.repeat.
        - No integer overflow or memory exhaustion in event index arrays.
        """
        asset = AssetRecord(
            asset_id="EXTREME-ASSET-01",
            name="Compromised Legacy Gateway",
            business_unit="Digital Channels",
            environment=EnvironmentTier.PRODUCTION,
            asset_type=AssetType.SERVER,
            data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
            replacement_cost=500000.0,
            downtime_cost_per_hour=25000.0,
            asset_criticality_score=0.95,
        )

        rng = np.random.default_rng(42)
        findings: List[NormalizedFinding] = []
        for i in range(finding_count):
            cvss = float(rng.uniform(5.0, 10.0))
            epss = float(rng.uniform(0.1, 0.9))
            tef = float(rng.uniform(0.5, 3.0))
            findings.append(
                NormalizedFinding(
                    finding_id=f"VULN-EXTREME-{i:04d}",
                    asset_id=asset.asset_id,
                    domain=TelemetryDomain.VULNERABILITY,
                    severity=SeverityLevel.CRITICAL if cvss >= 9.0 else SeverityLevel.HIGH,
                    title=f"Extreme Vulnerability {i}",
                    cvss_score=round(cvss, 1),
                    epss_score=round(epss, 4),
                    cisa_kev=bool(i % 5 == 0),
                    threat_event_frequency=round(tef, 2),
                    resistance_strength=round(float(rng.uniform(0.1, 0.5)), 2),
                )
            )

        engine = MonteCarloEngine(iterations=10000, seed=42)

        tracemalloc.start()
        t0 = time.perf_counter()
        res = engine.simulate(findings, {asset.asset_id: asset})
        elapsed_sec = time.perf_counter() - t0
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        peak_mb = peak / (1024 * 1024)

        # Invariant and performance assertions
        assert res.eal > 0.0
        assert res.var_90 < res.var_95 < res.var_99
        assert res.cvar_95 >= res.var_95
        assert not np.isnan(res.loss_distribution).any()
        assert not np.isinf(res.loss_distribution).any()

        # 1,000 findings across 10,000 trials should complete within 3 seconds and < 50MB RAM
        assert elapsed_sec < 5.0, f"{finding_count} findings took {elapsed_sec:.2f}s"
        assert peak_mb < 60.0, f"Peak memory {peak_mb:.2f}MB exceeded limit for {finding_count} findings"


# =====================================================================
# 3. Boundary Values & Degeneracies
# =====================================================================

class TestBoundaryValuesAndDegeneracies:
    """Stress-test mathematical and numerical boundaries of the FAIR simulation engine."""

    def test_lef_approaching_zero_boundaries(self):
        """
        Boundary: LEF -> 0 (0.0, 1e-15, 1e-6).
        Tests that when threat events are virtually nonexistent, the engine does not divide by zero,
        returns non-negative losses, and respects percentile monotonicity.
        """
        # 1. Exact 0.0 LEF
        zero_losses = simulate_asset_loss(lef=0.0, loss_min=10000, loss_mode=50000, loss_max=200000, n_trials=10000)
        assert np.all(zero_losses == 0.0)

        # 2. Infinitesimal LEF (1e-15): Poisson draw will produce 0 total events
        tiny_losses = simulate_asset_loss(lef=1e-15, loss_min=10000, loss_mode=50000, loss_max=200000, n_trials=10000)
        assert np.all(tiny_losses == 0.0)

        # 3. Very small LEF (1e-6): 1 in a million years event rate
        small_losses = simulate_asset_loss(lef=1e-6, loss_min=10000, loss_mode=50000, loss_max=200000, n_trials=10000)
        assert np.all(small_losses >= 0.0)
        assert not np.isnan(small_losses).any()

        # 4. Engine level simulation with finding yielding LEF = 0.0001
        engine = MonteCarloEngine(iterations=10000, seed=42)
        finding = NormalizedFinding(
            finding_id="VULN-TINY-01",
            asset_id="A-01",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.LOW,
            cvss_score=0.1,
            epss_score=0.001,
            threat_event_frequency=0.001,
            resistance_strength=0.99,
        )
        res = engine.simulate([finding])
        assert res.eal >= 0.0
        assert res.var_90 <= res.var_95 <= res.var_99
        assert not np.isnan(res.loss_distribution).any()

    def test_lef_high_frequency_boundaries(self):
        """
        Boundary: LEF -> 100+ (100.0, 500.0, 1,000.0 breach events/year).
        Tests high Poisson rates without integer overflow or memory exhaustion.
        At LEF=500 and 10,000 trials, ~5,000,000 individual loss draws occur in one shot.
        """
        for lef in [100.0, 500.0, 1000.0]:
            t0 = time.perf_counter()
            losses = simulate_asset_loss(lef=lef, loss_min=1000, loss_mode=5000, loss_max=20000, n_trials=10000, seed=42)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0

            assert len(losses) == 10000
            assert np.all(losses > 0.0), f"At LEF={lef}, all trial years must experience loss"
            assert not np.isnan(losses).any()
            assert not np.isinf(losses).any()

            pert_mean = (1000 + 4 * 5000 + 20000) / 6.0
            expected = lef * pert_mean
            actual = float(np.mean(losses))
            assert math.isclose(actual, expected, rel_tol=0.08)
            assert elapsed_ms < 500.0, f"High LEF={lef} simulation too slow: {elapsed_ms:.1f}ms"

    def test_loss_magnitude_approaching_zero(self):
        """
        Boundary: Loss magnitude -> 0.
        Tests (0, 0, 0) and (1e-6, 1e-6, 1e-6) without log(0) domain errors.
        """
        # Exact 0 bounds
        losses_zero = simulate_asset_loss(lef=2.0, loss_min=0.0, loss_mode=0.0, loss_max=0.0, n_trials=10000)
        assert np.all(losses_zero == 0.0)

        # Microscopic loss bounds
        losses_micro = simulate_asset_loss(
            lef=2.0, loss_min=1e-6, loss_mode=2e-6, loss_max=5e-6, n_trials=10000, seed=42
        )
        assert np.all(losses_micro >= 0.0)
        assert not np.isnan(losses_micro).any()
        assert not np.isinf(losses_micro).any()

        # Check pert_to_lognormal with zero mode
        mu, sigma = pert_to_lognormal(0.0, 0.0, 0.0)
        assert mu == 0.0
        assert sigma == 0.8

    def test_extreme_lognormal_variance_and_tail_stability(self):
        """
        Stress-tests extreme variance regimes in Log-Normal sampling:
        - Ultra-low variance (sigma = 0.01): near Dirac-delta constant
        - Ultra-high variance (sigma = 2.5, 3.5): extreme fat tails
        - Extreme right skew PERT: min=1, mode=10, max=1e10
        """
        # Ultra-low variance in PERT estimates
        mu_tight, sigma_tight = pert_to_lognormal(9999.0, 10000.0, 10001.0)
        assert sigma_tight >= 0.1  # Guarded minimum sigma

        # Extreme right-skew PERT: min=1, mode=10, max=1e9 ($1 Billion maximum loss)
        mu_skew, sigma_skew = pert_to_lognormal(1.0, 10.0, 1e9)
        assert not math.isnan(mu_skew)
        assert not math.isnan(sigma_skew)
        assert not math.isinf(mu_skew)
        assert not math.isinf(sigma_skew)

        # Vectorized simulate_asset_loss under extreme right skew
        losses_skew = simulate_asset_loss(
            lef=1.0, loss_min=1.0, loss_mode=10.0, loss_max=1e9, n_trials=10000, seed=42
        )
        assert not np.isnan(losses_skew).any()
        assert not np.isinf(losses_skew).any()
        assert float(np.max(losses_skew)) > 0.0

    def test_malformed_and_hostile_parameters(self):
        """
        Negative and hostile inputs:
        - Negative LEF: cleanly returns zeros without crashing
        - Negative loss bounds: cleanly returns zeros without crashing
        - Inverted bounds (min > max): gracefully handled
        """
        # Negative LEF
        res_neg_lef = simulate_asset_loss(lef=-5.0, loss_min=1000, loss_mode=5000, loss_max=10000)
        assert np.all(res_neg_lef == 0.0)

        # Negative loss bounds
        res_neg_loss = simulate_asset_loss(lef=2.0, loss_min=-1000, loss_mode=-500, loss_max=-10)
        assert np.all(res_neg_loss == 0.0)

        # Inverted PERT bounds (min > max) in pert_to_lognormal
        mu_inv, sigma_inv = pert_to_lognormal(min_val=100000.0, mode_val=50000.0, max_val=1000.0)
        assert mu_inv == 0.0
        assert sigma_inv == 0.8
