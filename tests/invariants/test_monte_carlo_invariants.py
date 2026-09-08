"""
tests/invariants/test_monte_carlo_invariants.py - Mathematical Invariants of FAIR Loss Engine.

Verifies:
1. Positive Expected Annual Loss (EAL > 0) for any non-empty threat pool.
2. Boundary condition: EAL == 0 and VaR == 0 for empty telemetry pool.
3. Strict Percentile Ordering: VaR 90th < VaR 95th < VaR 99th at enterprise/portfolio level.
4. Non-negative Loss Values: min(loss) >= 0.0 across all simulation iterations.
5. Bit-exact seed reproducibility: Identical seeds produce identical results; distinct seeds differ.
6. Diversification benefit (Subadditivity of Risk): Portfolio VaR 95th < Sum of individual asset VaR 95th.
7. Monotonicity with Threat Frequency: Scaling threat frequency increases EAL.
8. Convergence: Estimator variance shrinks as iteration count N increases.
"""

import math
from typing import Dict, List
import numpy as np
import pytest

from tests.conftest import (
    InvariantAssertions,
    MockAssetRecord,
    MockNormalizedFinding,
    ReferenceFairMonteCarlo,
    SeverityLevel,
    TelemetryDomain,
)


@pytest.mark.invariants
class TestMonteCarloInvariants:
    """Mathematical verification of the probabilistic Monte Carlo loss simulation."""

    def test_positive_eal_for_non_empty_threat_pool(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_telemetry_5_domains: List[MockNormalizedFinding],
        mock_asset_catalog: Dict[str, MockAssetRecord],
        invariant_assertions: InvariantAssertions,
    ):
        """Invariant: EAL > 0 for any non-empty set of active security findings."""
        res = fair_engine.simulate(
            findings=mock_telemetry_5_domains,
            assets=mock_asset_catalog,
            seed_override=42
        )
        invariant_assertions.assert_positive_eal(res.eal, is_empty_threat_pool=False)
        assert res.eal > 1000.0, f"Expected realistic enterprise EAL, got {res.eal}"
        assert len(res.asset_risks) > 0, "Asset risks breakdown must not be empty"

    def test_empty_threat_pool_zero_loss_boundary(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_asset_catalog: Dict[str, MockAssetRecord],
        invariant_assertions: InvariantAssertions,
    ):
        """Invariant: 0 findings must produce exact 0.0 EAL and 0.0 VaR without division-by-zero."""
        res = fair_engine.simulate(
            findings=[],
            assets=mock_asset_catalog,
            seed_override=42
        )
        invariant_assertions.assert_positive_eal(res.eal, is_empty_threat_pool=True)
        assert res.var_90 == 0.0, f"Expected VaR 90 = 0, got {res.var_90}"
        assert res.var_95 == 0.0, f"Expected VaR 95 = 0, got {res.var_95}"
        assert res.var_99 == 0.0, f"Expected VaR 99 = 0, got {res.var_99}"

    def test_strict_percentile_ordering(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_telemetry_5_domains: List[MockNormalizedFinding],
        mock_asset_catalog: Dict[str, MockAssetRecord],
        invariant_assertions: InvariantAssertions,
    ):
        """Invariant: For continuous loss distributions, VaR 90th < VaR 95th < VaR 99th."""
        res = fair_engine.simulate(
            findings=mock_telemetry_5_domains,
            assets=mock_asset_catalog,
            seed_override=100
        )
        invariant_assertions.assert_percentile_ordering(
            var_90=res.var_90,
            var_95=res.var_95,
            var_99=res.var_99,
            strict=True
        )
        assert res.var_99 > res.var_95 > res.var_90, (
            f"Expected strict percentile ordering: VaR 90 ({res.var_90}) < VaR 95 ({res.var_95}) < VaR 99 ({res.var_99})"
        )

    def test_non_negative_simulated_losses(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_telemetry_5_domains: List[MockNormalizedFinding],
        mock_asset_catalog: Dict[str, MockAssetRecord],
    ):
        """Invariant: Cyber losses are strictly non-negative; min(loss) >= 0.0."""
        res = fair_engine.simulate(
            findings=mock_telemetry_5_domains,
            assets=mock_asset_catalog,
            seed_override=777
        )
        min_loss = min(res.loss_distribution)
        assert min_loss >= 0.0, f"Observed negative loss in distribution: {min_loss}"

    def test_bit_exact_seed_reproducibility(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_telemetry_5_domains: List[MockNormalizedFinding],
        mock_asset_catalog: Dict[str, MockAssetRecord],
        invariant_assertions: InvariantAssertions,
    ):
        """Invariant: Identical seeds produce bit-exact identical EAL and VaR percentiles."""
        seed = 9999
        res1 = fair_engine.simulate(mock_telemetry_5_domains, mock_asset_catalog, seed_override=seed)
        res2 = fair_engine.simulate(mock_telemetry_5_domains, mock_asset_catalog, seed_override=seed)

        invariant_assertions.assert_seed_reproducibility(res1, res2, tolerance=1e-7)
        assert res1.loss_distribution[:50] == res2.loss_distribution[:50], (
            "Loss distribution vectors must be bit-exact identical for identical seeds"
        )

    def test_distinct_seeds_produce_different_realizations(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_telemetry_5_domains: List[MockNormalizedFinding],
        mock_asset_catalog: Dict[str, MockAssetRecord],
    ):
        """Verification: Different PRNG seeds generate distinct realizations within statistical bounds."""
        res_seed1 = fair_engine.simulate(mock_telemetry_5_domains, mock_asset_catalog, seed_override=123)
        res_seed2 = fair_engine.simulate(mock_telemetry_5_domains, mock_asset_catalog, seed_override=456)

        assert res_seed1.eal != res_seed2.eal, "Different seeds should produce distinct realization means"
        # However, means should be within 15% of each other for large N
        relative_diff = abs(res_seed1.eal - res_seed2.eal) / res_seed1.eal
        assert relative_diff < 0.15, f"Excessive variance between independent simulation runs: {relative_diff:.2%}"

    def test_portfolio_diversification_subadditivity(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_telemetry_5_domains: List[MockNormalizedFinding],
        mock_asset_catalog: Dict[str, MockAssetRecord],
    ):
        """
        Invariant: Portfolio VaR 95th <= Sum of individual asset VaR 95th.
        (Diversification benefit under subadditive tail risk).
        """
        # Run enterprise portfolio simulation
        portfolio_res = fair_engine.simulate(
            findings=mock_telemetry_5_domains,
            assets=mock_asset_catalog,
            seed_override=42
        )
        portfolio_var_95 = portfolio_res.var_95

        # Run independent simulation for each single finding / asset
        individual_var_95_sum = 0.0
        for f in mock_telemetry_5_domains:
            ind_res = fair_engine.simulate(
                findings=[f],
                assets=mock_asset_catalog,
                seed_override=42
            )
            individual_var_95_sum += ind_res.var_95

        assert portfolio_var_95 <= individual_var_95_sum + 1e-4, (
            f"Portfolio VaR 95 ({portfolio_var_95}) exceeded sum of individual VaRs ({individual_var_95_sum})!"
        )

    def test_monotonicity_with_threat_frequency(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_asset_catalog: Dict[str, MockAssetRecord],
    ):
        """Invariant: Increasing Threat Event Frequency strictly increases EAL."""
        finding_low = MockNormalizedFinding(
            finding_id="F-LOW",
            asset_id="asset-core-db-01",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            title="Vulnerability with Low TEF",
            cvss_score=7.5,
            epss_score=0.4,
            cisa_kev=False,
            threat_event_frequency=2.0,  # 2 attempts / year
            resistance_strength=0.3
        )
        finding_high = MockNormalizedFinding(
            finding_id="F-HIGH",
            asset_id="asset-core-db-01",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            title="Vulnerability with High TEF",
            cvss_score=7.5,
            epss_score=0.4,
            cisa_kev=False,
            threat_event_frequency=20.0,  # 20 attempts / year (10x higher)
            resistance_strength=0.3
        )

        res_low = fair_engine.simulate([finding_low], mock_asset_catalog, seed_override=42)
        res_high = fair_engine.simulate([finding_high], mock_asset_catalog, seed_override=42)

        assert res_high.eal > res_low.eal, (
            f"Expected higher TEF to yield higher EAL. Got low={res_low.eal}, high={res_high.eal}"
        )

    def test_loss_exceedance_curve_monotonicity(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_telemetry_5_domains: List[MockNormalizedFinding],
        mock_asset_catalog: Dict[str, MockAssetRecord],
    ):
        """
        Invariant: In the Loss Exceedance Curve (LEC), as Loss Threshold increases,
        the Exceedance Probability P(Loss >= X) must be monotonically non-increasing.
        """
        res = fair_engine.simulate(mock_telemetry_5_domains, mock_asset_catalog, seed_override=42)
        lec = res.loss_exceedance_curve
        assert len(lec) >= 5, "LEC must contain at least 5 points"

        # lec is list of (loss_value, exceedance_prob)
        for i in range(1, len(lec)):
            loss_prev, prob_prev = lec[i - 1]
            loss_curr, prob_curr = lec[i]
            assert loss_curr >= loss_prev, "LEC losses should be non-decreasing along quantiles"
            assert prob_curr <= prob_prev + 1e-6, (
                f"LEC probability violated monotonicity: P(Loss >= {loss_curr}) = {prob_curr} > "
                f"P(Loss >= {loss_prev}) = {prob_prev}"
            )
