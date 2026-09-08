"""
tests/e2e/test_tier2_boundary_corner.py - Tier 2 Boundary and Corner Case Testing.

Verifies extreme operational conditions, edge cases, numerical stability, and stress boundaries:
1. Zero budget ($0 / ₹0) and Infinite budget ($100M+ / ₹1,000 Cr).
2. Empty telemetry stream (0 findings, 0 alerts) without NaN or division by zero.
3. Extreme EPSS scores (0.0 and 1.0) and extreme CVSS scores (0.0 and 10.0).
4. Single isolated asset graph vs Deeply nested DAG (10 levels deep).
5. High-scale control portfolio (100+ controls knapsack optimization).
6. Catastrophic single loss event outlier (₹500 Crore single tail breach).
7. Infeasible budget: Mandatory controls exceeding available capital.
8. Telemetry records with boundary or extreme frequencies (10,000 attempts/yr vs 0.001 attempts/yr).
"""

import math
from typing import Dict, List
import networkx as nx
import numpy as np
import pytest

from tests.conftest import (
    AssetTier,
    DataSensitivity,
    InvariantAssertions,
    MockAssetRecord,
    MockCandidateControl,
    MockNormalizedFinding,
    ReferenceAssetGraph,
    ReferenceFairMonteCarlo,
    ReferenceKnapsackOptimizer,
    SeverityLevel,
    TelemetryDomain,
)


@pytest.mark.e2e
@pytest.mark.tier2
class TestTier2BoundaryCornerCases:
    """Boundary, extreme condition, and stress testing."""

    def test_zero_budget_and_infinite_budget(
        self,
        knapsack_optimizer: ReferenceKnapsackOptimizer,
        mock_control_portfolio: List[MockCandidateControl],
    ):
        """Boundary: $0 budget vs $1B budget."""
        # 1. Zero budget: spends exactly 0, selects 0 controls, no division by zero in ROSI
        res_zero = knapsack_optimizer.optimize(mock_control_portfolio, budget=0.0, baseline_eal=10000000.0)
        assert res_zero.allocated_spend == 0.0
        assert len(res_zero.selected_controls) == 0
        assert res_zero.portfolio_rosi == 0.0
        assert res_zero.risk_mitigated == 0.0

        # 2. Infinite budget: selects maximum non-conflicting portfolio
        res_inf = knapsack_optimizer.optimize(mock_control_portfolio, budget=1e12, baseline_eal=10000000.0)
        assert len(res_inf.selected_controls) >= 4
        assert res_inf.allocated_spend > 0.0
        # Check mutual exclusivity maintained even with infinite capital
        sel_ids = {c.control_id for c in res_inf.selected_controls}
        assert not ("CTRL-SIEM-AI" in sel_ids and "CTRL-LEGACY-SIEM" in sel_ids)

    def test_empty_telemetry_stream_boundary(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_asset_catalog: Dict[str, MockAssetRecord],
    ):
        """Boundary: Zero findings, zero alerts in enterprise."""
        res = fair_engine.simulate(findings=[], assets=mock_asset_catalog, seed_override=42)
        assert res.eal == 0.0
        assert res.var_90 == 0.0
        assert res.var_95 == 0.0
        assert res.var_99 == 0.0
        assert len(res.asset_risks) == 0
        assert len(res.loss_distribution) == fair_engine.iterations
        assert all(l == 0.0 for l in res.loss_distribution)
        assert not math.isnan(res.eal)

    def test_extreme_epss_and_cvss_scores(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_asset_catalog: Dict[str, MockAssetRecord],
    ):
        """Boundary: Minimal (0.0/0.0) and Maximum (1.0/10.0) vulnerability scores."""
        # Minimal threat finding
        f_min = MockNormalizedFinding(
            finding_id="F-MIN", asset_id="asset-core-db-01", domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.LOW, title="Zero Severity Baseline", cvss_score=0.0,
            epss_score=0.0, cisa_kev=False, threat_event_frequency=1.0, resistance_strength=0.99
        )
        # Maximal threat finding (Zero-Day Critical)
        f_max = MockNormalizedFinding(
            finding_id="F-MAX", asset_id="asset-core-db-01", domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.CRITICAL, title="Maximum Severity Threat", cvss_score=10.0,
            epss_score=1.0, cisa_kev=True, threat_event_frequency=100.0, resistance_strength=0.01
        )

        res_min = fair_engine.simulate([f_min], mock_asset_catalog, seed_override=42)
        res_max = fair_engine.simulate([f_max], mock_asset_catalog, seed_override=42)

        # Min scores produce negligible risk
        assert res_min.eal >= 0.0
        # Max scores produce orders of magnitude higher risk
        assert res_max.eal > res_min.eal * 20.0
        assert res_max.var_99 > res_max.var_95 > res_max.var_90

    def test_single_asset_isolated_vs_10_level_deep_dag(
        self,
        mock_dag_topologies: Dict[str, ReferenceAssetGraph],
    ):
        """Boundary: Isolated asset vs deeply nested 10-level DAG percolation."""
        isolated = mock_dag_topologies["isolated"]
        deep = mock_dag_topologies["deep"]

        # 1. Isolated asset: percolation equals base criticality
        crit_iso = isolated.calculate_percolated_criticality("standalone-01")
        assert crit_iso == 1.0

        # 2. Deep DAG leaf (deep-node-9 is depended upon by deep-node-0 through deep-node-8)
        crit_root = deep.calculate_percolated_criticality("deep-node-0")
        crit_leaf = deep.calculate_percolated_criticality("deep-node-9")

        assert crit_leaf > crit_root, (
            f"Expected leaf with 9 upstream dependencies to have higher percolated criticality "
            f"than root ({crit_leaf} vs {crit_root})"
        )
        # In a 10-level DAG, leaf has 9 ancestors
        ancestors_count = len(nx.ancestors(deep.graph, "deep-node-9"))
        assert ancestors_count == 9

    def test_high_scale_control_portfolio_100_controls(
        self,
        knapsack_optimizer: ReferenceKnapsackOptimizer,
    ):
        """Stress Boundary: Scalability testing with 100 candidate controls."""
        controls_100: List[MockCandidateControl] = []
        for i in range(100):
            controls_100.append(
                MockCandidateControl(
                    control_id=f"CTRL-SCALE-{i:03d}",
                    name=f"Scale Security Mitigation {i}",
                    category="Enterprise Scaling",
                    cost=float((i + 1) * 25000),  # ₹25k to ₹2.5M
                    target_finding_ids=[f"FIND-{i % 10}"],
                    effectiveness=min(0.95, 0.1 + (i % 8) * 0.1),
                    prerequisites=[f"CTRL-SCALE-{i-1:03d}"] if (i % 10 == 3 and i > 0) else [],
                    conflicts=[f"CTRL-SCALE-{i+1:03d}"] if (i % 15 == 0 and i < 99) else [],
                    is_mandatory=(i == 5 or i == 12)
                )
            )

        budget = 5000000.0  # ₹50 Lakhs
        res = knapsack_optimizer.optimize(
            controls=controls_100,
            budget=budget,
            baseline_eal=100000000.0  # ₹10 Crore
        )

        assert res.allocated_spend <= budget + 1e-6
        assert len(res.selected_controls) > 0
        assert res.risk_mitigated > 0.0
        # Check mandatory inclusion
        selected_ids = {c.control_id for c in res.selected_controls}
        if sum(c.cost for c in controls_100 if c.is_mandatory) <= budget:
            assert "CTRL-SCALE-005" in selected_ids

    def test_catastrophic_tail_event_outlier(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_asset_catalog: Dict[str, MockAssetRecord],
    ):
        """Boundary: Catastrophic ₹500 Crore single loss event."""
        catastrophic_asset = MockAssetRecord(
            asset_id="asset-central-vault",
            name="Apex Reserve Vault",
            business_unit="Treasury",
            tier=AssetTier.TIER_1,
            data_sensitivity=DataSensitivity.RESTRICTED_PCI,
            replacement_cost=5000000000.0,  # ₹500 Crore
            downtime_cost_per_hour=50000000.0,
            asset_criticality_score=10.0
        )
        catastrophic_finding = MockNormalizedFinding(
            finding_id="VULN-CATASTROPHIC",
            asset_id="asset-central-vault",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.CRITICAL,
            title="Catastrophic Unauthenticated Remote Code Execution",
            cvss_score=10.0,
            epss_score=0.99,
            cisa_kev=True,
            threat_event_frequency=5.0,
            resistance_strength=0.01
        )
        res = fair_engine.simulate(
            [catastrophic_finding],
            {catastrophic_asset.asset_id: catastrophic_asset},
            seed_override=42
        )
        # VaR 99 must capture extreme tail without integer or floating overflow
        assert res.var_99 > 100000000.0  # > ₹10 Crore
        assert not math.isinf(res.var_99)
        assert not math.isnan(res.var_99)
        assert res.var_99 > res.var_95 > res.var_90

    def test_infeasible_mandatory_controls_budget_handling(
        self,
        knapsack_optimizer: ReferenceKnapsackOptimizer,
    ):
        """Corner Case: Mandatory controls total cost exceeds user-provided budget."""
        mandatory_expensive = [
            MockCandidateControl(
                control_id="MAND-01", name="Mandatory Datacenter Overhaul", category="Physical",
                cost=10000000.0, target_finding_ids=["F1"], effectiveness=0.9, is_mandatory=True
            ),
            MockCandidateControl(
                control_id="MAND-02", name="Mandatory HSM Deployment", category="Crypto",
                cost=5000000.0, target_finding_ids=["F2"], effectiveness=0.85, is_mandatory=True
            ),
        ]
        low_budget = 1000000.0  # ₹10 Lakhs (far less than ₹1.5 Cr needed)

        # Optimizer must handle gracefully without crashing or breaching budget
        res = knapsack_optimizer.optimize(mandatory_expensive, budget=low_budget, baseline_eal=50000000.0)
        assert res.allocated_spend <= low_budget
        # Cannot fit either mandatory control, so 0 spend
        assert len(res.selected_controls) == 0

    def test_extreme_threat_frequencies(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_asset_catalog: Dict[str, MockAssetRecord],
    ):
        """Corner Case: Very low (0.001 / millennium) and very high (10,000 / year) frequencies."""
        f_ultra_low = MockNormalizedFinding(
            finding_id="F-ULTRA-LOW", asset_id="asset-core-db-01", domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.LOW, title="1-in-1000 year solar flare impact", cvss_score=5.0,
            epss_score=0.01, cisa_kev=False, threat_event_frequency=0.001, resistance_strength=0.5
        )
        f_ultra_high = MockNormalizedFinding(
            finding_id="F-ULTRA-HIGH", asset_id="asset-core-db-01", domain=TelemetryDomain.SIEM,
            severity=SeverityLevel.MEDIUM, title="DDoS Attack Wave", cvss_score=5.0,
            epss_score=0.1, cisa_kev=False, threat_event_frequency=10000.0, resistance_strength=0.5
        )

        res_low = fair_engine.simulate([f_ultra_low], mock_asset_catalog, seed_override=42)
        res_high = fair_engine.simulate([f_ultra_high], mock_asset_catalog, seed_override=42)

        # Ultra-low frequency will have 0 events in most iterations
        assert res_low.eal >= 0.0
        # Ultra-high frequency will have substantial loss
        assert res_high.eal > res_low.eal
        assert res_high.eal > 1000000.0
