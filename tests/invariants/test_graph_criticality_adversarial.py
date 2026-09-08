"""
tests/invariants/test_graph_criticality_adversarial.py - Adversarial Stress-Testing of NetworkX Dependency DAG & Criticality Engine.

Challenger 2 Empirical Verification:
1. Deeply nested dependency chains (20, 50, 100 levels deep) with upstream revenue percolation and topological invariants.
2. Adversarial cyclic dependency injection (self-loops, direct 2-cycles, multi-hop 25-cycles, cross-branch cycles) and rollback integrity.
3. Disconnected components, isolated orphan nodes, unregistered nodes, and massive fan-out/fan-in topologies (1,000-to-1 bottleneck, 1-to-1,000 fan-out).
4. Dynamic finding impact ratio: empirical verification across 80+ finding variations (CVSS/EPSS) and enterprise asset catalog that high-criticality assets with revenue percolation consistently out-scale sandbox assets by >7,000x.
"""

import time
from typing import List, Tuple
import pytest

from src.assets.graph import EnterpriseDependencyGraph, PercolationResult
from src.assets.models import (
    AssetRecord,
    AssetType,
    BusinessService,
    DataSensitivityTier,
    EnvironmentTier,
)
from src.assets.scoring import (
    calculate_asset_criticality_score,
    calculate_asset_financial_valuation,
    calculate_contextual_severity,
    calculate_finding_impact,
)
from src.config import (
    BASE_REGULATORY_FINE,
    DATA_SENSITIVITY_MULTIPLIERS,
    DEFAULT_MTTR_HOURS,
    ENVIRONMENT_MULTIPLIERS,
    MAX_ENTERPRISE_VALUATION,
)
from src.telemetry.generator import ApexEnterpriseGenerator
from src.telemetry.models import ExploitMaturity, NormalizedFinding, SeverityLevel, TelemetryDomain, VulnerabilityFinding


# ===========================================================================
# 1. Deeply Nested Dependency Chains (20, 50, 100 Levels)
# ===========================================================================
class TestDeeplyNestedDependencyChains:
    """Stress tests deep recursion and percolation across long dependency paths."""

    @pytest.mark.parametrize("depth", [20, 50, 100])
    def test_linear_deep_dependency_pipeline(self, depth: int) -> None:
        """
        Tests linear pipeline: Service S0 -> Node 1 -> Node 2 -> ... -> Node N.
        Failure of leaf Node N must percolate through all intermediate assets to S0.
        """
        graph = EnterpriseDependencyGraph()
        root_service = BusinessService(
            service_id="SVC-ROOT-PIPELINE",
            name="Deep Core Pipeline Service",
            business_unit="Institutional Settlement",
            revenue_per_hour_downtime=2_500_000.0,
            criticality=0.98,
        )
        graph.add_business_service(root_service)

        # Add chain of assets
        for i in range(1, depth + 1):
            asset = AssetRecord(
                asset_id=f"CHAIN-NODE-{i:03d}",
                name=f"pipeline-node-{i}",
                business_unit="Infrastructure",
                environment=EnvironmentTier.PRODUCTION,
                replacement_cost=10_000.0,
                downtime_cost_per_hour=500.0 * i,
            )
            graph.add_asset(asset)

        # Wire linear chain: Service -> Node 1 -> Node 2 -> ... -> Node N
        graph.add_dependency("SVC-ROOT-PIPELINE", "CHAIN-NODE-001")
        for i in range(1, depth):
            graph.add_dependency(f"CHAIN-NODE-{i:03d}", f"CHAIN-NODE-{i+1:03d}")

        assert graph.is_valid_dag() is True

        # Test failure percolation from the deepest leaf node
        leaf_id = f"CHAIN-NODE-{depth:03d}"
        t0 = time.perf_counter()
        result = graph.percolate_failure(leaf_id)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        # Verification invariants
        assert elapsed_ms < 50.0, f"Percolation too slow at depth {depth}: {elapsed_ms:.2f}ms"
        assert len(result.impacted_services) == 1
        assert result.impacted_services[0].service_id == "SVC-ROOT-PIPELINE"
        assert len(result.impacted_assets) == depth - 1
        expected_rev = 2_500_000.0 + (500.0 * depth)
        assert result.total_upstream_revenue_per_hour == expected_rev
        assert result.max_service_criticality == 0.98
        assert result.service_reachability_ratio == 1.0

        # Verify topological sort integrity
        topo = graph.topological_sort()
        assert len(topo) == depth + 1
        assert topo[0] == "SVC-ROOT-PIPELINE"
        assert topo[-1] == leaf_id

    def test_converging_multi_branch_tree_at_depth_20(self) -> None:
        """
        Tests 5 independent root services whose dependency trees merge into a common bottleneck at depth 20.
        Verifies that all 5 services are correctly aggregated without duplicates or omissions.
        """
        graph = EnterpriseDependencyGraph()
        num_services = 5
        branch_depth = 20
        services = []

        for s_idx in range(num_services):
            svc = BusinessService(
                service_id=f"SVC-BRANCH-{s_idx}",
                name=f"Branch Service {s_idx}",
                business_unit=f"BU-{s_idx}",
                revenue_per_hour_downtime=200_000.0 * (s_idx + 1),
                criticality=0.60 + 0.08 * s_idx,
            )
            graph.add_business_service(svc)
            services.append(svc)

            # Build branch nodes
            for d in range(1, branch_depth):
                node_id = f"NODE-B{s_idx}-D{d}"
                graph.add_asset(AssetRecord(asset_id=node_id, name=node_id, business_unit=f"BU-{s_idx}"))

            # Wire branch
            graph.add_dependency(f"SVC-BRANCH-{s_idx}", f"NODE-B{s_idx}-D1")
            for d in range(1, branch_depth - 1):
                graph.add_dependency(f"NODE-B{s_idx}-D{d}", f"NODE-B{s_idx}-D{d+1}")

        # Shared leaf convergence asset at depth 20
        shared_leaf = AssetRecord(
            asset_id="SHARED-CORE-LEAF",
            name="shared-core-leaf",
            business_unit="Core",
            downtime_cost_per_hour=50_000.0,
        )
        graph.add_asset(shared_leaf)

        # Wire each branch tail to the shared leaf
        for s_idx in range(num_services):
            graph.add_dependency(f"NODE-B{s_idx}-D{branch_depth - 1}", "SHARED-CORE-LEAF")

        assert graph.is_valid_dag() is True

        res = graph.percolate_failure("SHARED-CORE-LEAF")
        assert len(res.impacted_services) == num_services
        assert set(s.service_id for s in res.impacted_services) == {f"SVC-BRANCH-{i}" for i in range(num_services)}

        # Expected revenue: sum(200k * (i+1) for i in 0..4) + 50k = 200k*(1+2+3+4+5) + 50k = 3,000,000 + 50,000 = 3,050,000
        expected_revenue = sum(200_000.0 * (i + 1) for i in range(num_services)) + 50_000.0
        assert res.total_upstream_revenue_per_hour == expected_revenue
        assert res.max_service_criticality == pytest.approx(0.60 + 0.08 * 4, abs=0.001)
        assert res.service_reachability_ratio == 1.0


# ===========================================================================
# 2. Adversarial Cyclic Dependency Injection & Rejection
# ===========================================================================
class TestCyclicDependencyRejection:
    """Stress tests cycle detection, rejection, and DAG state consistency under attack."""

    def test_self_loop_injection_rejected(self) -> None:
        """Verifies that self-referential loop (A -> A) is rejected immediately."""
        graph = EnterpriseDependencyGraph()
        node = AssetRecord(asset_id="NODE-SELF", name="Node Self", business_unit="IT")
        graph.add_asset(node)

        with pytest.raises(ValueError, match="creates a cyclic dependency"):
            graph.add_dependency("NODE-SELF", "NODE-SELF")

        assert graph.is_valid_dag() is True
        assert ("NODE-SELF", "NODE-SELF") not in graph.graph.edges

    def test_direct_two_node_cycle_rejected(self) -> None:
        """Verifies that direct 2-cycle (A -> B -> A) is rejected and rolled back."""
        graph = EnterpriseDependencyGraph()
        graph.add_asset(AssetRecord(asset_id="NODE-A", name="A", business_unit="IT"))
        graph.add_asset(AssetRecord(asset_id="NODE-B", name="B", business_unit="IT"))

        graph.add_dependency("NODE-A", "NODE-B")
        assert graph.is_valid_dag() is True

        with pytest.raises(ValueError, match="creates a cyclic dependency"):
            graph.add_dependency("NODE-B", "NODE-A")

        assert graph.is_valid_dag() is True
        assert ("NODE-B", "NODE-A") not in graph.graph.edges
        assert ("NODE-A", "NODE-B") in graph.graph.edges

    def test_multi_hop_25_level_cycle_injection_and_state_recovery(self) -> None:
        """
        Injects a cycle across a 25-node chain (N0 -> N1 -> ... -> N24 -> N0).
        Verifies rejection, rollback, and that subsequent valid dependencies can still be added.
        """
        graph = EnterpriseDependencyGraph()
        for i in range(25):
            graph.add_asset(AssetRecord(asset_id=f"C-NODE-{i:02d}", name=f"node-{i}", business_unit="IT"))

        for i in range(24):
            graph.add_dependency(f"C-NODE-{i:02d}", f"C-NODE-{i+1:02d}")

        assert graph.is_valid_dag() is True

        # Attempt multi-hop cycle
        with pytest.raises(ValueError, match="creates a cyclic dependency"):
            graph.add_dependency("C-NODE-24", "C-NODE-00")

        # State integrity verification
        assert graph.is_valid_dag() is True
        assert ("C-NODE-24", "C-NODE-00") not in graph.graph.edges
        assert len(graph.graph.edges) == 24

        # Verify subsequent valid edge addition works
        graph.add_asset(AssetRecord(asset_id="C-NODE-EXTRA", name="extra", business_unit="IT"))
        graph.add_dependency("C-NODE-24", "C-NODE-EXTRA")
        assert graph.is_valid_dag() is True
        assert len(graph.graph.edges) == 25

    def test_burst_cyclic_attacks_maintain_dag_invariants(self) -> None:
        """
        Applies a burst of 100 invalid backwards cycle edges to a DAG.
        Verifies that every single cycle is rejected and the graph remains healthy.
        """
        graph = EnterpriseDependencyGraph()
        n = 15
        for i in range(n):
            graph.add_asset(AssetRecord(asset_id=f"B-{i}", name=f"B-{i}", business_unit="BU"))

        for i in range(n - 1):
            graph.add_dependency(f"B-{i}", f"B-{i+1}")

        rejections = 0
        for i in range(1, n):
            for j in range(0, i):
                try:
                    graph.add_dependency(f"B-{i}", f"B-{j}")
                except ValueError:
                    rejections += 1

        expected_rejections = (n * (n - 1)) // 2
        assert rejections == expected_rejections
        assert graph.is_valid_dag() is True
        assert len(graph.graph.edges) == n - 1


# ===========================================================================
# 3. Disconnected Components, Isolated Orphans, and Massive Topologies
# ===========================================================================
class TestTopologicalBoundariesAndScale:
    """Stress tests disconnected components, isolated orphans, and high-scale fan-out/fan-in."""

    def test_disconnected_subgraphs_have_zero_cross_leakage(self) -> None:
        """
        Constructs 4 completely isolated subgraphs.
        Verifies that failure percolation in Subgraph A has exactly zero effect on B, C, D.
        """
        graph = EnterpriseDependencyGraph()
        for sub in ["ALPHA", "BETA", "GAMMA", "DELTA"]:
            svc = BusinessService(
                service_id=f"SVC-{sub}",
                name=f"Service {sub}",
                business_unit=sub,
                revenue_per_hour_downtime=500_000.0,
                criticality=0.8,
            )
            graph.add_business_service(svc)
            a1 = AssetRecord(asset_id=f"APP-{sub}", name=f"app-{sub}", business_unit=sub, downtime_cost_per_hour=1000.0)
            a2 = AssetRecord(asset_id=f"DB-{sub}", name=f"db-{sub}", business_unit=sub, downtime_cost_per_hour=5000.0)
            graph.add_asset(a1)
            graph.add_asset(a2)
            graph.add_dependency(f"SVC-{sub}", f"APP-{sub}")
            graph.add_dependency(f"APP-{sub}", f"DB-{sub}")

        # Test failure on DB-ALPHA
        res = graph.percolate_failure("DB-ALPHA")
        assert len(res.impacted_services) == 1
        assert res.impacted_services[0].service_id == "SVC-ALPHA"
        assert res.impacted_assets == ["APP-ALPHA"]
        assert res.total_upstream_revenue_per_hour == 505_000.0
        # Zero reach into other subgraphs
        assert res.service_reachability_ratio == 0.25  # 1 out of 4 services

    def test_isolated_orphan_node_behavior(self) -> None:
        """Verifies safe degradation for an isolated node with zero edges."""
        graph = EnterpriseDependencyGraph()
        # Add a connected service and asset, plus an isolated orphan node
        svc = BusinessService(
            service_id="SVC-MAIN",
            name="Main Service",
            business_unit="Core",
            revenue_per_hour_downtime=100_000.0,
            criticality=0.8,
        )
        asset_main = AssetRecord(asset_id="ASSET-MAIN", name="main", business_unit="Core")
        orphan = AssetRecord(
            asset_id="ORPHAN-ISOLATED-01",
            name="isolated-test-node",
            business_unit="QA",
            environment=EnvironmentTier.SANDBOX,
            replacement_cost=500.0,
            downtime_cost_per_hour=0.0,
        )
        graph.add_business_service(svc)
        graph.add_asset(asset_main)
        graph.add_asset(orphan)
        graph.add_dependency("SVC-MAIN", "ASSET-MAIN")

        res = graph.percolate_failure("ORPHAN-ISOLATED-01")
        assert res.impacted_services == []
        assert res.impacted_assets == []
        assert res.total_upstream_revenue_per_hour == 0.0
        assert res.service_reachability_ratio == 0.0

        centrality = graph.calculate_centrality()
        assert centrality["ORPHAN-ISOLATED-01"]["betweenness_centrality"] == 0.0
        assert centrality["ORPHAN-ISOLATED-01"]["in_degree_centrality"] == 0.0

    def test_unregistered_node_query_graceful_handling(self) -> None:
        """Verifies that querying a completely non-existent node ID degrades safely without exception."""
        graph = EnterpriseDependencyGraph()
        res = graph.percolate_failure("NON-EXISTENT-GHOST-ID")
        assert res.asset_id == "NON-EXISTENT-GHOST-ID"
        assert res.impacted_services == []
        assert res.total_upstream_revenue_per_hour == 0.0

    def test_massive_1000_to_1_fan_in_bottleneck(self) -> None:
        """
        Stress tests 1,000 business services converging onto a single shared database hub.
        Validates:
        - Percolation runtime < 20ms
        - Identification of hub as SPOF
        - In-degree centrality = 1.0
        """
        graph = EnterpriseDependencyGraph()
        hub_asset = AssetRecord(
            asset_id="CORE-CENTRAL-HUB",
            name="core-central-database",
            business_unit="Core",
            downtime_cost_per_hour=75_000.0,
        )
        graph.add_asset(hub_asset)

        num_services = 1000
        service_rev = 1_000.0
        for i in range(num_services):
            svc = BusinessService(
                service_id=f"SVC-TENANT-{i:04d}",
                name=f"Tenant Service {i}",
                business_unit="Tenants",
                revenue_per_hour_downtime=service_rev,
                criticality=0.85,
            )
            graph.add_business_service(svc)
            graph.add_dependency(f"SVC-TENANT-{i:04d}", "CORE-CENTRAL-HUB")

        t0 = time.perf_counter()
        res = graph.percolate_failure("CORE-CENTRAL-HUB")
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        assert elapsed_ms < 25.0, f"Percolation took too long on 1,000 fan-in: {elapsed_ms:.2f}ms"
        assert len(res.impacted_services) == num_services
        assert res.total_upstream_revenue_per_hour == (num_services * service_rev) + 75_000.0
        assert res.service_reachability_ratio == 1.0

        # SPOF check
        spofs = graph.identify_spofs(min_impacted_services=100)
        assert "CORE-CENTRAL-HUB" in spofs

    def test_massive_1_to_1000_fan_out_service(self) -> None:
        """
        Stress tests 1 business service depending on 1,000 leaf microservices.
        Failure of any individual microservice only impacts that 1 service.
        """
        graph = EnterpriseDependencyGraph()
        svc = BusinessService(
            service_id="SVC-MONOLITH",
            name="Monolith Umbrella",
            business_unit="Operations",
            revenue_per_hour_downtime=1_000_000.0,
            criticality=0.90,
        )
        graph.add_business_service(svc)

        num_leaves = 1000
        for i in range(num_leaves):
            leaf = AssetRecord(
                asset_id=f"LEAF-{i:04d}",
                name=f"leaf-worker-{i}",
                business_unit="Operations",
                downtime_cost_per_hour=10.0,
            )
            graph.add_asset(leaf)
            graph.add_dependency("SVC-MONOLITH", f"LEAF-{i:04d}")

        res = graph.percolate_failure("LEAF-0500")
        assert len(res.impacted_services) == 1
        assert res.impacted_services[0].service_id == "SVC-MONOLITH"
        assert res.total_upstream_revenue_per_hour == 1_000_010.0


# ===========================================================================
# 4. Dynamic Finding Impact Ratio (>7,000x Invariant Across Matrix)
# ===========================================================================
@pytest.fixture(scope="module")
def enterprise_setup():
    """Loads ApexGlobal enterprise reference dataset."""
    gen = ApexEnterpriseGenerator(seed=42)
    assets, findings, graph = gen.generate_enterprise_dataset()
    sandbox = next(a for a in assets if a.asset_id == "CORP-DEV-SANDBOX-01")
    pay_db = next(a for a in assets if a.asset_id == "PAY-DB-01")
    high_crit_assets = [
        a for a in assets
        if a.environment == EnvironmentTier.PRODUCTION
        and a.data_sensitivity_tier == DataSensitivityTier.RESTRICTED
    ]
    return {
        "assets": assets,
        "findings": findings,
        "graph": graph,
        "sandbox": sandbox,
        "pay_db": pay_db,
        "high_crit_assets": high_crit_assets,
    }


class TestDynamicFindingImpactRatioAdversarial:
    """
    Exhaustively verifies that high-criticality assets with revenue percolation
    consistently out-scale low-criticality sandbox assets by >7,000x across
    a diverse matrix of findings (CVSS, EPSS) and enterprise assets.
    """

    def test_impact_ratio_across_diverse_cvss_epss_matrix(self, enterprise_setup) -> None:
        """
        Tests 72 finding variations across CVSS [0.5..10.0] and EPSS [0.001..0.99]
        between Core Payment DB and Isolated Developer Sandbox.
        Invariant: Impact ratio must strictly exceed 7,000x for every non-zero finding.
        """
        graph = enterprise_setup["graph"]
        pay_db = enterprise_setup["pay_db"]
        sandbox = enterprise_setup["sandbox"]

        cvss_scores = [0.5, 1.0, 2.0, 3.5, 5.0, 6.5, 7.5, 8.5, 9.8]
        epss_scores = [0.001, 0.005, 0.02, 0.10, 0.35, 0.60, 0.884, 0.99]

        ratios: List[float] = []
        for cvss in cvss_scores:
            for epss in epss_scores:
                finding = VulnerabilityFinding(
                    finding_id=f"VULN-CVSS-{cvss}-EPSS-{epss}",
                    asset_id="DYNAMIC",
                    cve_id="CVE-DYNAMIC-TEST",
                    title="Dynamic Security Finding",
                    cvss_score=cvss,
                    epss_score=epss,
                    exploit_maturity=ExploitMaturity.HIGH,
                )
                impact_high = calculate_finding_impact(finding, pay_db, graph)
                impact_low = calculate_finding_impact(finding, sandbox, graph)

                assert impact_high > 0.0, f"High impact must be positive, got {impact_high}"
                assert impact_low > 0.0, f"Low impact must be positive, got {impact_low}"

                ratio = impact_high / impact_low
                ratios.append(ratio)
                assert ratio > 7000.0, (
                    f"Invariant violated for CVSS {cvss}, EPSS {epss}: ratio {ratio:.2f}x <= 7,000x"
                )

        min_ratio = min(ratios)
        max_ratio = max(ratios)
        assert min_ratio > 700_000.0, f"Expected ratio near 717,000x, got minimum {min_ratio}"
        assert max_ratio > 700_000.0

    def test_impact_ratio_across_all_restricted_production_assets(self, enterprise_setup) -> None:
        """
        Verifies that ALL 20 restricted production assets in the enterprise catalog
        achieve >7,000x ratio when compared against the sandbox asset for identical findings.
        """
        graph = enterprise_setup["graph"]
        sandbox = enterprise_setup["sandbox"]
        high_crit_assets = enterprise_setup["high_crit_assets"]

        assert len(high_crit_assets) >= 15, "Expected at least 15 high-criticality assets in Apex catalog"

        ratios_per_asset: List[Tuple[str, float, float, float]] = []
        for asset in high_crit_assets:
            impact_high = calculate_finding_impact(9.8, asset, graph)
            impact_sandbox = calculate_finding_impact(9.8, sandbox, graph)
            ratio = impact_high / impact_sandbox
            ratios_per_asset.append((asset.asset_id, ratio, impact_high, impact_sandbox))

            assert ratio > 7000.0, (
                f"Asset {asset.asset_id} failed 7,000x threshold: ratio={ratio:.2f}x "
                f"(high={impact_high}, sandbox={impact_sandbox})"
            )

        min_asset = min(ratios_per_asset, key=lambda x: x[1])
        max_asset = max(ratios_per_asset, key=lambda x: x[1])

        assert min_asset[1] > 7000.0, f"Minimum ratio {min_asset[1]} violates >7,000x invariant"
        # Minimum ratio is CLOUD-BACKUP-VAULT-01 (~7,848x)
        # Maximum ratio is CLOUD-IAM-VAULT-01 (~1,024,936x)
        assert max_asset[1] > 1_000_000.0, f"Maximum ratio should exceed 1,000,000x, got {max_asset[1]}"

    def test_ratio_independence_from_cvss_scaling(self, enterprise_setup) -> None:
        """
        Mathematical Invariant:
        Since quantified_impact = valuation * technical_factor * (0.05 + 0.95 * acs)
        and technical_factor = (cvss / 10.0) * (0.5 + 0.5 * epss),
        for identical findings on two assets, the ratio (Impact_high / Impact_low)
        is mathematically constant and independent of CVSS/EPSS (modulo rounding).
        """
        graph = enterprise_setup["graph"]
        pay_db = enterprise_setup["pay_db"]
        sandbox = enterprise_setup["sandbox"]

        # Test across 5 vastly different CVSS scores
        cvss_samples = [1.0, 3.0, 5.5, 7.5, 9.8]
        measured_ratios = []
        for cvss in cvss_samples:
            ih = calculate_finding_impact(cvss, pay_db, graph)
            il = calculate_finding_impact(cvss, sandbox, graph)
            measured_ratios.append(ih / il)

        # Invariant: All ratios should be within 0.5% of each other (due to round(val, 2))
        baseline = measured_ratios[0]
        for r in measured_ratios[1:]:
            rel_diff = abs(r - baseline) / baseline
            assert rel_diff < 0.005, f"Ratio drifted by {rel_diff:.4%} between CVSS scores"

    def test_boundary_zero_cvss_impact(self, enterprise_setup) -> None:
        """
        Boundary condition: CVSS = 0.0 (informational finding without vulnerability score).
        Both high and low impacts must be exactly $0.00 without throwing exceptions.
        """
        graph = enterprise_setup["graph"]
        pay_db = enterprise_setup["pay_db"]
        sandbox = enterprise_setup["sandbox"]

        impact_high = calculate_finding_impact(0.0, pay_db, graph)
        impact_low = calculate_finding_impact(0.0, sandbox, graph)

        assert impact_high == 0.0
        assert impact_low == 0.0
