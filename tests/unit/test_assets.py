"""Unit tests for asset models, NetworkX dependency DAG percolation, graph centrality, and dynamic ACS scoring."""

import pytest
from pydantic import ValidationError

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
from src.config import BASE_REGULATORY_FINE, DEFAULT_MTTR_HOURS, MAX_ENTERPRISE_VALUATION
from src.telemetry.generator import ApexEnterpriseGenerator
from src.telemetry.models import ExploitMaturity, VulnerabilityFinding


# ---------------------------------------------------------------------------
# Test 1: AssetRecord and BusinessService Pydantic Schemas
# ---------------------------------------------------------------------------
def test_business_service_model() -> None:
    """Validates BusinessService model fields and constraints."""
    service = BusinessService(
        service_id="SVC-SWIFT",
        name="SWIFT Wire Settlement",
        business_unit="Payment Services",
        revenue_per_hour_downtime=1_200_000.0,
        criticality=1.0,
        description="Global institutional wire settlements",
    )
    assert service.service_id == "SVC-SWIFT"
    assert service.revenue_per_hour_downtime == 1_200_000.0
    assert service.criticality == 1.0

    # Negative revenue validation
    with pytest.raises(ValidationError):
        BusinessService(
            service_id="SVC-ERR",
            name="Error Service",
            business_unit="IT",
            revenue_per_hour_downtime=-500.0,
        )


def test_asset_record_model() -> None:
    """Validates AssetRecord model attributes and defaults."""
    asset = AssetRecord(
        asset_id="PAY-DB-01",
        name="oracle-payment-cluster-01",
        business_unit="Payment Services",
        environment=EnvironmentTier.PRODUCTION,
        asset_type=AssetType.DATABASE,
        data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
        replacement_cost=250_000.0,
        downtime_cost_per_hour=150_000.0,
        dependent_services=["SVC-SWIFT"],
        financial_asset_valuation=50_000_000.0,
    )
    assert asset.asset_id == "PAY-DB-01"
    assert asset.environment == EnvironmentTier.PRODUCTION
    assert asset.asset_type == AssetType.DATABASE
    assert asset.data_sensitivity_tier == DataSensitivityTier.RESTRICTED
    assert asset.replacement_cost == 250_000.0
    assert asset.downtime_cost_per_hour == 150_000.0
    assert len(asset.dependent_services) == 1


# ---------------------------------------------------------------------------
# Test 2: NetworkX Dependency DAG Percolation & Upstream Revenue Aggregation
# ---------------------------------------------------------------------------
def test_networkx_dag_percolation_and_revenue_aggregation() -> None:
    """
    Tests upstream failure percolation across a multi-tier dependency topology:
      - Service S1 ($500,000/hr) -> App A1 ($20,000/hr)
      - Service S2 ($800,000/hr) -> App A2 ($30,000/hr)
      - Both App A1 and App A2 depend on Database DB1 ($50,000/hr)
    """
    graph = EnterpriseDependencyGraph()

    s1 = BusinessService(
        service_id="SVC-RETAIL",
        name="Retail Banking",
        business_unit="Retail",
        revenue_per_hour_downtime=500_000.0,
        criticality=0.85,
    )
    s2 = BusinessService(
        service_id="SVC-PAYMENTS",
        name="Merchant Payments",
        business_unit="Payments",
        revenue_per_hour_downtime=800_000.0,
        criticality=0.95,
    )
    graph.add_business_service(s1)
    graph.add_business_service(s2)

    a1 = AssetRecord(
        asset_id="APP-01",
        name="retail-api",
        business_unit="Retail",
        downtime_cost_per_hour=20_000.0,
    )
    a2 = AssetRecord(
        asset_id="APP-02",
        name="payments-api",
        business_unit="Payments",
        downtime_cost_per_hour=30_000.0,
    )
    db1 = AssetRecord(
        asset_id="DB-01",
        name="shared-oracle-cluster",
        business_unit="Core",
        downtime_cost_per_hour=50_000.0,
    )
    graph.add_asset(a1)
    graph.add_asset(a2)
    graph.add_asset(db1)

    # Wire dependencies: Service -> App -> DB
    graph.add_dependency("SVC-RETAIL", "APP-01")
    graph.add_dependency("APP-01", "DB-01")

    graph.add_dependency("SVC-PAYMENTS", "APP-02")
    graph.add_dependency("APP-02", "DB-01")

    assert graph.is_valid_dag() is True

    # 1. Percolate failure of DB-01 (infrastructure bottleneck)
    res_db = graph.percolate_failure("DB-01")
    assert len(res_db.impacted_services) == 2
    svc_ids = {s.service_id for s in res_db.impacted_services}
    assert svc_ids == {"SVC-RETAIL", "SVC-PAYMENTS"}
    # Expected: $500k + $800k (services) + $50k (db direct) = $1,350,000/hr
    assert res_db.total_upstream_revenue_per_hour == 1_350_000.0
    assert res_db.max_service_criticality == 0.95
    assert res_db.service_reachability_ratio == 1.0

    # 2. Percolate failure of APP-01 (isolated to Retail)
    res_a1 = graph.percolate_failure("APP-01")
    assert len(res_a1.impacted_services) == 1
    assert res_a1.impacted_services[0].service_id == "SVC-RETAIL"
    # Expected: $500k (service) + $20k (app direct) = $520,000/hr
    assert res_a1.total_upstream_revenue_per_hour == 520_000.0
    assert res_a1.max_service_criticality == 0.85
    assert res_a1.service_reachability_ratio == 0.5


def test_dag_cycle_detection_and_topological_sort() -> None:
    """Verifies that dependency graph strictly enforces acyclicity and provides topological sorting."""
    graph = EnterpriseDependencyGraph()
    a1 = AssetRecord(asset_id="NODE-A", name="Node A", business_unit="IT")
    a2 = AssetRecord(asset_id="NODE-B", name="Node B", business_unit="IT")
    a3 = AssetRecord(asset_id="NODE-C", name="Node C", business_unit="IT")
    graph.add_asset(a1)
    graph.add_asset(a2)
    graph.add_asset(a3)

    graph.add_dependency("NODE-A", "NODE-B")
    graph.add_dependency("NODE-B", "NODE-C")

    # Cycle attempt: NODE-C -> NODE-A
    with pytest.raises(ValueError, match="creates a cyclic dependency"):
        graph.add_dependency("NODE-C", "NODE-A")

    # Verify DAG remains valid and top-sorted
    assert graph.is_valid_dag() is True
    order = graph.topological_sort()
    assert order.index("NODE-A") < order.index("NODE-B") < order.index("NODE-C")


# ---------------------------------------------------------------------------
# Test 3: Graph Centrality and SPOF Identification
# ---------------------------------------------------------------------------
def test_graph_centrality_and_spof_detection() -> None:
    """Tests betweenness and in-degree centrality calculation and SPOF detection."""
    graph = EnterpriseDependencyGraph()

    s1 = BusinessService(service_id="S1", name="Service 1", business_unit="BU1", revenue_per_hour_downtime=100_000.0)
    s2 = BusinessService(service_id="S2", name="Service 2", business_unit="BU2", revenue_per_hour_downtime=200_000.0)
    s3 = BusinessService(service_id="S3", name="Service 3", business_unit="BU3", revenue_per_hour_downtime=300_000.0)
    graph.add_business_service(s1)
    graph.add_business_service(s2)
    graph.add_business_service(s3)

    db_spof = AssetRecord(asset_id="CORE-DB", name="Core DB", business_unit="Core")
    leaf_node = AssetRecord(asset_id="LEAF-WS", name="Leaf Workstation", business_unit="IT")
    graph.add_asset(db_spof)
    graph.add_asset(leaf_node)

    graph.add_dependency("S1", "CORE-DB")
    graph.add_dependency("S2", "CORE-DB")
    graph.add_dependency("S3", "CORE-DB")

    centrality = graph.calculate_centrality()
    assert "CORE-DB" in centrality
    assert centrality["CORE-DB"]["in_degree_centrality"] > centrality["LEAF-WS"]["in_degree_centrality"]

    # SPOF check (min_impacted_services=2)
    spofs = graph.identify_spofs(min_impacted_services=2)
    assert "CORE-DB" in spofs
    assert "LEAF-WS" not in spofs


# ---------------------------------------------------------------------------
# Test 4: Financial Asset Valuation & Dynamic ACS Formulation
# ---------------------------------------------------------------------------
def test_financial_asset_valuation_calculation() -> None:
    """Tests the financial asset valuation formula: C_replace + C_downtime + F_regulatory."""
    prod_asset = AssetRecord(
        asset_id="PROD-ASSET-01",
        name="prod-server",
        business_unit="Core",
        environment=EnvironmentTier.PRODUCTION,
        data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
        replacement_cost=50_000.0,
        downtime_cost_per_hour=10_000.0,
    )
    # With MTTR = 24.0h:
    # C_replace = $50,000
    # C_downtime = $10,000 * 24 = $240,000
    # F_regulatory = $500,000 * 2.5 (Restricted) * 1.0 (Production) = $1,250,000
    # Expected total = $50,000 + $240,000 + $1,250,000 = $1,540,000
    valuation = calculate_asset_financial_valuation(prod_asset, mttr_hours=24.0)
    assert valuation == 1_540_000.0


def test_dynamic_acs_scoring_tiers() -> None:
    """Validates that ACS correctly scores production critical assets high and sandbox assets low."""
    # Production asset with high upstream criticality
    prod_asset = AssetRecord(
        asset_id="PAY-PROD",
        name="payment-prod",
        business_unit="Payments",
        environment=EnvironmentTier.PRODUCTION,
        data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
        replacement_cost=100_000.0,
        downtime_cost_per_hour=50_000.0,
    )
    perc_prod = PercolationResult(
        asset_id="PAY-PROD",
        impacted_services=[BusinessService(service_id="S1", name="S1", business_unit="P", revenue_per_hour_downtime=500_000.0, criticality=1.0)],
        total_upstream_revenue_per_hour=550_000.0,
        max_service_criticality=1.0,
        service_reachability_ratio=0.8,
    )
    cent_prod = {"betweenness_centrality": 0.45, "in_degree_centrality": 0.5}
    acs_prod = calculate_asset_criticality_score(prod_asset, perc_prod, cent_prod)

    # Sandbox asset with zero upstream impact and public sensitivity
    sandbox_asset = AssetRecord(
        asset_id="DEV-SANDBOX",
        name="dev-sandbox",
        business_unit="IT",
        environment=EnvironmentTier.SANDBOX,
        data_sensitivity_tier=DataSensitivityTier.PUBLIC,
        replacement_cost=1_000.0,
        downtime_cost_per_hour=0.0,
    )
    perc_sbx = PercolationResult(
        asset_id="DEV-SANDBOX",
        impacted_services=[],
        total_upstream_revenue_per_hour=0.0,
        max_service_criticality=0.05,
        service_reachability_ratio=0.0,
    )
    acs_sbx = calculate_asset_criticality_score(sandbox_asset, perc_sbx)

    assert acs_prod > 0.70
    assert acs_sbx < 0.05
    assert acs_prod > 15 * acs_sbx


def test_contextual_severity_modifier() -> None:
    """Tests the contextual severity modifier function."""
    raw_sev = 10.0
    high_impact = calculate_contextual_severity(raw_sev, acs=0.95)
    low_impact = calculate_contextual_severity(raw_sev, acs=0.05)
    assert high_impact > low_impact
    # High: 10 * (0.4 + 1.6 * 0.95) = 19.2
    assert high_impact == pytest.approx(19.2, abs=0.01)
    # Low: 10 * (0.4 + 1.6 * 0.05) = 4.8
    assert low_impact == pytest.approx(4.8, abs=0.01)


# ---------------------------------------------------------------------------
# Test 5: MANDATORY >7,000x Dynamic Finding Impact Ratio Assertion
# ---------------------------------------------------------------------------
def test_dynamic_finding_impact_ratio_exceeds_7000x() -> None:
    """
    MANDATORY CRITICALITY INVARIANT:
    Identical technical findings (e.g., CVSS 9.8 CVE) MUST yield radically different
    quantified impact (>7,000x difference) when placed on a sandbox asset vs a core
    payment processing database with dependent revenue percolation.
    """
    generator = ApexEnterpriseGenerator(seed=42)
    assets, findings, graph = generator.generate_enterprise_dataset()

    # Locate Core Payment Database and Developer Sandbox
    pay_db = next(a for a in assets if a.asset_id == "PAY-DB-01")
    sandbox = next(a for a in assets if a.asset_id == "CORP-DEV-SANDBOX-01")

    assert pay_db is not None
    assert sandbox is not None
    assert pay_db.environment == EnvironmentTier.PRODUCTION
    assert sandbox.environment == EnvironmentTier.SANDBOX
    assert pay_db.data_sensitivity_tier == DataSensitivityTier.RESTRICTED
    assert sandbox.data_sensitivity_tier == DataSensitivityTier.PUBLIC

    # Evaluate identical technical finding: CVSS 9.8 CVE with EPSS 0.884
    vuln = VulnerabilityFinding(
        finding_id="VULN-IDENTICAL-TEST",
        asset_id="PLACEHOLDER",
        cve_id="CVE-2023-38606",
        title="OpenSSL Buffer Overrun",
        cvss_score=9.8,
        epss_score=0.884,
        exploit_maturity=ExploitMaturity.HIGH,
        cisa_kev=True,
    )

    impact_payment_db = calculate_finding_impact(vuln, pay_db, graph)
    impact_sandbox = calculate_finding_impact(vuln, sandbox, graph)

    impact_ratio = impact_payment_db / impact_sandbox

    # Assertions
    assert impact_payment_db > 1_000_000.0, f"Payment DB impact should be multi-million USD, got {impact_payment_db}"
    assert impact_sandbox < 500.0, f"Sandbox impact should be under $500 USD, got {impact_sandbox}"
    assert impact_ratio > 7000.0, (
        f"Dynamic impact ratio {impact_ratio:,.2f}x failed invariant: MUST BE > 7,000x!"
    )
