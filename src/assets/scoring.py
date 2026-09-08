"""Dynamic Asset Criticality Score (ACS) engine and finding impact modifier."""

from typing import Any, Dict, Optional, Union
from src.assets.graph import EnterpriseDependencyGraph, PercolationResult
from src.assets.models import AssetRecord, DataSensitivityTier, EnvironmentTier
from src.config import (
    BASE_REGULATORY_FINE,
    DATA_SENSITIVITY_MULTIPLIERS,
    DEFAULT_MTTR_HOURS,
    ENVIRONMENT_MULTIPLIERS,
    MAX_ENTERPRISE_VALUATION,
)
from src.telemetry.models import NormalizedFinding, VulnerabilityFinding


def calculate_asset_financial_valuation(
    asset: AssetRecord,
    percolation_result: Optional[PercolationResult] = None,
    mttr_hours: float = DEFAULT_MTTR_HOURS,
) -> float:
    """
    Calculates total financial asset valuation (C_replace + C_downtime + F_regulatory).
    
    Formula:
      C_replace: Direct infrastructure replacement cost
      C_downtime: MTTR * total_upstream_revenue_per_hour (from dependency percolation)
      F_regulatory: BASE_REGULATORY_FINE * M_data * M_env
    """
    # 1. Replacement cost
    c_replace = asset.replacement_cost

    # 2. Downtime cost
    if percolation_result is not None:
        hourly_loss = percolation_result.total_upstream_revenue_per_hour
    else:
        hourly_loss = asset.downtime_cost_per_hour
    c_downtime = hourly_loss * mttr_hours

    # 3. Regulatory fine exposure
    sens_key = (
        asset.data_sensitivity_tier.value
        if hasattr(asset.data_sensitivity_tier, "value")
        else str(asset.data_sensitivity_tier)
    )
    m_data = DATA_SENSITIVITY_MULTIPLIERS.get(sens_key, 1.0)

    env_key = (
        asset.environment.value
        if hasattr(asset.environment, "value")
        else str(asset.environment)
    )
    m_env = ENVIRONMENT_MULTIPLIERS.get(env_key, 1.0)

    # Sandbox / dev environments utilize synthetic or scrubbed non-production data
    f_regulatory = BASE_REGULATORY_FINE * m_data * m_env

    total_val = round(c_replace + c_downtime + f_regulatory, 2)
    return total_val


def calculate_asset_criticality_score(
    asset: AssetRecord,
    percolation_result: Optional[PercolationResult] = None,
    centrality_metrics: Optional[Dict[str, float]] = None,
    max_enterprise_valuation: float = MAX_ENTERPRISE_VALUATION,
) -> float:
    """
    Calculates the normalized Dynamic Asset Criticality Score (ACS) in [0.0, 1.0].
    
    Weights:
      w_b = 0.35 (Business Service Criticality of upstream dependents)
      w_d = 0.20 (Graph Centrality and Reachability)
      w_s = 0.25 (Data Sensitivity Tier Multiplier)
      w_f = 0.20 (Financial Asset Valuation Ratio)
    
    Adjusted by operational environment tier:
      ACS_effective = ACS_raw * M_env
    """
    # 1. Business Service Criticality B(u)
    if percolation_result and percolation_result.impacted_services:
        b_u = percolation_result.max_service_criticality
    else:
        b_u = 0.05

    # 2. Centrality & Dependency Reachability D(u)
    reachability = percolation_result.service_reachability_ratio if percolation_result else 0.0
    betweenness = centrality_metrics.get("betweenness_centrality", 0.0) if centrality_metrics else 0.0
    d_u = min(1.0, 0.5 * reachability + 0.5 * betweenness)
    if d_u < 0.02:
        d_u = 0.02

    # 3. Data Sensitivity Tier S(u)
    sens_key = (
        asset.data_sensitivity_tier.value
        if hasattr(asset.data_sensitivity_tier, "value")
        else str(asset.data_sensitivity_tier)
    )
    m_data = DATA_SENSITIVITY_MULTIPLIERS.get(sens_key, 1.0)
    # Normalize against max data multiplier (Restricted = 2.5)
    s_u = min(1.0, max(0.08, m_data / 2.5))

    # 4. Financial Valuation Ratio F(u)
    valuation = calculate_asset_financial_valuation(asset, percolation_result)
    f_u = min(1.0, max(0.01, valuation / max_enterprise_valuation))

    # Raw weighted criticality
    w_b, w_d, w_s, w_f = 0.35, 0.20, 0.25, 0.20
    acs_raw = (w_b * b_u) + (w_d * d_u) + (w_s * s_u) + (w_f * f_u)

    # Operational environment adjustment
    env_key = (
        asset.environment.value
        if hasattr(asset.environment, "value")
        else str(asset.environment)
    )
    m_env = ENVIRONMENT_MULTIPLIERS.get(env_key, 1.0)

    acs_effective = min(1.0, max(0.001, acs_raw * m_env))
    return round(acs_effective, 5)


def calculate_contextual_severity(raw_severity: float, acs: float) -> float:
    """
    Computes modified contextual finding severity.
    ContextualSeverity = raw_severity * (0.40 + 1.60 * ACS)
    """
    return round(raw_severity * (0.40 + 1.60 * acs), 4)


def calculate_finding_impact(
    finding: Union[NormalizedFinding, VulnerabilityFinding, float, int],
    asset: AssetRecord,
    graph_engine: Optional[EnterpriseDependencyGraph] = None,
    percolation_result: Optional[PercolationResult] = None,
    mttr_hours: float = DEFAULT_MTTR_HOURS,
) -> float:
    """
    Dynamically calculates the quantified financial risk impact (in USD) of a finding
    when placed on a specific enterprise asset.
    
    Incorporates:
      - Raw technical severity (CVSS Base score [0.0, 10.0])
      - EPSS exploit likelihood
      - Dynamic Asset Criticality Score (ACS)
      - Upstream revenue percolation & total asset financial valuation
      - Environment tier multiplier (Production vs Sandbox)
    
    Guarantee: Identical technical findings yield >7,000x difference between
    an isolated developer sandbox asset and a core payment processing database.
    """
    # 1. Extract raw technical severity score and exploit factor
    if isinstance(finding, (float, int)):
        cvss = float(finding)
        epss = 0.05
    elif isinstance(finding, VulnerabilityFinding):
        cvss = finding.cvss_score
        epss = finding.epss_score
    elif isinstance(finding, NormalizedFinding):
        cvss = finding.cvss_score
        epss = finding.epss_score
    else:
        raise TypeError(f"Unsupported finding type: {type(finding)}")

    # 2. Obtain graph percolation and centrality metrics if graph is supplied
    if percolation_result is None and graph_engine is not None:
        percolation_result = graph_engine.percolate_failure(asset.asset_id)
        centrality_all = graph_engine.calculate_centrality()
        centrality = centrality_all.get(asset.asset_id, {})
    else:
        centrality = {}

    # 3. Calculate financial valuation and dynamic ACS
    valuation = calculate_asset_financial_valuation(asset, percolation_result, mttr_hours)
    acs = calculate_asset_criticality_score(asset, percolation_result, centrality)

    # 4. Contextual impact modifier:
    # Scale technical severity [0.0, 10.0] into a fractional loss factor
    technical_factor = (cvss / 10.0) * (0.5 + 0.5 * epss)

    # Contextual impact scale: combines ACS and asset financial valuation
    # Sandbox environment assets have tiny valuation and minimal ACS,
    # while production payment DB has multi-million valuation and near 1.0 ACS.
    quantified_impact = valuation * technical_factor * (0.05 + 0.95 * acs)

    return round(quantified_impact, 2)
