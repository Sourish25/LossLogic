"""
src/quant/fair_mapper.py - Factor Analysis of Information Risk (FAIR) Parameter Mapper.

Translates technical security findings (NormalizedFinding, MockNormalizedFinding)
and enterprise asset records (AssetRecord, MockAssetRecord, EnterpriseDependencyGraph)
into standard FAIR quantitative risk parameters:
- Contact Frequency (CF)
- Probability of Action (PoA)
- Threat Event Frequency (TEF = CF * PoA)
- Threat Capability (TCap)
- Resistance Strength (RS)
- Vulnerability (Vuln = P(TCap > RS))
- Loss Event Frequency (LEF = TEF * Vuln)
- Primary Loss Magnitude (Incident Response + Downtime Outage + Asset Replacement)
- Secondary Loss Magnitude (Regulatory Fine + Litigation + Customer Churn)
- Three-point Beta-PERT & Log-Normal distribution parameterization (mu, sigma)
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, ConfigDict, Field

from src.config import (
    BASE_REGULATORY_FINE,
    DATA_SENSITIVITY_MULTIPLIERS,
    DEFAULT_MTTR_HOURS,
    ENVIRONMENT_MULTIPLIERS,
    DataSensitivityTier,
    EnvironmentTier,
)


class FairParameters(BaseModel):
    """Normalized FAIR quantitative parameters for loss frequency and magnitude."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    contact_frequency: float = Field(..., description="Threat Contact Frequency (CF) in events/year")
    probability_of_action: float = Field(..., ge=0.0, le=1.0, description="Probability of Action (PoA) [0.0, 1.0]")
    threat_event_frequency: float = Field(..., ge=0.0, description="Threat Event Frequency (TEF = CF * PoA)")
    threat_capability: float = Field(..., ge=0.0, le=1.0, description="Threat Capability (TCap) [0.0, 1.0]")
    resistance_strength: float = Field(..., ge=0.0, le=1.0, description="Asset Resistance Strength (RS) [0.0, 1.0]")
    vulnerability_probability: float = Field(..., ge=0.0, le=1.0, description="Vulnerability P(TCap > RS) [0.0, 1.0]")
    loss_event_frequency: float = Field(..., ge=0.0, description="Loss Event Frequency (LEF = TEF * Vuln)")
    primary_loss_min: float = Field(..., ge=0.0, description="Primary Loss Minimum bound ($)")
    primary_loss_mode: float = Field(..., ge=0.0, description="Primary Loss Most Likely / Mode ($)")
    primary_loss_max: float = Field(..., ge=0.0, description="Primary Loss Maximum bound ($)")
    secondary_loss_mode: float = Field(..., ge=0.0, description="Secondary Loss Most Likely / Mode ($)")
    loss_mu: float = Field(default=0.0, description="LogNormal distribution location parameter mu")
    loss_sigma: float = Field(default=0.8, ge=0.01, description="LogNormal distribution scale parameter sigma")
    secondary_probability: float = Field(default=0.5, ge=0.0, le=1.0, description="Probability of secondary loss trigger")
    secondary_loss_min: float = Field(default=0.0, ge=0.0, description="Secondary Loss Minimum bound ($)")
    secondary_loss_max: float = Field(default=0.0, ge=0.0, description="Secondary Loss Maximum bound ($)")


def get_tier_multiplier(asset: Optional[Any]) -> float:
    """Derives operational tier risk multiplier from asset record."""
    if asset is None:
        return 1.0

    # Support MockAssetRecord tier enum or string
    tier = getattr(asset, "tier", None)
    if tier is not None:
        val = tier.value if hasattr(tier, "value") else str(tier)
        val = val.upper()
        if "1" in val or "CRITICAL" in val:
            return 5.0
        elif "2" in val:
            return 2.0
        elif "3" in val:
            return 1.0
        elif "4" in val or "SANDBOX" in val:
            return 0.2

    # Support AssetRecord environment
    env = getattr(asset, "environment", None)
    if env is not None:
        val = env.value if hasattr(env, "value") else str(env)
        val = val.lower()
        if "prod" in val:
            return 5.0
        elif "stag" in val:
            return 2.0
        elif "dev" in val:
            return 1.0
        elif "sand" in val:
            return 0.2

    return 1.0


def get_data_sensitivity_multiplier(asset: Optional[Any]) -> float:
    """Derives data classification multiplier (Public: 0.2, Internal: 0.5, Confidential: 1.0, Restricted: 2.5)."""
    if asset is None:
        return 1.0

    sens = getattr(asset, "data_sensitivity_tier", None) or getattr(asset, "data_sensitivity", None)
    if sens is not None:
        val = sens.value if hasattr(sens, "value") else str(sens)
        val = val.upper()
        if "RESTRICTED" in val or "PCI" in val:
            return 2.5
        elif "CONFIDENTIAL" in val:
            return 1.0
        elif "INTERNAL" in val:
            return 0.5
        elif "PUBLIC" in val:
            return 0.2

    return 1.0


def get_acs(asset: Optional[Any]) -> float:
    """Returns normalized Asset Criticality Score (ACS), defaulting to 1.0."""
    if asset is None:
        return 1.0
    acs = getattr(asset, "asset_criticality_score", None)
    if acs is not None and float(acs) > 0:
        return float(acs)
    return 1.0


def get_downtime_hourly_cost(asset: Optional[Any], graph: Optional[Any] = None) -> float:
    """
    Computes effective hourly downtime cost, integrating upstream business service
    dependency percolation from EnterpriseDependencyGraph if available.
    """
    if asset is None:
        return 0.0

    direct_cost = float(
        getattr(asset, "downtime_cost_per_hour", 0.0)
        or getattr(asset, "hourly_downtime_revenue", 0.0)
        or 0.0
    )

    if graph is not None and hasattr(graph, "percolate_failure") and hasattr(asset, "asset_id"):
        try:
            percolation = graph.percolate_failure(asset.asset_id)
            if hasattr(percolation, "total_upstream_revenue_per_hour"):
                return max(direct_cost, float(percolation.total_upstream_revenue_per_hour))
        except Exception:
            pass

    return direct_cost


def calculate_contact_frequency(finding: Any, asset: Optional[Any] = None) -> float:
    """
    Computes Threat Contact Frequency (CF):
    Baseline 0.5-1.0 contacts/year, augmented by internet exposure, open ports,
    and SIEM alert velocities.
    """
    # If finding already defines threat_event_frequency, derive consistent CF
    tef = getattr(finding, "threat_event_frequency", None)
    epss = float(getattr(finding, "epss_score", 0.1) or 0.1)
    cisa_kev = bool(getattr(finding, "cisa_kev", False))
    poa = calculate_probability_of_action(epss, cisa_kev)

    if tef is not None and float(tef) > 0.0:
        return round(float(tef) / max(0.01, poa), 4)

    # Telemetry signal synthesis
    cf_base = 0.5
    raw = getattr(finding, "raw_payload", {}) or {}

    # Public exposure / open ports
    if raw.get("public_exposure") or raw.get("is_internet_facing"):
        cf_base += 3.0
    open_ports = raw.get("open_ports", [])
    if open_ports:
        cf_base += 5.0
        sensitive_ports = {21, 22, 23, 3389, 1433, 3306, 5432, 27017}
        if any(p in sensitive_ports for p in open_ports):
            cf_base += 5.0

    # SIEM alert velocity
    alert_count = raw.get("alert_count") or raw.get("event_count_24h") or 0
    cf_base += 0.15 * min(50, alert_count)

    return round(cf_base, 4)


def calculate_probability_of_action(
    epss_score: float, cisa_kev: bool = False, exploit_maturity: Optional[Any] = None
) -> float:
    """
    Derives Probability of Action (PoA) from exploit weaponization metrics:
    PoA = min(1.0, 0.05 + 0.65 * EPSS + 0.30 * I_KEV).
    """
    epss = max(0.0, min(1.0, float(epss_score)))
    poa = 0.05 + 0.65 * epss
    if cisa_kev:
        poa += 0.30

    if exploit_maturity is not None:
        mat_str = str(exploit_maturity).upper()
        if "WEAPONIZED" in mat_str:
            poa += 0.15
        elif "HIGH" in mat_str:
            poa += 0.10
        elif "FUNCTIONAL" in mat_str:
            poa += 0.05

    return round(max(0.01, min(1.0, poa)), 4)


def calculate_threat_capability(cvss_score: float, epss_score: float) -> float:
    """
    Threat Capability (TCap) distribution mean:
    TCap = min(1.0, max(0.05, EPSS * 1.5 + (CVSS / 20.0))).
    """
    cvss = max(0.0, min(10.0, float(cvss_score)))
    epss = max(0.0, min(1.0, float(epss_score)))
    tcap = epss * 1.5 + (cvss / 20.0)
    return round(max(0.05, min(1.0, tcap)), 4)


def calculate_resistance_strength(finding: Any, asset: Optional[Any] = None) -> float:
    """
    Extracts or models Resistance Strength (RS) degraded by unpatched findings.
    Bound to [0.01, 0.99].
    """
    rs = getattr(finding, "resistance_strength", None)
    if rs is not None:
        return round(max(0.01, min(0.99, float(rs))), 4)
    return 0.50


def calculate_vulnerability(threat_capability: float, resistance_strength: float) -> float:
    """
    FAIR Vulnerability: probability that threat capability overcomes resistance:
    Vuln = max(0.02, min(0.98, TCap * (1.0 - RS * 0.8))).
    """
    tcap = max(0.0, min(1.0, float(threat_capability)))
    rs = max(0.0, min(1.0, float(resistance_strength)))
    vuln = tcap * (1.0 - rs * 0.8)
    return round(max(0.02, min(0.98, vuln)), 4)


def calculate_primary_loss(
    cvss_score: float, asset: Optional[Any] = None, graph: Optional[Any] = None
) -> Tuple[float, float, float]:
    """
    Computes Primary Loss magnitude three-point bounds (min, mode, max):
    - Incident Response & Forensics: 50,000 * (CVSS / 5.0)^1.5 * TierMult * ACS
    - Downtime Revenue Loss: MTTR (4h default) * Upstream Hourly Downtime Revenue
    - Asset Restoration & Replacement: ReplacementCost * 0.05
    """
    cvss = max(0.0, min(10.0, float(cvss_score)))
    t_mult = get_tier_multiplier(asset)
    acs = get_acs(asset)

    ir_cost = 50000.0 * ((cvss / 5.0) ** 1.5) * t_mult * acs

    downtime_cost = 0.0
    replacement_cost = 0.0
    if asset is not None:
        hourly_downtime = get_downtime_hourly_cost(asset, graph)
        downtime_cost = hourly_downtime * 4.0
        replacement_cost = float(getattr(asset, "replacement_cost", 0.0) or 0.0) * 0.05

    mode_val = max(0.0, ir_cost + downtime_cost + replacement_cost)
    min_val = round(mode_val * 0.25, 2)
    max_val = round(mode_val * 4.0, 2)
    return min_val, round(mode_val, 2), max_val


def calculate_secondary_loss(asset: Optional[Any] = None) -> Tuple[float, float, float, float]:
    """
    Computes Secondary Loss parameters (probability, min, mode, max):
    - Regulatory fine exposure: Base regulatory fine ($500k) * Data Sensitivity Multiplier
    - Customer notification, litigation & churn: $50,000 * SensMultiplier * ACS
    """
    sens_mult = get_data_sensitivity_multiplier(asset)
    acs = get_acs(asset)

    reg_fine = BASE_REGULATORY_FINE * sens_mult
    litigation = 50000.0 * sens_mult * acs
    sec_mode = reg_fine + litigation

    sec_prob = 0.10 if sens_mult <= 0.2 else (0.85 if sens_mult >= 2.0 else 0.50)
    sec_min = round(sec_mode * 0.20, 2)
    sec_max = round(sec_mode * 3.0, 2)
    return sec_prob, sec_min, round(sec_mode, 2), sec_max


def pert_to_lognormal(
    min_val: float, mode_val: float, max_val: float, gamma: float = 4.0
) -> Tuple[float, float]:
    """
    Converts a three-point PERT estimate (min, mode, max) into equivalent
    Log-Normal distribution parameters (mu, sigma).
    """
    if mode_val <= 0.0 or max_val <= min_val:
        return 0.0, 0.8

    mu_pert = (min_val + gamma * mode_val + max_val) / (gamma + 2.0)
    sigma_pert = (max_val - min_val) / (gamma + 2.0)
    var_pert = max(1e-6, sigma_pert ** 2)

    mu = float(math.log((mu_pert ** 2) / math.sqrt(var_pert + mu_pert ** 2)))
    sigma = float(math.sqrt(math.log(1.0 + var_pert / (mu_pert ** 2))))
    return mu, max(0.1, sigma)


class FairMapper:
    """
    Automated mapper translating security telemetry findings and asset criticalities
    into rigorous FAIR standard quantitative parameters.
    """

    @classmethod
    def map_finding(
        cls,
        finding: Any,
        asset: Optional[Any] = None,
        graph: Optional[Any] = None,
    ) -> FairParameters:
        """Translates a single finding and associated asset into complete FAIR parameters."""
        cvss = float(getattr(finding, "cvss_score", 5.0) or 5.0)
        epss = float(getattr(finding, "epss_score", 0.1) or 0.1)
        cisa_kev = bool(getattr(finding, "cisa_kev", False))
        exploit_maturity = getattr(finding, "exploit_maturity", None)

        cf = calculate_contact_frequency(finding, asset)
        poa = calculate_probability_of_action(epss, cisa_kev, exploit_maturity)

        # Respect pre-calculated threat_event_frequency on finding if present
        finding_tef = getattr(finding, "threat_event_frequency", None)
        if finding_tef is not None:
            tef = float(finding_tef)
        else:
            tef = round(cf * poa, 4)

        tcap = calculate_threat_capability(cvss, epss)
        rs = calculate_resistance_strength(finding, asset)
        vuln = calculate_vulnerability(tcap, rs)

        # Loss Event Frequency
        if tef <= 0.0:
            lef = 0.0
        else:
            lef = max(0.0001, round(tef * vuln, 6))

        # Primary Loss
        p_min, p_mode, p_max = calculate_primary_loss(cvss, asset, graph)

        # Secondary Loss
        s_prob, s_min, s_mode, s_max = calculate_secondary_loss(asset)

        # LogNormal location and scale parameterization
        # Use calibrated sigma=0.8 and mu=ln(max(100.0, mode)) consistent with standard cyber loss models
        mu = float(math.log(max(10.0, p_mode)))
        sigma = 0.8

        return FairParameters(
            contact_frequency=cf,
            probability_of_action=poa,
            threat_event_frequency=tef,
            threat_capability=tcap,
            resistance_strength=rs,
            vulnerability_probability=vuln,
            loss_event_frequency=lef,
            primary_loss_min=p_min,
            primary_loss_mode=p_mode,
            primary_loss_max=p_max,
            secondary_loss_mode=s_mode,
            loss_mu=mu,
            loss_sigma=sigma,
            secondary_probability=s_prob,
            secondary_loss_min=s_min,
            secondary_loss_max=s_max,
        )

    @classmethod
    def map_asset(
        cls,
        asset: Any,
        findings: List[Any],
        graph: Optional[Any] = None,
    ) -> FairParameters:
        """
        Aggregates multiple findings on an asset into asset-level compound FAIR parameters.
        """
        if not findings:
            p_min, p_mode, p_max = calculate_primary_loss(0.0, asset, graph)
            s_prob, s_min, s_mode, s_max = calculate_secondary_loss(asset)
            return FairParameters(
                contact_frequency=0.0,
                probability_of_action=0.0,
                threat_event_frequency=0.0,
                threat_capability=0.05,
                resistance_strength=0.99,
                vulnerability_probability=0.02,
                loss_event_frequency=0.0,
                primary_loss_min=0.0,
                primary_loss_mode=0.0,
                primary_loss_max=0.0,
                secondary_loss_mode=s_mode,
                loss_mu=0.0,
                loss_sigma=0.8,
                secondary_probability=s_prob,
                secondary_loss_min=s_min,
                secondary_loss_max=s_max,
            )

        total_lef = 0.0
        max_cvss = 0.0
        max_epss = 0.0
        any_kev = False
        min_rs = 1.0

        for f in findings:
            params = cls.map_finding(f, asset, graph)
            total_lef += params.loss_event_frequency
            max_cvss = max(max_cvss, float(getattr(f, "cvss_score", 0.0) or 0.0))
            max_epss = max(max_epss, float(getattr(f, "epss_score", 0.0) or 0.0))
            any_kev = any_kev or bool(getattr(f, "cisa_kev", False))
            min_rs = min(min_rs, params.resistance_strength)

        tcap = calculate_threat_capability(max_cvss, max_epss)
        vuln = calculate_vulnerability(tcap, min_rs)
        poa = calculate_probability_of_action(max_epss, any_kev)
        cf = round(total_lef / max(0.01, vuln * poa), 4)

        p_min, p_mode, p_max = calculate_primary_loss(max_cvss, asset, graph)
        s_prob, s_min, s_mode, s_max = calculate_secondary_loss(asset)

        mu = float(math.log(max(10.0, p_mode)))

        return FairParameters(
            contact_frequency=cf,
            probability_of_action=poa,
            threat_event_frequency=round(total_lef / max(0.01, vuln), 4),
            threat_capability=tcap,
            resistance_strength=min_rs,
            vulnerability_probability=vuln,
            loss_event_frequency=round(total_lef, 6),
            primary_loss_min=p_min,
            primary_loss_mode=p_mode,
            primary_loss_max=p_max,
            secondary_loss_mode=s_mode,
            loss_mu=mu,
            loss_sigma=0.8,
            secondary_probability=s_prob,
            secondary_loss_min=s_min,
            secondary_loss_max=s_max,
        )
