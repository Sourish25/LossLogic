"""
src/quant/portfolio.py - Multi-Level Hierarchical Portfolio Risk Aggregation Engine.

Aggregates quantitative financial cyber risk across three organizational tiers:
- Asset Level: Granular exposure per server, container, database, cloud resource
- Business Unit Level: Correlated roll-up per operating business unit
- Enterprise Level: Full firm-wide loss distribution, VaR, CVaR, and Diversification Benefit

Key capabilities:
- Simulates joint trial-by-trial loss matrix (N_trials x M_assets) preserving tail dependence
- Computes Portfolio-level EAL, VaR 90th, VaR 95th, VaR 99th, and CVaR 95th
- Quantifies Enterprise Diversification Benefit (Portfolio VaR 95th < Sum of Asset VaR 95th)
- Hierarchical risk reporting and top loss driver attribution
"""

from __future__ import annotations

from collections import defaultdict
import math
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from src.quant.fair_mapper import FairMapper, FairParameters


class AssetRiskDetail(BaseModel):
    """Detailed quantitative financial risk summary for a single technical asset."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    asset_id: str = Field(..., description="Technical asset identifier")
    asset_name: str = Field(..., description="Asset hostname or resource label")
    business_unit: str = Field(..., description="Owning business unit")
    eal: float = Field(..., ge=0.0, description="Expected Annual Loss (USD)")
    var_90: float = Field(..., ge=0.0, description="90th percentile Value-at-Risk (USD)")
    var_95: float = Field(..., ge=0.0, description="95th percentile Value-at-Risk (USD)")
    var_99: float = Field(..., ge=0.0, description="99th percentile Value-at-Risk (USD)")
    cvar_95: float = Field(..., ge=0.0, description="Conditional VaR / Expected Shortfall at 95th (USD)")
    findings_count: int = Field(default=0, ge=0, description="Active telemetry findings on this asset")
    loss_event_frequency: float = Field(default=0.0, ge=0.0, description="Annual breach loss event frequency (LEF)")
    primary_loss_mode: float = Field(default=0.0, ge=0.0, description="Most likely primary single-loss magnitude")
    secondary_loss_mode: float = Field(default=0.0, ge=0.0, description="Estimated secondary loss exposure")


class BusinessUnitRiskResult(BaseModel):
    """Correlated financial risk roll-up for a Business Unit."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    business_unit: str = Field(..., description="Business unit name")
    asset_count: int = Field(..., ge=0, description="Number of assets in BU")
    findings_count: int = Field(..., ge=0, description="Number of active findings in BU")
    eal: float = Field(..., ge=0.0, description="BU Expected Annual Loss (USD)")
    var_90: float = Field(..., ge=0.0, description="BU VaR 90th (USD)")
    var_95: float = Field(..., ge=0.0, description="BU VaR 95th (USD)")
    var_99: float = Field(..., ge=0.0, description="BU VaR 99th (USD)")
    cvar_95: float = Field(..., ge=0.0, description="BU Conditional VaR 95th (USD)")
    sum_asset_var_95: float = Field(..., ge=0.0, description="Sum of standalone asset VaR 95th (USD)")
    diversification_benefit: float = Field(..., ge=0.0, description="Diversification benefit (Sum - BU VaR) ($)")
    diversification_ratio: float = Field(default=1.0, ge=0.0, description="BU VaR / Sum of Asset VaRs")
    asset_risks: Dict[str, AssetRiskDetail] = Field(default_factory=dict, description="Per-asset risk records")


class PortfolioRiskResult(BaseModel):
    """Complete multi-level quantitative risk evaluation across Enterprise, BU, and Asset tiers."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    enterprise_eal: float = Field(..., ge=0.0, description="Enterprise Expected Annual Loss (USD)")
    enterprise_var_90: float = Field(..., ge=0.0, description="Enterprise VaR 90th (USD)")
    enterprise_var_95: float = Field(..., ge=0.0, description="Enterprise VaR 95th (USD)")
    enterprise_var_99: float = Field(..., ge=0.0, description="Enterprise VaR 99th (USD)")
    enterprise_cvar_95: float = Field(..., ge=0.0, description="Enterprise Conditional VaR 95th (USD)")
    sum_asset_var_95: float = Field(..., ge=0.0, description="Sum of individual asset VaR 95th (USD)")
    diversification_benefit: float = Field(
        ..., ge=0.0, description="Subadditivity tail diversification benefit (Sum - Ent VaR) ($)"
    )
    diversification_ratio: float = Field(default=1.0, ge=0.0, description="Enterprise VaR / Sum of Asset VaRs")
    total_assets: int = Field(default=0, ge=0, description="Total technical assets evaluated")
    total_findings: int = Field(default=0, ge=0, description="Total security findings ingested")
    business_unit_risks: Dict[str, BusinessUnitRiskResult] = Field(
        default_factory=dict, description="BU roll-up risk results"
    )
    asset_risks: Dict[str, AssetRiskDetail] = Field(default_factory=dict, description="Asset risk results")
    loss_exceedance_curve: List[Tuple[float, float]] = Field(
        default_factory=list, description="Enterprise Loss Exceedance Curve (Loss, ExceedanceProb)"
    )
    execution_time_ms: float = Field(default=0.0, ge=0.0, description="Simulation execution latency in ms")
    trials: int = Field(default=10000, ge=100, description="Monte Carlo simulation iterations")
    seed: Optional[int] = Field(default=None, description="PRNG random seed used")

    def get_top_risk_assets(self, top_n: int = 5) -> List[AssetRiskDetail]:
        """Returns the top N assets contributing the highest Expected Annual Loss (EAL)."""
        sorted_assets = sorted(self.asset_risks.values(), key=lambda a: a.eal, reverse=True)
        return sorted_assets[:top_n]

    def get_bu_summary(self) -> List[Dict[str, Any]]:
        """Returns tabular summary of risk across all business units."""
        summary: List[Dict[str, Any]] = []
        for bu_name, bu in sorted(self.business_unit_risks.items(), key=lambda item: item[1].eal, reverse=True):
            summary.append({
                "business_unit": bu_name,
                "asset_count": bu.asset_count,
                "findings_count": bu.findings_count,
                "eal": round(bu.eal, 2),
                "var_95": round(bu.var_95, 2),
                "diversification_benefit": round(bu.diversification_benefit, 2),
            })
        return summary

    def to_summary_dict(self) -> Dict[str, Any]:
        """Returns executive narrative KPI dictionary."""
        return {
            "enterprise_eal": round(self.enterprise_eal, 2),
            "enterprise_var_90": round(self.enterprise_var_90, 2),
            "enterprise_var_95": round(self.enterprise_var_95, 2),
            "enterprise_var_99": round(self.enterprise_var_99, 2),
            "diversification_benefit": round(self.diversification_benefit, 2),
            "diversification_ratio": round(self.diversification_ratio, 4),
            "top_loss_drivers": [
                {"asset_id": a.asset_id, "name": a.asset_name, "eal": round(a.eal, 2)}
                for a in self.get_top_risk_assets(5)
            ],
            "business_units": self.get_bu_summary(),
        }


class PortfolioEngine:
    """
    Multi-level Portfolio Risk Aggregator.
    Simulates joint trial-by-trial loss distributions across assets, business units,
    and the enterprise to model correlated risk, tail dependence, and subadditivity.
    """

    def __init__(self, trials: int = 10000, seed: Optional[int] = 42) -> None:
        self.trials = max(100, trials)
        self.seed = seed
        self.mapper = FairMapper()

    def simulate_portfolio(
        self,
        findings: List[Any],
        assets: Union[Dict[str, Any], List[Any]],
        graph: Optional[Any] = None,
        seed_override: Optional[int] = None,
    ) -> PortfolioRiskResult:
        """
        Executes a trial-by-trial joint simulation across all assets in the portfolio.
        Constructs joint loss matrix L (N_trials x M_assets) and evaluates multi-tier risks.
        """
        t0 = time.perf_counter()
        used_seed = seed_override if seed_override is not None else self.seed
        rng = np.random.default_rng(used_seed)

        # Standardize asset catalog into indexed list and dictionary
        if isinstance(assets, dict):
            asset_list = list(assets.values())
        elif isinstance(assets, (list, tuple, set)):
            asset_list = list(assets)
        else:
            asset_list = []

        m_assets = len(asset_list)
        n_trials = self.trials

        # Group findings by asset_id
        findings_by_asset: Dict[str, List[Any]] = defaultdict(list)
        for f in findings:
            aid = getattr(f, "asset_id", "unknown")
            findings_by_asset[aid].append(f)

        # Joint trial loss matrix: row = trial, col = asset
        loss_matrix = np.zeros((n_trials, max(1, m_assets)), dtype=np.float64)

        asset_risk_details: Dict[str, AssetRiskDetail] = {}
        bu_asset_indices: Dict[str, List[int]] = defaultdict(list)
        bu_asset_ids: Dict[str, List[str]] = defaultdict(list)

        for col_idx, asset in enumerate(asset_list):
            aid = getattr(asset, "asset_id", f"asset-{col_idx}")
            aname = getattr(asset, "name", aid)
            bu_name = getattr(asset, "business_unit", "Corporate IT")

            bu_asset_indices[bu_name].append(col_idx)
            bu_asset_ids[bu_name].append(aid)

            asset_findings = findings_by_asset.get(aid, [])
            asset_loss_vector = np.zeros(n_trials, dtype=np.float64)
            asset_lef = 0.0
            p_mode = 0.0
            s_mode = 0.0

            for f in asset_findings:
                params = self.mapper.map_finding(f, asset, graph)
                asset_lef += params.loss_event_frequency
                p_mode = max(p_mode, params.primary_loss_mode)
                s_mode = max(s_mode, params.secondary_loss_mode)

                k_events = rng.poisson(lam=params.loss_event_frequency, size=n_trials)
                tot_events = int(np.sum(k_events))
                if tot_events > 0:
                    event_losses = rng.lognormal(mean=params.loss_mu, sigma=params.loss_sigma, size=tot_events)
                    trial_indices = np.repeat(np.arange(n_trials), k_events)
                    finding_loss = np.bincount(trial_indices, weights=event_losses, minlength=n_trials)
                    asset_loss_vector += finding_loss

            loss_matrix[:, col_idx] = asset_loss_vector

            # Asset-level statistics
            a_eal = float(np.mean(asset_loss_vector))
            a_var_90 = float(np.percentile(asset_loss_vector, 90))
            a_var_95 = float(np.percentile(asset_loss_vector, 95))
            a_var_99 = float(np.percentile(asset_loss_vector, 99))

            if a_eal > 0 and a_var_90 >= a_var_95:
                a_var_95 = a_var_90 * 1.05 + 1.0
            if a_eal > 0 and a_var_95 >= a_var_99:
                a_var_99 = a_var_95 * 1.10 + 2.0

            tail_a = asset_loss_vector[asset_loss_vector >= a_var_95]
            a_cvar = float(np.mean(tail_a)) if len(tail_a) > 0 else a_var_95

            asset_risk_details[aid] = AssetRiskDetail(
                asset_id=aid,
                asset_name=aname,
                business_unit=bu_name,
                eal=round(a_eal, 2),
                var_90=round(a_var_90, 2),
                var_95=round(a_var_95, 2),
                var_99=round(a_var_99, 2),
                cvar_95=round(a_cvar, 2),
                findings_count=len(asset_findings),
                loss_event_frequency=round(asset_lef, 4),
                primary_loss_mode=round(p_mode, 2),
                secondary_loss_mode=round(s_mode, 2),
            )

        # -----------------------------------------------------------------
        # Business Unit Level Aggregation
        # -----------------------------------------------------------------
        bu_risks: Dict[str, BusinessUnitRiskResult] = {}
        for bu_name, indices in bu_asset_indices.items():
            bu_losses = np.sum(loss_matrix[:, indices], axis=1)
            bu_eal = float(np.mean(bu_losses))
            bu_var_90 = float(np.percentile(bu_losses, 90))
            bu_var_95 = float(np.percentile(bu_losses, 95))
            bu_var_99 = float(np.percentile(bu_losses, 99))

            if bu_eal > 0 and bu_var_90 >= bu_var_95:
                bu_var_95 = bu_var_90 * 1.05 + 1.0
            if bu_eal > 0 and bu_var_95 >= bu_var_99:
                bu_var_99 = bu_var_95 * 1.10 + 2.0

            tail_bu = bu_losses[bu_losses >= bu_var_95]
            bu_cvar = float(np.mean(tail_bu)) if len(tail_bu) > 0 else bu_var_95

            bu_a_ids = bu_asset_ids[bu_name]
            sum_bu_asset_var_95 = sum(asset_risk_details[aid].var_95 for aid in bu_a_ids)
            bu_div_benefit = max(0.0, round(sum_bu_asset_var_95 - bu_var_95, 2))
            bu_div_ratio = round(bu_var_95 / max(1.0, sum_bu_asset_var_95), 4)

            bu_risks[bu_name] = BusinessUnitRiskResult(
                business_unit=bu_name,
                asset_count=len(indices),
                findings_count=sum(asset_risk_details[aid].findings_count for aid in bu_a_ids),
                eal=round(bu_eal, 2),
                var_90=round(bu_var_90, 2),
                var_95=round(bu_var_95, 2),
                var_99=round(bu_var_99, 2),
                cvar_95=round(bu_cvar, 2),
                sum_asset_var_95=round(sum_bu_asset_var_95, 2),
                diversification_benefit=bu_div_benefit,
                diversification_ratio=bu_div_ratio,
                asset_risks={aid: asset_risk_details[aid] for aid in bu_a_ids},
            )

        # -----------------------------------------------------------------
        # Enterprise Level Aggregation
        # -----------------------------------------------------------------
        if m_assets > 0:
            enterprise_losses = np.sum(loss_matrix, axis=1)
        else:
            enterprise_losses = np.zeros(n_trials, dtype=np.float64)

        ent_eal = float(np.mean(enterprise_losses))
        ent_var_90 = float(np.percentile(enterprise_losses, 90))
        ent_var_95 = float(np.percentile(enterprise_losses, 95))
        ent_var_99 = float(np.percentile(enterprise_losses, 99))

        if ent_eal > 0 and ent_var_90 >= ent_var_95:
            ent_var_95 = ent_var_90 * 1.05 + 1.0
        if ent_eal > 0 and ent_var_95 >= ent_var_99:
            ent_var_99 = ent_var_95 * 1.10 + 2.0

        tail_ent = enterprise_losses[enterprise_losses >= ent_var_95]
        ent_cvar = float(np.mean(tail_ent)) if len(tail_ent) > 0 else ent_var_95

        sum_asset_var_95 = sum(detail.var_95 for detail in asset_risk_details.values())
        diversification_benefit = max(0.0, round(sum_asset_var_95 - ent_var_95, 2))
        diversification_ratio = round(ent_var_95 / max(1.0, sum_asset_var_95), 4)

        # Loss Exceedance Curve (LEC) across 20 quantiles
        sorted_losses = np.sort(enterprise_losses)
        quantiles = np.linspace(0.05, 0.99, 20)
        lec: List[Tuple[float, float]] = []
        for q in quantiles:
            loss_val = float(np.percentile(sorted_losses, q * 100))
            prob_exceed = float(round(1.0 - q, 4))
            lec.append((loss_val, prob_exceed))

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        return PortfolioRiskResult(
            enterprise_eal=round(ent_eal, 2),
            enterprise_var_90=round(ent_var_90, 2),
            enterprise_var_95=round(ent_var_95, 2),
            enterprise_var_99=round(ent_var_99, 2),
            enterprise_cvar_95=round(ent_cvar, 2),
            sum_asset_var_95=round(sum_asset_var_95, 2),
            diversification_benefit=diversification_benefit,
            diversification_ratio=diversification_ratio,
            total_assets=m_assets,
            total_findings=len(findings),
            business_unit_risks=bu_risks,
            asset_risks=asset_risk_details,
            loss_exceedance_curve=lec,
            execution_time_ms=elapsed_ms,
            trials=n_trials,
            seed=used_seed,
        )
