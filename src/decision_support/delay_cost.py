"""
src/decision_support/delay_cost.py - Compounding Delayed Remediation Cost Model.

Models:
- Cumulative excess expected loss over delay window Delta t.
- Non-homogeneous Poisson process breach probability hazard surge.
- Daily loss gradient (marginal cost per additional day of delay).
- Convex compounding remediation penalty (Cost(60d) > 2 * Cost(30d)).
- Dual-currency calculations (USD and INR).
- Executive off-cycle emergency remediation decision rule.
- Authoritative reference function calculate_delay_cost matching PROJECT.md.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Sequence, Union
import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from src.config import USD_TO_INR_RATE
from src.quant.fair_mapper import FairMapper, FairParameters


class DelayPoint(BaseModel):
    """Financial penalty and hazard metrics at a specific day of remediation delay."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    delay_days: int = Field(..., ge=0, description="Elapsed delay in days")
    epss_projected: float = Field(..., ge=0.0, le=1.0, description="Projected EPSS exploit probability")
    excess_expected_loss_usd: float = Field(..., ge=0.0, description="Cumulative excess expected loss (USD)")
    excess_expected_loss_inr: float = Field(..., ge=0.0, description="Cumulative excess expected loss (INR)")
    breach_probability_in_window: float = Field(..., ge=0.0, le=1.0, description="P(Breach >= 1 in window)")
    expected_delay_hazard_usd: float = Field(..., ge=0.0, description="Hazard cost of potential breach (USD)")
    expected_delay_hazard_inr: float = Field(..., ge=0.0, description="Hazard cost of potential breach (INR)")
    total_cost_of_delay_usd: float = Field(..., ge=0.0, description="Total delayed remediation cost (USD)")
    total_cost_of_delay_inr: float = Field(..., ge=0.0, description="Total delayed remediation cost (INR)")
    daily_loss_gradient_usd: float = Field(..., ge=0.0, description="Marginal daily loss gradient d(Cost)/dt (USD)")
    daily_loss_gradient_inr: float = Field(..., ge=0.0, description="Marginal daily loss gradient d(Cost)/dt (INR)")

    @property
    def total_cost_of_delay(self) -> float:
        """Default total cost property."""
        return self.total_cost_of_delay_usd

    @property
    def excess_expected_loss(self) -> float:
        return self.excess_expected_loss_usd

    @property
    def expected_delay_hazard_cost(self) -> float:
        return self.expected_delay_hazard_usd

    @property
    def daily_loss_gradient(self) -> float:
        return self.daily_loss_gradient_usd


class DelayCostResult(BaseModel):
    """Complete assessment of financial exposure incurred by delaying vulnerability remediation."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    finding_id: Optional[str] = Field(default=None, description="Analyzed finding identifier")
    asset_id: Optional[str] = Field(default=None, description="Target asset identifier")
    days_delay: int = Field(..., ge=0, description="Delay horizon in days")
    total_delay_penalty: float = Field(..., ge=0.0, description="Total delay penalty in base currency")
    total_delay_penalty_usd: float = Field(..., ge=0.0, description="Total delay penalty in USD")
    total_delay_penalty_inr: float = Field(..., ge=0.0, description="Total delay penalty in INR")
    breach_probability_surge: float = Field(..., ge=0.0, le=1.0, description="Probability of breach during delay")
    daily_loss_gradient: float = Field(..., ge=0.0, description="Marginal daily cost rate d(Cost)/dt")
    daily_loss_gradient_usd: float = Field(..., ge=0.0, description="Marginal daily cost rate in USD")
    daily_loss_gradient_inr: float = Field(..., ge=0.0, description="Marginal daily cost rate in INR")
    delay_curve: List[DelayPoint] = Field(default_factory=list, description="Day-by-day compounding delay points")
    currency: str = Field(default="USD", description="Base reporting currency")
    expedite_cost_threshold: float = Field(default=10000.0, description="Off-cycle emergency patch threshold (USD)")
    executive_recommendation: str = Field(..., description="Actionable leadership recommendation")
    expedite_warranted: bool = Field(default=False, description="Whether emergency off-cycle remediation is warranted")


class DelayedRemediationModel:
    """
    Mathematical model of compounding cyber risk debt and non-homogeneous Poisson breach hazard
    resulting from postponed vulnerability patching.
    """

    def __init__(
        self,
        base_hazard_accel: float = 0.02,
        expedite_cost_usd: float = 10000.0,
    ) -> None:
        self.hazard_accel = base_hazard_accel
        self.expedite_cost_usd = expedite_cost_usd
        self.mapper = FairMapper()

    def compute_daily_curve(
        self,
        findings: Sequence[Any],
        max_days: int = 90,
        assets: Optional[Any] = None,
        graph: Optional[Any] = None,
    ) -> List[DelayPoint]:
        """
        Computes the daily compounding delay curve from Day 0 to Day max_days.
        """
        if not findings or max_days <= 0:
            return [
                DelayPoint(
                    delay_days=0,
                    epss_projected=0.0,
                    excess_expected_loss_usd=0.0,
                    excess_expected_loss_inr=0.0,
                    breach_probability_in_window=0.0,
                    expected_delay_hazard_usd=0.0,
                    expected_delay_hazard_inr=0.0,
                    total_cost_of_delay_usd=0.0,
                    total_cost_of_delay_inr=0.0,
                    daily_loss_gradient_usd=0.0,
                    daily_loss_gradient_inr=0.0,
                )
            ]

        # Extract asset map if provided
        if isinstance(assets, dict):
            assets_map = assets
        elif isinstance(assets, (list, tuple)):
            assets_map = {getattr(a, "asset_id", str(i)): a for i, a in enumerate(assets)}
        else:
            assets_map = {}

        # 1. Aggregate baseline daily EAL and LEF across findings
        total_baseline_eal = 0.0
        total_mitigated_eal = 0.0
        total_lef = 0.0
        loss_modes: List[float] = []
        epss_list: List[float] = []

        for f in findings:
            asset_id = getattr(f, "asset_id", "")
            asset = assets_map.get(asset_id)
            params = self.mapper.map_finding(f, asset, graph)

            f_eal = params.loss_event_frequency * params.primary_loss_mode
            total_baseline_eal += f_eal
            # If patched, finding loss drops by ~85-95%
            total_mitigated_eal += f_eal * 0.10
            total_lef += params.loss_event_frequency
            loss_modes.append(params.primary_loss_mode)
            epss_list.append(float(getattr(f, "epss_score", 0.1) or 0.1))

        # Fallback minimums for realistic modeling
        if total_baseline_eal <= 0.0:
            total_baseline_eal = 50000.0  # fallback base
            total_mitigated_eal = 5000.0
            total_lef = 0.5
            loss_modes = [100000.0]

        mean_loss_magnitude = float(np.mean(loss_modes)) if loss_modes else 100000.0
        initial_epss = float(np.mean(epss_list)) if epss_list else 0.1

        base_daily_loss = (total_baseline_eal - total_mitigated_eal) / 365.0
        base_daily_lef = total_lef / 365.0

        curve: List[DelayPoint] = []
        cumulative_excess_loss = 0.0
        cumulative_hazard_rate = 0.0
        prev_total_cost = 0.0

        # Day 0: Baseline state (zero delay penalty)
        curve.append(
            DelayPoint(
                delay_days=0,
                epss_projected=round(initial_epss, 4),
                excess_expected_loss_usd=0.0,
                excess_expected_loss_inr=0.0,
                breach_probability_in_window=0.0,
                expected_delay_hazard_usd=0.0,
                expected_delay_hazard_inr=0.0,
                total_cost_of_delay_usd=0.0,
                total_cost_of_delay_inr=0.0,
                daily_loss_gradient_usd=round(base_daily_loss, 2),
                daily_loss_gradient_inr=round(base_daily_loss * USD_TO_INR_RATE, 2),
            )
        )

        for d in range(1, max_days + 1):
            # Dynamic compounding threat drift
            compound_factor = (1.0 + self.hazard_accel) ** d

            # 1. Daily excess loss for day d
            daily_excess = base_daily_loss * compound_factor
            cumulative_excess_loss += daily_excess

            # 2. Non-homogeneous Poisson hazard accumulation
            daily_lef = base_daily_lef * compound_factor
            cumulative_hazard_rate += daily_lef
            # P(Breach >= 1 in [0, d]) = 1 - exp(-cumulative_hazard)
            breach_prob = float(1.0 - math.exp(-min(10.0, cumulative_hazard_rate)))

            # Breach hazard expected loss
            hazard_cost = breach_prob * (mean_loss_magnitude * 0.5)

            # Total cost of delay at day d
            total_delay_usd = cumulative_excess_loss + hazard_cost
            total_delay_inr = total_delay_usd * USD_TO_INR_RATE

            # Discrete daily gradient d(Cost)/dt
            daily_grad_usd = total_delay_usd - prev_total_cost
            daily_grad_inr = daily_grad_usd * USD_TO_INR_RATE
            prev_total_cost = total_delay_usd

            # EPSS drift projection
            epss_proj = min(0.999, initial_epss * (1.0 + 0.015 * d))

            curve.append(
                DelayPoint(
                    delay_days=d,
                    epss_projected=round(epss_proj, 4),
                    excess_expected_loss_usd=round(cumulative_excess_loss, 2),
                    excess_expected_loss_inr=round(cumulative_excess_loss * USD_TO_INR_RATE, 2),
                    breach_probability_in_window=round(breach_prob, 6),
                    expected_delay_hazard_usd=round(hazard_cost, 2),
                    expected_delay_hazard_inr=round(hazard_cost * USD_TO_INR_RATE, 2),
                    total_cost_of_delay_usd=round(total_delay_usd, 2),
                    total_cost_of_delay_inr=round(total_delay_inr, 2),
                    daily_loss_gradient_usd=round(daily_grad_usd, 2),
                    daily_loss_gradient_inr=round(daily_grad_inr, 2),
                )
            )

        return curve

    def evaluate_delay(
        self,
        findings: Sequence[Any],
        days_delay: int = 30,
        assets: Optional[Any] = None,
        graph: Optional[Any] = None,
        currency: str = "USD",
        custom_expedite_cost: Optional[float] = None,
    ) -> DelayCostResult:
        """
        Evaluates delayed remediation cost at specified horizon days_delay.
        """
        days = max(0, int(days_delay))
        curve = self.compute_daily_curve(
            findings=findings,
            max_days=max(days, 90),
            assets=assets,
            graph=graph,
        )

        pt = curve[days] if days < len(curve) else curve[-1]

        # Expedite cost threshold
        expedite_threshold = (
            custom_expedite_cost if custom_expedite_cost is not None else self.expedite_cost_usd
        )
        if currency.upper() == "INR":
            cost_threshold_converted = expedite_threshold * USD_TO_INR_RATE
            penalty_val = pt.total_cost_of_delay_inr
            grad_val = pt.daily_loss_gradient_inr
        else:
            cost_threshold_converted = expedite_threshold
            penalty_val = pt.total_cost_of_delay_usd
            grad_val = pt.daily_loss_gradient_usd

        expedite_warranted = pt.total_cost_of_delay_usd > expedite_threshold

        # Format executive recommendation
        curr_sym = "₹" if currency.upper() == "INR" else "$"
        if days == 0:
            rec = "Remediation scheduled immediately. Zero delayed remediation debt incurred."
        elif expedite_warranted:
            rec = (
                f"Emergency Off-Cycle Remediation Warranted: Postponing remediation by {days} days "
                f"incurs {curr_sym}{penalty_val:,.0f} in compounding cyber risk debt, exceeding "
                f"the {curr_sym}{cost_threshold_converted:,.0f} emergency deployment threshold. "
                f"Breach probability surges to {pt.breach_probability_in_window * 100:.2f}%."
            )
        else:
            rec = (
                f"Standard Maintenance Window Permissible: Delay penalty of {curr_sym}{penalty_val:,.0f} "
                f"over {days} days remains within operational risk tolerance."
            )

        finding_id = getattr(findings[0], "finding_id", None) if findings else None
        asset_id = getattr(findings[0], "asset_id", None) if findings else None

        return DelayCostResult(
            finding_id=finding_id,
            asset_id=asset_id,
            days_delay=days,
            total_delay_penalty=round(penalty_val, 2),
            total_delay_penalty_usd=pt.total_cost_of_delay_usd,
            total_delay_penalty_inr=pt.total_cost_of_delay_inr,
            breach_probability_surge=pt.breach_probability_in_window,
            daily_loss_gradient=round(grad_val, 2),
            daily_loss_gradient_usd=pt.daily_loss_gradient_usd,
            daily_loss_gradient_inr=pt.daily_loss_gradient_inr,
            delay_curve=[curve[d] for d in [0, 7, 14, 30, 60, 90] if d < len(curve)],
            currency=currency,
            expedite_cost_threshold=round(cost_threshold_converted, 2),
            executive_recommendation=rec,
            expedite_warranted=expedite_warranted,
        )


def calculate_delay_cost(
    findings: Sequence[Any],
    days_delay: int = 30,
    assets: Optional[Any] = None,
    graph: Optional[Any] = None,
    currency: str = "USD",
) -> DelayCostResult:
    """
    Authoritative reference function adhering to PROJECT.md interface contract:
    calculate_delay_cost(findings, days_delay: int) -> DelayCostResult
    """
    model = DelayedRemediationModel()
    return model.evaluate_delay(
        findings=findings,
        days_delay=days_delay,
        assets=assets,
        graph=graph,
        currency=currency,
    )
