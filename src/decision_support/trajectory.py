"""
src/decision_support/trajectory.py - Predictive Threat Scoring & 30/60/90-Day Risk Trajectory Forecasting.

Models:
- Dynamic EPSS velocity (dEPSS/dt) and acceleration (d^2EPSS/dt^2).
- CISA KEV weaponization step-penalties and campaign multipliers.
- Dynamic coupling between EPSS trajectory and FAIR Threat Event Frequency (TEF).
- Multi-scenario 30/60/90-day time-series forecasting (Baseline, Pessimistic, Optimistic/Mitigated).
- Forward-projected EAL, VaR 90/95/99 percentiles, and confidence intervals across horizons.
"""

from __future__ import annotations

from enum import Enum
import math
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from src.config import USD_TO_INR_RATE
from src.quant.monte_carlo import MonteCarloEngine, SimulationResult


class TrajectoryScenario(str, Enum):
    """Forecasting scenario modes."""
    BASELINE = "BASELINE"          # Status quo: historical EPSS drift & normal patching
    PESSIMISTIC = "PESSIMISTIC"    # Adversarial surge: zero patching, KEV escalation, accelerating exploits
    OPTIMISTIC = "OPTIMISTIC"      # Mitigated: proactive patching & control deployment


class TrajectoryPoint(BaseModel):
    """Quantitative risk metrics at a specific future forecast horizon."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    days: int = Field(..., ge=0, description="Forecast horizon in days (e.g. 0, 30, 60, 90)")
    eal: float = Field(..., ge=0.0, description="Expected Annual Loss at horizon (base currency)")
    var_90: float = Field(..., ge=0.0, description="Value-at-Risk 90th percentile")
    var_95: float = Field(..., ge=0.0, description="Value-at-Risk 95th percentile")
    var_99: float = Field(..., ge=0.0, description="Value-at-Risk 99th percentile")
    eal_lower_ci: float = Field(..., ge=0.0, description="5th percentile confidence bound")
    eal_upper_ci: float = Field(..., ge=0.0, description="95th percentile confidence bound")
    epss_mean: float = Field(..., ge=0.0, le=1.0, description="Mean projected EPSS exploit probability")
    active_finding_count: int = Field(default=0, ge=0, description="Projected active vulnerability count")
    eal_inr: Optional[float] = Field(default=None, description="EAL in INR")
    var_95_inr: Optional[float] = Field(default=None, description="VaR 95 in INR")


class TrajectoryForecast(BaseModel):
    """Complete multi-scenario 30/60/90-day threat and risk trajectory forecast."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    baseline_trajectory: List[TrajectoryPoint] = Field(..., description="Status quo forecast (t=0, 30, 60, 90)")
    pessimistic_trajectory: List[TrajectoryPoint] = Field(..., description="Adversarial surge forecast")
    optimistic_trajectory: List[TrajectoryPoint] = Field(..., description="Mitigated investment forecast")
    epss_velocity_mean: float = Field(default=0.0, description="Average EPSS daily rate of change (dEPSS/dt)")
    epss_acceleration_mean: float = Field(default=0.0, description="Average EPSS daily acceleration (d^2EPSS/dt^2)")
    currency: str = Field(default="USD", description="Base reporting currency")
    summary: str = Field(default="", description="Executive narrative summary of trajectory")


class ThreatTrajectoryForecaster:
    """
    Predictive threat modeling engine implementing EPSS velocity/acceleration dynamics
    and forward-projected Monte Carlo risk trajectory forecasting.
    """

    def __init__(
        self,
        c1: float = 1.0,
        c2: float = 0.5,
        omega_kev: float = 0.05,
        gamma_ext: float = 1.0,
        monte_carlo_trials: int = 2000,
    ) -> None:
        self.c1 = c1
        self.c2 = c2
        self.omega_kev = omega_kev
        self.gamma_ext = gamma_ext
        self.trials = max(200, monte_carlo_trials)
        self.mc_engine = MonteCarloEngine(iterations=self.trials)

    @staticmethod
    def calculate_epss_velocity(
        epss_current: float, epss_previous: float, delta_t_days: float = 30.0
    ) -> float:
        """
        Calculates discrete first derivative of EPSS:
        alpha = (EPSS(t) - EPSS(t - delta_t)) / delta_t
        """
        dt = max(1.0, float(delta_t_days))
        return float((epss_current - epss_previous) / dt)

    @staticmethod
    def calculate_epss_acceleration(
        vel_current: float, vel_previous: float, delta_t_days: float = 30.0
    ) -> float:
        """
        Calculates discrete second derivative of EPSS:
        beta = (alpha(t) - alpha(t - delta_t)) / delta_t
        """
        dt = max(1.0, float(delta_t_days))
        return float((vel_current - vel_previous) / dt)

    def project_epss(
        self,
        epss_current: float,
        velocity: float = 0.0,
        acceleration: float = 0.0,
        cisa_kev: bool = False,
        tau_days: int = 30,
    ) -> float:
        """
        Projects EPSS score at horizon tau days using generalized logistic growth:
        E_v(t + tau) = min(1.0, 1 / (1 + ((1 - E0)/E0) * exp(-k_v * tau)))
        """
        tau = max(0, int(tau_days))
        if tau == 0:
            return float(max(0.0, min(1.0, epss_current)))

        e0 = max(0.001, min(0.999, float(epss_current)))
        kev_term = self.omega_kev if cisa_kev else 0.0
        # Campaign momentum growth rate per day
        kv = max(0.0, self.c1 * velocity + self.c2 * acceleration + kev_term)

        if kv > 0.0:
            odds = (1.0 - e0) / e0
            # Scale tau to months for numerical stability if tau is in days
            scaled_exp = -kv * (tau / 30.0)
            clamped_exp = max(-20.0, min(20.0, scaled_exp))
            projected = 1.0 / (1.0 + odds * math.exp(clamped_exp))
        else:
            # Linear drift fallback if no positive acceleration
            projected = e0 + velocity * tau

        return float(max(0.001, min(0.999, projected)))

    def project_finding(
        self,
        finding: Any,
        tau_days: int,
        scenario: TrajectoryScenario = TrajectoryScenario.BASELINE,
        velocity: float = 0.001,
        acceleration: float = 0.0001,
    ) -> Any:
        """
        Projects a finding's EPSS score and Threat Event Frequency (TEF) forward to horizon tau_days.
        Returns a projected clone of the finding.
        """
        current_epss = float(getattr(finding, "epss_score", 0.1) or 0.1)
        current_tef = float(getattr(finding, "threat_event_frequency", 1.0) or 1.0)
        cisa_kev = bool(getattr(finding, "cisa_kev", False))
        current_rs = float(getattr(finding, "resistance_strength", 0.5) or 0.5)

        # Apply scenario-specific modifications to velocity, acceleration, and KEV
        if scenario == TrajectoryScenario.PESSIMISTIC:
            proj_vel = max(velocity, 0.003) * 1.5
            proj_acc = max(acceleration, 0.0005) * 2.0
            proj_kev = True
            campaign_mult = 1.25
        elif scenario == TrajectoryScenario.OPTIMISTIC:
            proj_vel = -abs(velocity) if velocity != 0 else -0.002
            proj_acc = -abs(acceleration) if acceleration != 0 else -0.0002
            proj_kev = cisa_kev
            campaign_mult = 0.8
        else:
            proj_vel = velocity
            proj_acc = acceleration
            proj_kev = cisa_kev
            campaign_mult = 1.0

        projected_epss = self.project_epss(
            current_epss, proj_vel, proj_acc, proj_kev, tau_days
        )

        # Dynamic TEF coupling: TEF(t + tau) = TEF(t) * [1 + gamma * ((E_tau - E_0) / (E_0 + eps))] * M_camp
        if tau_days == 0:
            projected_tef = current_tef
        else:
            epss_delta_ratio = (projected_epss - current_epss) / max(0.01, current_epss)
            tef_factor = max(0.1, (1.0 + self.gamma_ext * epss_delta_ratio) * campaign_mult)
            projected_tef = current_tef * tef_factor

        # Resistance strength shifts in optimistic scenario due to proactive hardening
        if scenario == TrajectoryScenario.OPTIMISTIC and tau_days > 0:
            hardening_gain = min(0.35, 0.10 * (tau_days / 30.0))
            projected_rs = min(0.95, current_rs + (1.0 - current_rs) * hardening_gain)
        else:
            projected_rs = current_rs

        # Create shallow clone or dictionary-like update
        # Check if finding is a Pydantic model (NormalizedFinding, etc.)
        if hasattr(finding, "model_copy"):
            return finding.model_copy(update={
                "epss_score": round(projected_epss, 4),
                "threat_event_frequency": round(projected_tef, 4),
                "cisa_kev": proj_kev,
                "resistance_strength": round(projected_rs, 4),
            })
        elif hasattr(finding, "__dict__"):
            # Dataclass or custom object: create a clone
            from copy import copy
            cloned = copy(finding)
            setattr(cloned, "epss_score", round(projected_epss, 4))
            setattr(cloned, "threat_event_frequency", round(projected_tef, 4))
            setattr(cloned, "cisa_kev", proj_kev)
            setattr(cloned, "resistance_strength", round(projected_rs, 4))
            return cloned
        else:
            return finding

    def forecast_trajectory(
        self,
        findings: Sequence[Any],
        assets: Optional[Any] = None,
        horizons: Sequence[int] = (0, 30, 60, 90),
        seed: int = 42,
        graph: Optional[Any] = None,
        currency: str = "USD",
        default_velocity: float = 0.002,
        default_acceleration: float = 0.0001,
    ) -> TrajectoryForecast:
        """
        Executes multi-scenario forward-projected risk simulations at t=0, 30, 60, 90 days.
        Maintains Common Random Numbers across trajectory horizons for clean monotonicity.
        """
        if not findings:
            empty_pts = [
                TrajectoryPoint(
                    days=d,
                    eal=0.0,
                    var_90=0.0,
                    var_95=0.0,
                    var_99=0.0,
                    eal_lower_ci=0.0,
                    eal_upper_ci=0.0,
                    epss_mean=0.0,
                    active_finding_count=0,
                    eal_inr=0.0,
                    var_95_inr=0.0,
                )
                for d in horizons
            ]
            return TrajectoryForecast(
                baseline_trajectory=empty_pts,
                pessimistic_trajectory=empty_pts,
                optimistic_trajectory=empty_pts,
                epss_velocity_mean=0.0,
                epss_acceleration_mean=0.0,
                currency=currency,
                summary="No active findings. Enterprise risk trajectory is baseline 0.0.",
            )

        scenarios = [
            TrajectoryScenario.BASELINE,
            TrajectoryScenario.PESSIMISTIC,
            TrajectoryScenario.OPTIMISTIC,
        ]
        results_by_scenario: Dict[TrajectoryScenario, List[TrajectoryPoint]] = {
            s: [] for s in scenarios
        }

        # Calculate average initial EPSS metrics
        initial_epss = [float(getattr(f, "epss_score", 0.1) or 0.1) for f in findings]
        mean_initial_epss = float(np.mean(initial_epss)) if initial_epss else 0.1

        for scenario in scenarios:
            for tau in horizons:
                # Project all findings forward to horizon tau under given scenario
                projected_findings = [
                    self.project_finding(
                        f,
                        tau_days=tau,
                        scenario=scenario,
                        velocity=default_velocity,
                        acceleration=default_acceleration,
                    )
                    for f in findings
                ]

                # Run Monte Carlo simulation with Common Random Numbers (identical seed)
                sim_res: SimulationResult = self.mc_engine.simulate(
                    findings=projected_findings,
                    assets=assets,
                    seed_override=seed,
                    graph=graph,
                )

                # Parametric 90% confidence interval for EAL: [EAL_5%, EAL_95%]
                losses = sim_res.loss_distribution
                if losses and len(losses) > 0:
                    eal_low = float(np.percentile(losses, 5))
                    eal_high = float(np.percentile(losses, 95))
                else:
                    eal_low = sim_res.eal * 0.8
                    eal_high = sim_res.eal * 1.2

                proj_epss_vals = [
                    float(getattr(f, "epss_score", 0.1) or 0.1) for f in projected_findings
                ]
                mean_proj_epss = float(np.mean(proj_epss_vals)) if proj_epss_vals else mean_initial_epss

                # Currency conversion to INR if requested or provided as secondary field
                eal_val = sim_res.eal
                var_95_val = sim_res.var_95
                if currency.upper() == "INR":
                    eal_inr = eal_val
                    var_95_inr = var_95_val
                else:
                    eal_inr = eal_val * USD_TO_INR_RATE
                    var_95_inr = var_95_val * USD_TO_INR_RATE

                pt = TrajectoryPoint(
                    days=tau,
                    eal=round(eal_val, 2),
                    var_90=round(sim_res.var_90, 2),
                    var_95=round(sim_res.var_95, 2),
                    var_99=round(sim_res.var_99, 2),
                    eal_lower_ci=round(eal_low, 2),
                    eal_upper_ci=round(eal_high, 2),
                    epss_mean=round(mean_proj_epss, 4),
                    active_finding_count=len(projected_findings),
                    eal_inr=round(eal_inr, 2),
                    var_95_inr=round(var_95_inr, 2),
                )
                results_by_scenario[scenario].append(pt)

        # Generate concise summary narrative
        base_t0 = results_by_scenario[TrajectoryScenario.BASELINE][0].eal
        base_t90 = results_by_scenario[TrajectoryScenario.BASELINE][-1].eal
        pess_t90 = results_by_scenario[TrajectoryScenario.PESSIMISTIC][-1].eal
        opt_t90 = results_by_scenario[TrajectoryScenario.OPTIMISTIC][-1].eal

        growth_pct = ((base_t90 - base_t0) / max(1.0, base_t0)) * 100.0
        summary_text = (
            f"Over the next 90 days, baseline Expected Annual Loss is projected to "
            f"{'increase' if growth_pct >= 0 else 'decrease'} by {abs(growth_pct):.1f}% "
            f"(from {currency} {base_t0:,.0f} to {currency} {base_t90:,.0f}). "
            f"Under an adversarial surge scenario, 90-day exposure escalates to {currency} {pess_t90:,.0f}, "
            f"whereas proactive mitigation would constrain risk to {currency} {opt_t90:,.0f}."
        )

        return TrajectoryForecast(
            baseline_trajectory=results_by_scenario[TrajectoryScenario.BASELINE],
            pessimistic_trajectory=results_by_scenario[TrajectoryScenario.PESSIMISTIC],
            optimistic_trajectory=results_by_scenario[TrajectoryScenario.OPTIMISTIC],
            epss_velocity_mean=default_velocity,
            epss_acceleration_mean=default_acceleration,
            currency=currency,
            summary=summary_text,
        )
