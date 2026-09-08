"""
src/decision_support/what_if.py - Interactive What-If Counterfactual Scenario Simulation Engine.

Provides:
- Common Random Numbers (CRN) using identical paired random streams across baseline and counterfactual runs.
- Concrete monetary deltas: delta_eal = baseline_eal - counterfactual_eal, delta_var_95, delta_var_90/99.
- Risk reduction percentage computation and Net Financial Benefit / ROSI %.
- Counterfactual scenario mutators: applying controls (reducing TEF, boosting RS), patching CVEs,
  or removing controls (degradation analysis).
- Reference interface function run_counterfactual_simulation.
"""

from __future__ import annotations

from copy import copy
from typing import Any, Dict, List, Optional, Sequence, Union
import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from src.config import USD_TO_INR_RATE
from src.quant.monte_carlo import MonteCarloEngine, SimulationResult


class WhatIfRequest(BaseModel):
    """Parameters for executing an interactive What-If scenario simulation."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    baseline_seed: int = Field(default=42, description="Common Random Number seed for paired simulations")
    cves_to_patch: List[str] = Field(default_factory=list, description="CVE IDs to eliminate (e.g. CVE-2023-34362)")
    finding_ids_to_remove: List[str] = Field(default_factory=list, description="Finding IDs to eliminate")
    controls_to_add: List[str] = Field(default_factory=list, description="Control names/IDs to apply (e.g. MFA, EDR)")
    controls_to_remove: List[str] = Field(default_factory=list, description="Existing controls to disable (degradation)")
    target_asset_ids: List[str] = Field(default_factory=list, description="Asset IDs in scope (empty = all assets)")
    control_efficacy: float = Field(default=0.75, ge=0.0, le=1.0, description="Efficacy multiplier of added controls")
    control_cost: float = Field(default=0.0, ge=0.0, description="Cost of the intervention in specified currency")
    currency: str = Field(default="USD", description="Currency unit (USD or INR)")
    trials: int = Field(default=5000, ge=100, description="Monte Carlo simulation iterations")


class WhatIfResult(BaseModel):
    """Result of What-If counterfactual scenario comparison."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    baseline_eal: float = Field(..., description="Baseline Expected Annual Loss")
    simulated_eal: float = Field(..., description="Counterfactual Simulated Expected Annual Loss")
    delta_eal: float = Field(..., description="EAL reduction: Baseline EAL - Simulated EAL")
    risk_reduction_pct: float = Field(..., description="Percentage reduction in Expected Annual Loss")

    baseline_var_90: float = Field(default=0.0, description="Baseline VaR 90th percentile")
    simulated_var_90: float = Field(default=0.0, description="Counterfactual VaR 90th percentile")
    delta_var_90: float = Field(default=0.0, description="Baseline VaR 90 - Simulated VaR 90")

    baseline_var_95: float = Field(..., description="Baseline VaR 95th percentile")
    simulated_var_95: float = Field(..., description="Counterfactual VaR 95th percentile")
    delta_var_95: float = Field(..., description="Baseline VaR 95 - Simulated VaR 95")

    baseline_var_99: float = Field(default=0.0, description="Baseline VaR 99th percentile")
    simulated_var_99: float = Field(default=0.0, description="Counterfactual VaR 99th percentile")
    delta_var_99: float = Field(default=0.0, description="Baseline VaR 99 - Simulated VaR 99")

    intervention_cost: float = Field(default=0.0, ge=0.0, description="Intervention cost")
    net_financial_benefit: float = Field(default=0.0, description="Delta EAL - Intervention Cost")
    rosi_percent: Optional[float] = Field(default=None, description="Return on Security Investment %")

    currency: str = Field(default="USD", description="Currency unit")
    actionable_summary: str = Field(default="", description="Plain-language executive summary")
    baseline_findings_count: int = Field(default=0, description="Number of baseline findings")
    counterfactual_findings_count: int = Field(default=0, description="Number of counterfactual findings")
    used_seed: int = Field(default=42, description="CRN seed used for both runs")

    @property
    def mitigated_eal(self) -> float:
        """Alias for simulated_eal matching interface contracts."""
        return self.simulated_eal

    @property
    def counterfactual_eal(self) -> float:
        """Alias for simulated_eal."""
        return self.simulated_eal

    @property
    def delta_eal_percent(self) -> float:
        """Alias for risk_reduction_pct."""
        return self.risk_reduction_pct


class WhatIfEngine:
    """
    Counterfactual scenario simulation engine utilizing Common Random Numbers (CRN)
    for high-precision variance-reduced risk delta calculations.
    """

    def __init__(self, iterations: int = 5000, seed: int = 42) -> None:
        self.iterations = max(100, iterations)
        self.seed = seed
        self.mc_engine = MonteCarloEngine(iterations=self.iterations)

    def mutate_findings(
        self,
        findings: Sequence[Any],
        cves_to_patch: Sequence[str] = (),
        finding_ids_to_remove: Sequence[str] = (),
        controls_to_add: Sequence[str] = (),
        controls_to_remove: Sequence[str] = (),
        target_asset_ids: Sequence[str] = (),
        control_efficacy: float = 0.75,
    ) -> List[Any]:
        """
        Creates a counterfactual finding portfolio by applying or removing controls,
        patching CVEs, or adjusting parameters.
        """
        patch_cves_upper = {c.strip().upper() for c in cves_to_patch}
        remove_ids = set(finding_ids_to_remove)
        target_assets = set(target_asset_ids)

        counterfactual: List[Any] = []

        for f in findings:
            fid = getattr(f, "finding_id", "")
            cve = getattr(f, "cve_id", "")
            title = getattr(f, "title", "")
            asset_id = getattr(f, "asset_id", "")

            # 1. Elimination check: is this finding patched or removed?
            if fid in remove_ids:
                continue
            if cve and cve.upper() in patch_cves_upper:
                continue
            if any(p in title.upper() for p in patch_cves_upper if p):
                continue

            # Check if this finding's asset is in scope (if scope specified)
            in_scope = (not target_assets) or (asset_id in target_assets)

            # 2. Control additions (risk reductions)
            tef = float(getattr(f, "threat_event_frequency", 1.0) or 1.0)
            rs = float(getattr(f, "resistance_strength", 0.5) or 0.5)

            if in_scope and controls_to_add:
                for c in controls_to_add:
                    c_upper = c.upper()
                    if "MFA" in c_upper or "IAM" in c_upper:
                        # IAM hardening boosts resistance strength
                        rs = min(0.98, rs + (1.0 - rs) * control_efficacy)
                    elif "EDR" in c_upper or "ANTIVIRUS" in c_upper:
                        # EDR boosts resistance strength and suppresses event frequency
                        rs = min(0.95, rs + (1.0 - rs) * control_efficacy)
                        tef = max(0.01, tef * (1.0 - control_efficacy * 0.5))
                    elif "WAF" in c_upper or "FIREWALL" in c_upper or "PERIMETER" in c_upper:
                        # Perimeter filtering cuts threat contact frequency
                        tef = max(0.01, tef * (1.0 - control_efficacy))
                    elif "PATCH" in c_upper or "VAP" in c_upper:
                        tef = max(0.01, tef * (1.0 - control_efficacy * 0.8))
                        rs = min(0.95, rs + 0.3)
                    else:
                        # Generic control
                        tef = max(0.01, tef * (1.0 - control_efficacy * 0.5))
                        rs = min(0.95, rs + (1.0 - rs) * (control_efficacy * 0.5))

            # 3. Control removals (degradation analysis / risk surge)
            if in_scope and controls_to_remove:
                for c in controls_to_remove:
                    c_upper = c.upper()
                    if "EDR" in c_upper or "AGENT" in c_upper:
                        rs = max(0.05, rs * 0.3)
                        tef = tef * 2.0
                    elif "MFA" in c_upper or "IAM" in c_upper:
                        rs = max(0.05, rs * 0.2)
                        tef = tef * 2.5
                    elif "WAF" in c_upper or "FIREWALL" in c_upper:
                        tef = tef * 3.0
                    else:
                        rs = max(0.05, rs * 0.5)
                        tef = tef * 1.5

            # Clone finding with updated attributes
            if hasattr(f, "model_copy"):
                counterfactual.append(f.model_copy(update={
                    "threat_event_frequency": round(tef, 4),
                    "resistance_strength": round(rs, 4),
                }))
            elif hasattr(f, "__dict__"):
                cloned = copy(f)
                setattr(cloned, "threat_event_frequency", round(tef, 4))
                setattr(cloned, "resistance_strength", round(rs, 4))
                counterfactual.append(cloned)
            else:
                counterfactual.append(f)

        return counterfactual

    def simulate(
        self,
        baseline_findings: Sequence[Any],
        request: WhatIfRequest,
        assets: Optional[Any] = None,
        graph: Optional[Any] = None,
    ) -> WhatIfResult:
        """
        Executes a paired baseline vs counterfactual simulation using Common Random Numbers (CRN).
        """
        counterfactual_findings = self.mutate_findings(
            findings=baseline_findings,
            cves_to_patch=request.cves_to_patch,
            finding_ids_to_remove=request.finding_ids_to_remove,
            controls_to_add=request.controls_to_add,
            controls_to_remove=request.controls_to_remove,
            target_asset_ids=request.target_asset_ids,
            control_efficacy=request.control_efficacy,
        )

        return self.simulate_pair(
            baseline_findings=baseline_findings,
            counterfactual_findings=counterfactual_findings,
            assets=assets,
            seed=request.baseline_seed,
            graph=graph,
            trials=request.trials,
            cost=request.control_cost,
            currency=request.currency,
        )

    def simulate_pair(
        self,
        baseline_findings: Sequence[Any],
        counterfactual_findings: Sequence[Any],
        assets: Optional[Any] = None,
        seed: int = 42,
        graph: Optional[Any] = None,
        trials: Optional[int] = None,
        cost: float = 0.0,
        currency: str = "USD",
    ) -> WhatIfResult:
        """
        Simulates two finding configurations with the exact same seed (CRN),
        computing concrete monetary deltas and financial metrics.
        """
        n_trials = trials or self.iterations
        engine = MonteCarloEngine(iterations=n_trials)

        # Run Baseline
        base_res = engine.simulate(
            findings=list(baseline_findings),
            assets=assets,
            seed_override=seed,
            graph=graph,
        )

        # Run Counterfactual with identical seed (Common Random Numbers)
        cf_res = engine.simulate(
            findings=list(counterfactual_findings),
            assets=assets,
            seed_override=seed,
            graph=graph,
        )

        delta_eal = float(base_res.eal - cf_res.eal)
        delta_var_90 = float(base_res.var_90 - cf_res.var_90)
        delta_var_95 = float(base_res.var_95 - cf_res.var_95)
        delta_var_99 = float(base_res.var_99 - cf_res.var_99)

        if base_res.eal > 0.0:
            pct_reduction = (delta_eal / base_res.eal) * 100.0
        else:
            pct_reduction = 0.0

        net_benefit = delta_eal - cost
        if cost > 0.0:
            rosi = ((delta_eal - cost) / cost) * 100.0
        else:
            rosi = None

        # Build actionable plain-language summary
        curr_sym = "₹" if currency.upper() == "INR" else "$"
        if delta_eal > 0:
            summary = (
                f"Proposed intervention reduces Expected Annual Loss by {curr_sym}{delta_eal:,.0f} "
                f"({pct_reduction:.1f}% risk reduction) and shrinks 95th percentile Value-at-Risk "
                f"by {curr_sym}{delta_var_95:,.0f}."
            )
            if rosi is not None:
                summary += f" Yields a Return on Security Investment (ROSI) of {rosi:.1f}%."
        elif delta_eal < 0:
            summary = (
                f"Degradation scenario escalates Expected Annual Loss by {curr_sym}{abs(delta_eal):,.0f} "
                f"(+{abs(pct_reduction):.1f}% risk surge) and increases tail VaR 95 by {curr_sym}{abs(delta_var_95):,.0f}."
            )
        else:
            summary = "No change in Expected Annual Loss detected for this scenario."

        return WhatIfResult(
            baseline_eal=round(base_res.eal, 2),
            simulated_eal=round(cf_res.eal, 2),
            delta_eal=round(delta_eal, 2),
            risk_reduction_pct=round(pct_reduction, 2),
            baseline_var_90=round(base_res.var_90, 2),
            simulated_var_90=round(cf_res.var_90, 2),
            delta_var_90=round(delta_var_90, 2),
            baseline_var_95=round(base_res.var_95, 2),
            simulated_var_95=round(cf_res.var_95, 2),
            delta_var_95=round(delta_var_95, 2),
            baseline_var_99=round(base_res.var_99, 2),
            simulated_var_99=round(cf_res.var_99, 2),
            delta_var_99=round(delta_var_99, 2),
            intervention_cost=round(cost, 2),
            net_financial_benefit=round(net_benefit, 2),
            rosi_percent=round(rosi, 2) if rosi is not None else None,
            currency=currency,
            actionable_summary=summary,
            baseline_findings_count=len(baseline_findings),
            counterfactual_findings_count=len(counterfactual_findings),
            used_seed=seed,
        )


def run_counterfactual_simulation(
    baseline_findings: Sequence[Any],
    mitigated_findings: Optional[Sequence[Any]] = None,
    assets: Optional[Any] = None,
    seed: int = 42,
    graph: Optional[Any] = None,
    trials: int = 5000,
    cost: float = 0.0,
    currency: str = "USD",
) -> WhatIfResult:
    """
    Authoritative reference function adhering to PROJECT.md interface contract:
    run_counterfactual_simulation(baseline_findings, mitigated_findings, seed=42) -> WhatIfResult
    """
    engine = WhatIfEngine(iterations=trials, seed=seed)
    if mitigated_findings is None:
        # Default scenario: mitigate highest CVSS vulnerability
        if baseline_findings:
            highest = max(baseline_findings, key=lambda f: getattr(f, "cvss_score", 0.0))
            mitigated_findings = [f for f in baseline_findings if f != highest]
        else:
            mitigated_findings = []

    return engine.simulate_pair(
        baseline_findings=baseline_findings,
        counterfactual_findings=mitigated_findings,
        assets=assets,
        seed=seed,
        graph=graph,
        trials=trials,
        cost=cost,
        currency=currency,
    )
