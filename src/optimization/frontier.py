"""
src/optimization/frontier.py - Pareto Efficiency Frontier & Kneedle Elbow Detection.
"""

import math
from typing import Any, Callable, Dict, List, Optional, Set
import numpy as np

from src.optimization.models import FrontierPoint, FrontierResult, SecurityControl
from src.optimization.rosi import calculate_rosi, convert_currency, calculate_marginal_cbr
from src.config import usd_to_inr, inr_to_usd


def detect_elbow_point(curve: List[FrontierPoint]) -> Optional[FrontierPoint]:
    """
    Kneedle algorithm implementation for finding the optimal knee/elbow point
    on the Pareto efficiency frontier.

    Identifies the point of maximum perpendicular distance from the line
    connecting minimum spend (origin) to maximum spend (full budget).
    This point represents the optimal capital allocation balancing risk reduction and cost.
    """
    if not curve:
        return None
    if len(curve) <= 2:
        curve[-1].is_elbow_point = True
        return curve[-1]

    # Reset all elbow flags
    for p in curve:
        p.is_elbow_point = False

    c_min = curve[0].spend
    c_max = curve[-1].spend
    r_min = curve[0].risk_mitigated
    r_max = curve[-1].risk_mitigated

    delta_c = c_max - c_min
    delta_r = r_max - r_min

    if delta_c <= 1e-6 or delta_r <= 1e-6:
        curve[0].is_elbow_point = True
        return curve[0]

    max_dist = -float("inf")
    best_idx = 0

    # Line connecting (0, 0) and (1, 1) in normalized space: x - y = 0
    # Perpendicular distance is (y - x) / sqrt(2)
    for i, pt in enumerate(curve):
        norm_x = (pt.spend - c_min) / delta_c
        norm_y = (pt.risk_mitigated - r_min) / delta_r
        # For concave frontier, norm_y > norm_x
        dist = (norm_y - norm_x) / math.sqrt(2.0)
        if dist > max_dist:
            max_dist = dist
            best_idx = i

    curve[best_idx].is_elbow_point = True
    return curve[best_idx]


def _filter_upper_concave_envelope(
    raw_points: List[FrontierPoint],
    baseline_eal: float,
    currency: str = "USD",
) -> List[FrontierPoint]:
    """
    Construct the Upper Concave Envelope of the Pareto efficiency frontier.

    Filters flat plateau steps (d_spend == 0), eliminates Pareto-dominated points,
    and applies Andrew's Monotone Chain convex hull algorithm to enforce strictly
    monotonically non-increasing marginal efficiency (dRisk/dCost).

    Every vertex on the resulting envelope represents an actual, optimal knapsack
    allocation that lies on the upper boundary of the feasible investment set.
    """
    if not raw_points:
        return []
    if len(raw_points) <= 2:
        return list(raw_points)

    # 1. Group by spend to filter plateaus:
    # Retain the point with the maximum risk mitigation for each distinct spend.
    spend_map: Dict[float, FrontierPoint] = {}
    for p in raw_points:
        s_key = round(float(p.spend), 2)
        if s_key not in spend_map or p.risk_mitigated > spend_map[s_key].risk_mitigated:
            spend_map[s_key] = p

    # Sort strictly ascending by spend
    sorted_points = sorted(spend_map.values(), key=lambda p: p.spend)

    # 2. Strict Pareto dominance:
    # Increasing spend must strictly increase risk mitigation.
    pareto_points: List[FrontierPoint] = [sorted_points[0]]
    for p in sorted_points[1:]:
        if p.risk_mitigated > pareto_points[-1].risk_mitigated + 1e-6:
            pareto_points.append(p)

    if len(pareto_points) <= 2:
        return pareto_points

    # 3. Upper Concave Envelope via Monotone Chain (Andrew's Upper Hull)
    envelope: List[FrontierPoint] = []
    for p in pareto_points:
        while len(envelope) >= 2:
            p_prev = envelope[-1]
            p_prev2 = envelope[-2]

            ds1 = p_prev.spend - p_prev2.spend
            dr1 = p_prev.risk_mitigated - p_prev2.risk_mitigated
            ds2 = p.spend - p_prev.spend
            dr2 = p.risk_mitigated - p_prev.risk_mitigated

            s1 = dr1 / ds1 if ds1 > 0.0 else 0.0
            s2 = dr2 / ds2 if ds2 > 0.0 else 0.0

            # Slope surge tolerance (allow 1e-6 numerical epsilon)
            if s2 > s1 + 1e-6:
                envelope.pop()
            else:
                break
        envelope.append(p)

    # 4. Recompute marginal cost-benefit ratios along the envelope
    for i in range(1, len(envelope)):
        ds = envelope[i].spend - envelope[i - 1].spend
        dr = envelope[i].risk_mitigated - envelope[i - 1].risk_mitigated
        envelope[i].marginal_cost_benefit_ratio = (dr / ds) if ds > 0 else 0.0

    return envelope


def generate_pareto_frontier(
    controls: List[Any],
    baseline_eal: float,
    max_budget: Optional[float] = None,
    step_count: int = 10,
    currency: str = "USD",
    finding_risks: Optional[Dict[str, float]] = None,
    solver_fn: Optional[Callable[[List[Any], float, float], Dict[str, Any]]] = None,
) -> FrontierResult:
    """
    Generate Pareto Efficiency Frontier by conducting a parametric budget sweep across K steps.

    Filters non-dominated points, enforces diminishing marginal returns (non-increasing dRisk/dCost),
    and determines the Kneedle elbow point.
    """
    if not controls or baseline_eal <= 0.0:
        origin = FrontierPoint(
            budget_step=0.0,
            spend=0.0,
            risk_mitigated=0.0,
            residual_eal=max(0.0, baseline_eal),
            rosi_percentage=0.0,
            is_elbow_point=True,
            selected_control_ids=[],
        )
        return FrontierResult(
            curve=[origin],
            elbow_point=origin,
            max_mitigation_usd=0.0,
            total_candidate_cost_usd=0.0,
        )

    # Extract control costs in requested currency
    def get_cost(c: Any) -> float:
        if isinstance(c, SecurityControl):
            return c.get_cost(currency)
        if hasattr(c, "cost"):
            return float(c.cost)
        if hasattr(c, "cost_usd"):
            return float(c.cost_usd) if currency.upper() == "USD" else usd_to_inr(float(c.cost_usd))
        return 0.0

    def get_effectiveness(c: Any) -> float:
        return getattr(c, "effectiveness", 0.0)

    total_cost = sum(get_cost(c) for c in controls)
    b_limit = max_budget if max_budget is not None and max_budget > 0.0 else total_cost
    if b_limit <= 0.0:
        b_limit = total_cost if total_cost > 0.0 else 1000.0

    k_steps = max(2, step_count)
    budget_grid = np.linspace(0.0, max(b_limit, total_cost), k_steps)

    # Calculate individual baseline mitigations
    n = len(controls)
    mitigations = np.zeros(n, dtype=np.float64)
    for idx, c in enumerate(controls):
        if finding_risks:
            target_ids = getattr(c, "target_finding_ids", [])
            impacted = sum(finding_risks.get(fid, 0.0) for fid in target_ids)
            mitigations[idx] = min(impacted * get_effectiveness(c), baseline_eal * 0.9)
        elif getattr(c, "risk_reduction_usd", 0.0) > 0.0:
            rr = getattr(c, "risk_reduction_usd", 0.0)
            if currency.upper() == "INR":
                rr = usd_to_inr(rr)
            mitigations[idx] = min(rr, baseline_eal * 0.9)
        else:
            c_cost = get_cost(c)
            base_red = (baseline_eal * 0.15) * get_effectiveness(c) * (1.0 + 0.1 * math.log1p(c_cost / 1000.0))
            mitigations[idx] = min(base_red, baseline_eal * 0.4)

    # Precalculate costs and topological sort order once across all budget steps
    from src.optimization.solver import get_topological_order

    costs_arr = np.array([get_cost(c) for c in controls], dtype=np.float64)
    sorted_indices = get_topological_order(controls, costs_arr, mitigations)

    # Internal quick solve if external solver not passed
    def default_quick_solve(ctrls: List[Any], b: float) -> Dict[str, Any]:
        if b <= 0.0:
            return {"spend": 0.0, "mitigated": 0.0, "selected_ids": []}
        allocated = 0.0
        mitigated = 0.0
        sel_ids: List[str] = []
        sel_set: Set[str] = set()

        for i in sorted_indices:
            c = ctrls[i]
            cost_c = costs_arr[i]
            cid = getattr(c, "control_id", str(i))
            conflicts = getattr(c, "conflicts", [])
            prereqs = getattr(c, "prerequisites", [])
            if allocated + cost_c <= b:
                if not any(conf in sel_set for conf in conflicts):
                    if all(p in sel_set for p in prereqs):
                        sel_ids.append(cid)
                        sel_set.add(cid)
                        allocated += cost_c
                        mitigated += mitigations[i]
        return {"spend": allocated, "mitigated": mitigated, "selected_ids": sel_ids}

    raw_points: List[FrontierPoint] = []

    for step_val in budget_grid:
        if step_val <= 1e-6:
            res = {"spend": 0.0, "mitigated": 0.0, "selected_ids": []}
        elif solver_fn is not None:
            res = solver_fn(controls, step_val, baseline_eal)
        else:
            res = default_quick_solve(controls, step_val)

        cur_spend = float(res["spend"])
        cur_mitigated = float(res["mitigated"])

        res_eal = max(0.0, baseline_eal - cur_mitigated)
        p_rosi = calculate_rosi(cur_mitigated, cur_spend)

        # Currency normalized fields
        if currency.upper() == "INR":
            s_inr = cur_spend
            s_usd = inr_to_usd(cur_spend)
            r_inr = cur_mitigated
            r_usd = inr_to_usd(cur_mitigated)
            res_usd = inr_to_usd(res_eal)
            res_inr = res_eal
        else:
            s_usd = cur_spend
            s_inr = usd_to_inr(cur_spend)
            r_usd = cur_mitigated
            r_inr = usd_to_inr(cur_mitigated)
            res_usd = res_eal
            res_inr = usd_to_inr(res_eal)

        pt = FrontierPoint(
            budget_step=float(step_val),
            budget_spend_usd=s_usd,
            budget_spend_inr=s_inr,
            risk_mitigated_usd=r_usd,
            risk_mitigated_inr=r_inr,
            residual_eal_usd=res_usd,
            residual_eal_inr=res_inr,
            portfolio_rosi=p_rosi,
            marginal_cost_benefit_ratio=0.0,
            is_elbow_point=False,
            spend=cur_spend,
            risk_mitigated=cur_mitigated,
            residual_eal=res_eal,
            rosi_percentage=p_rosi,
            selected_control_ids=list(res.get("selected_ids", [])),
        )
        raw_points.append(pt)

    # Filter plateaus, enforce strict Pareto dominance, and construct Upper Concave Envelope
    envelope = _filter_upper_concave_envelope(raw_points, baseline_eal=baseline_eal, currency=currency)

    # Detect Kneedle elbow point on the filtered concave envelope
    elbow = detect_elbow_point(envelope)

    max_mit_usd = envelope[-1].risk_mitigated_usd if envelope else 0.0
    max_mit_inr = envelope[-1].risk_mitigated_inr if envelope else 0.0
    tot_cost_usd = total_cost if currency.upper() == "USD" else inr_to_usd(total_cost)
    tot_cost_inr = total_cost if currency.upper() == "INR" else usd_to_inr(total_cost)

    return FrontierResult(
        curve=envelope,
        elbow_point=elbow,
        max_mitigation_usd=max_mit_usd,
        max_mitigation_inr=max_mit_inr,
        total_candidate_cost_usd=tot_cost_usd,
        total_candidate_cost_inr=tot_cost_inr,
    )
