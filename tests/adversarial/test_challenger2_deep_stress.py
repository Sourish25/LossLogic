"""
tests/adversarial/test_challenger2_deep_stress.py - Deep Adversarial Stress & Invariant Suite for Milestone 4 Remediation.

Empirical verification harness authored by Challenger 2:
1. Extreme scaling (50, 100, 200 controls) with complex DAGs, cliques, and mandatory sets.
2. Mathematical invariants (allocated_spend <= budget, ROSI %, NFB, exchange rate invariance).
3. Pareto efficiency frontier upper concave envelope monotonicity (diminishing returns under all conditions).
4. Boundary edge cases (empty control list, all controls exceed budget, zero budget, negative budget,
   single control, all mandatory but insufficient budget, mandatory conflict, missing prereq).
"""

import math
import random
import time
from typing import List, Set
import numpy as np
import pytest

from src.config import USD_TO_INR_RATE, inr_to_usd, usd_to_inr
from src.optimization.models import (
    OptimizationRequest,
    OptimizationResult,
    SecurityControl,
    FrontierPoint,
    FrontierResult,
)
from src.optimization.solver import OptimizationSolver
from src.optimization.frontier import generate_pareto_frontier, detect_elbow_point
from src.optimization.rosi import (
    calculate_marginal_cbr,
    calculate_net_financial_benefit,
    calculate_rosi,
)


def _build_complex_portfolio(
    n: int,
    dep_prob: float = 0.15,
    conflict_prob: float = 0.08,
    mandatory_ratio: float = 0.10,
    seed: int = 42,
    currency: str = "USD",
) -> List[SecurityControl]:
    """Generate a highly constrained portfolio for stress-testing."""
    rng = random.Random(seed)
    controls = []
    for i in range(n):
        cid = f"C_{i:04d}"
        cost = round(rng.uniform(100.0, 25000.0), 2)
        eff = round(rng.uniform(0.05, 0.95), 2)
        rr = round(rng.uniform(500.0, 100000.0), 2)

        # Preceding dependencies (DAG)
        prereqs = []
        if i > 0 and rng.random() < dep_prob:
            k_deps = min(i, rng.randint(1, 3))
            prereqs = [f"C_{p:04d}" for p in rng.sample(range(i), k_deps)]

        # Conflicts
        conflicts = []
        if i > 0 and rng.random() < conflict_prob:
            k_conf = min(i, rng.randint(1, 2))
            conflicts = [f"C_{c:04d}" for c in rng.sample(range(i), k_conf)]

        is_mand = (rng.random() < mandatory_ratio)

        controls.append(
            SecurityControl(
                control_id=cid,
                name=f"Control {cid}",
                category=f"Cat_{i % 5}",
                cost_usd=cost if currency == "USD" else inr_to_usd(cost),
                cost_inr=usd_to_inr(cost) if currency == "USD" else cost,
                cost=cost,
                effectiveness=eff,
                risk_reduction_usd=rr if currency == "USD" else inr_to_usd(rr),
                risk_reduction_inr=usd_to_inr(rr) if currency == "USD" else rr,
                prerequisites=prereqs,
                conflicts=conflicts,
                is_mandatory=is_mand,
            )
        )
    return controls


class TestExtremePortfolioScaling:
    """Stress-test 50, 100, and 200 controls with complex constraints."""

    @pytest.mark.parametrize("n_controls", [50, 100, 200])
    def test_extreme_portfolio_sizes_and_constraint_satisfaction(self, n_controls: int):
        """Verify solver handles 50, 100, 200 controls without hanging or violating constraints."""
        solver = OptimizationSolver()
        controls = _build_complex_portfolio(n_controls, seed=1000 + n_controls)
        total_cost = sum(c.cost_usd for c in controls)
        budget = total_cost * 0.4
        baseline_eal = budget * 2.5

        t0 = time.perf_counter()
        res = solver.optimize(controls, budget=budget, baseline_eal=baseline_eal, include_frontier=False)
        solve_duration = time.perf_counter() - t0

        # Invariants
        assert res.is_budget_satisfied is True
        assert res.allocated_spend_usd <= budget, (
            f"Allocated spend {res.allocated_spend_usd} exceeded budget {budget} for N={n_controls}"
        )
        assert solve_duration < 2.0, f"Solve took too long ({solve_duration:.2f}s) for N={n_controls}"

        # Constraint verification
        sel_set = set(res.selected_control_ids)
        ctrl_map = {c.control_id: c for c in controls}

        for cid in sel_set:
            c = ctrl_map[cid]
            # Prerequisites satisfied
            for p in c.prerequisites:
                if p in ctrl_map:
                    assert p in sel_set, f"Prerequisite {p} missing for {cid} in solution!"
            # Mutual exclusivity satisfied
            for conf in c.conflicts:
                assert conf not in sel_set, f"Conflicting controls {cid} and {conf} co-selected!"

    def test_clique_of_size_20_mutual_exclusivity(self):
        """Stress-test a complete conflict graph (clique) of 20 controls."""
        solver = OptimizationSolver()
        k = 20
        clique = [
            SecurityControl(
                control_id=f"K20_{i}",
                name=f"Member {i}",
                category="IAM",
                cost_usd=float(500 * (i + 1)),
                effectiveness=0.5 + (0.02 * i),
                conflicts=[f"K20_{j}" for j in range(k) if j != i],
            )
            for i in range(k)
        ]
        res = solver.optimize(clique, budget=1e9, baseline_eal=1000000.0, include_frontier=False)
        sel = [cid for cid in res.selected_control_ids if cid.startswith("K20_")]
        assert len(sel) <= 1, f"Clique constraint violated! Selected {len(sel)} items: {sel}"


class TestMathematicalInvariantsHarness:
    """Stress-test mathematical invariants across dense random budgets."""

    def test_500_random_budgets_strict_spend_inequality(self):
        """
        Adversarial Invariant: Across 500 randomly sampled budgets from 0 to 1.5 * total_cost,
        allocated_spend <= budget strictly, with zero tolerance.
        """
        solver = OptimizationSolver()
        controls = _build_complex_portfolio(30, seed=4242)
        total_cost = sum(c.cost_usd for c in controls)
        rng = random.Random(7777)

        for _ in range(500):
            b = rng.uniform(0.0, total_cost * 1.5)
            res = solver.optimize(controls, budget=b, baseline_eal=500000.0, include_frontier=False)
            assert res.allocated_spend <= b, (
                f"Strict zero-tolerance budget violation! spend={res.allocated_spend} > budget={b}"
            )
            assert res.is_budget_satisfied is True

    def test_rosi_and_nfb_mathematical_consistency(self):
        """
        Verify ROSI % formula: ((Risk Mitigated - Spend) / Spend) * 100.
        Verify Net Financial Benefit: Risk Mitigated - Spend.
        """
        solver = OptimizationSolver()
        controls = _build_complex_portfolio(25, seed=555)
        budget = 20000.0
        baseline_eal = 200000.0

        res = solver.optimize(controls, budget=budget, baseline_eal=baseline_eal, include_frontier=False)
        spend = res.allocated_spend_usd
        mitigated = res.risk_mitigated_usd

        if spend > 0:
            expected_rosi = ((mitigated - spend) / spend) * 100.0
            assert math.isclose(res.portfolio_rosi, expected_rosi, rel_tol=1e-4), (
                f"ROSI mismatch: expected {expected_rosi}, got {res.portfolio_rosi}"
            )
            expected_nfb = mitigated - spend
            assert math.isclose(res.net_financial_benefit_usd, expected_nfb, rel_tol=1e-4), (
                f"NFB mismatch: expected {expected_nfb}, got {res.net_financial_benefit_usd}"
            )
        else:
            assert res.portfolio_rosi == 0.0
            assert res.net_financial_benefit_usd == 0.0

    def test_currency_conversion_invariants(self):
        """Verify USD and INR values maintain exact USD_TO_INR_RATE = 83.5."""
        solver = OptimizationSolver()
        controls = _build_complex_portfolio(20, seed=888, currency="USD")
        budget = 15000.0
        baseline_eal = 150000.0

        res_usd = solver.optimize(controls, budget=budget, baseline_eal=baseline_eal, currency="USD", include_frontier=False)
        assert math.isclose(res_usd.allocated_spend_usd * USD_TO_INR_RATE, res_usd.allocated_spend_inr, rel_tol=1e-4)
        assert math.isclose(res_usd.risk_mitigated_usd * USD_TO_INR_RATE, res_usd.risk_mitigated_inr, rel_tol=1e-4)
        assert math.isclose(res_usd.residual_eal_usd * USD_TO_INR_RATE, res_usd.residual_eal_inr, rel_tol=1e-4)
        assert math.isclose(res_usd.net_financial_benefit_usd * USD_TO_INR_RATE, res_usd.net_financial_benefit_inr, rel_tol=1e-4)


class TestParetoFrontierConcaveEnvelopeInvariants:
    """Stress-test Pareto efficiency frontier and upper concave envelope."""

    @pytest.mark.parametrize("seed", [101, 202, 303, 404, 505])
    def test_pareto_diminishing_returns_and_concavity(self, seed: int):
        """
        Verify that for arbitrary random portfolios, the Pareto frontier satisfies:
        1. Monotonically non-decreasing spend.
        2. Monotonically non-decreasing risk mitigation.
        3. Monotonically non-increasing marginal slope (diminishing returns).
        """
        controls = _build_complex_portfolio(20, seed=seed)
        total_cost = sum(c.cost_usd for c in controls)
        res = generate_pareto_frontier(
            controls=controls,
            baseline_eal=total_cost * 3.0,
            max_budget=total_cost,
            step_count=15,
            currency="USD",
        )
        curve = res.curve
        assert len(curve) >= 2, "Frontier curve must contain at least 2 points"

        slopes = []
        for i in range(1, len(curve)):
            ds = curve[i].spend - curve[i - 1].spend
            dr = curve[i].risk_mitigated - curve[i - 1].risk_mitigated

            # Spend must strictly increase on filtered envelope
            assert ds > -1e-6, f"Spend decreased from {curve[i-1].spend} to {curve[i].spend}"
            # Risk mitigated must not decrease
            assert dr > -1e-6, f"Risk mitigation decreased from {curve[i-1].risk_mitigated} to {curve[i].risk_mitigated}"

            if ds > 1e-4:
                slopes.append(dr / ds)

        # Monotonically non-increasing marginal slopes (diminishing returns)
        for j in range(1, len(slopes)):
            assert slopes[j] <= slopes[j - 1] + 1e-4, (
                f"Diminishing returns violated! Slope {slopes[j]} > previous slope {slopes[j-1]}"
            )


class TestBoundaryEdgeCases:
    """Stress-test boundary and pathological edge cases."""

    def test_empty_control_list(self):
        """Empty control list returns zero allocation without errors."""
        solver = OptimizationSolver()
        res = solver.optimize([], budget=10000.0, baseline_eal=50000.0, include_frontier=False)
        assert res.allocated_spend == 0.0
        assert len(res.selected_control_ids) == 0
        assert res.risk_mitigated == 0.0
        assert res.residual_eal == 50000.0
        assert res.is_budget_satisfied is True

    def test_all_controls_exceed_budget(self):
        """When all controls cost more than the budget, solver selects none."""
        solver = OptimizationSolver()
        controls = [
            SecurityControl(control_id="EXP1", name="Exp 1", category="cat", cost_usd=10000.0, effectiveness=0.9),
            SecurityControl(control_id="EXP2", name="Exp 2", category="cat", cost_usd=20000.0, effectiveness=0.8),
        ]
        res = solver.optimize(controls, budget=5000.0, baseline_eal=100000.0, include_frontier=False)
        assert res.allocated_spend == 0.0
        assert len(res.selected_control_ids) == 0
        assert res.is_budget_satisfied is True

    def test_zero_and_negative_budgets(self):
        """Zero and negative budgets return 0 spend, is_budget_satisfied=True."""
        solver = OptimizationSolver()
        c = SecurityControl(control_id="C1", name="C1", category="cat", cost_usd=100.0, effectiveness=0.5)

        res_zero = solver.optimize([c], budget=0.0, baseline_eal=10000.0, include_frontier=False)
        assert res_zero.allocated_spend == 0.0
        assert res_zero.is_budget_satisfied is True

        res_neg = solver.optimize([c], budget=-500.0, baseline_eal=10000.0, include_frontier=False)
        assert res_neg.allocated_spend == 0.0
        assert res_neg.is_budget_satisfied is True

    def test_single_control_exact_fit_and_over_budget(self):
        """Single control tested at cost, cost - eps, and cost + eps."""
        solver = OptimizationSolver()
        c = SecurityControl(control_id="C1", name="C1", category="cat", cost_usd=1000.0, effectiveness=0.7)

        # Exactly fits
        res_exact = solver.optimize([c], budget=1000.0, baseline_eal=10000.0, include_frontier=False)
        assert res_exact.allocated_spend == 1000.0
        assert res_exact.selected_control_ids == ["C1"]

        # Slightly under
        res_under = solver.optimize([c], budget=999.99, baseline_eal=10000.0, include_frontier=False)
        assert res_under.allocated_spend == 0.0
        assert res_under.selected_control_ids == []

        # Over
        res_over = solver.optimize([c], budget=1000.01, baseline_eal=10000.0, include_frontier=False)
        assert res_over.allocated_spend == 1000.0
        assert res_over.selected_control_ids == ["C1"]

    def test_all_controls_mandatory_but_budget_insufficient(self):
        """
        All controls are marked mandatory, but total cost exceeds budget.
        Solver must gracefully select the highest-value subset that fits within budget
        without exceeding the budget limit or crashing.
        """
        solver = OptimizationSolver()
        controls = [
            SecurityControl(control_id="M1", name="M1", category="cat", cost_usd=1000.0, effectiveness=0.8, is_mandatory=True),
            SecurityControl(control_id="M2", name="M2", category="cat", cost_usd=1000.0, effectiveness=0.6, is_mandatory=True),
            SecurityControl(control_id="M3", name="M3", category="cat", cost_usd=1000.0, effectiveness=0.4, is_mandatory=True),
        ]
        # Total cost = 3000, but budget = 2200 (fits 2 controls)
        res = solver.optimize(controls, budget=2200.0, baseline_eal=50000.0, include_frontier=False)
        assert res.allocated_spend <= 2200.0
        assert res.is_budget_satisfied is True
        # Should have selected the highest-effectiveness controls (M1 and M2)
        assert len(res.selected_control_ids) == 2
        assert "M1" in res.selected_control_ids
        assert "M2" in res.selected_control_ids

    def test_conflicting_mandatory_controls(self):
        """
        Two controls are both mandatory but conflict with each other.
        Solver must select at most one of them to maintain feasibility.
        """
        solver = OptimizationSolver()
        controls = [
            SecurityControl(control_id="M_A", name="M_A", category="cat", cost_usd=1000.0, effectiveness=0.9, is_mandatory=True, conflicts=["M_B"]),
            SecurityControl(control_id="M_B", name="M_B", category="cat", cost_usd=1000.0, effectiveness=0.8, is_mandatory=True, conflicts=["M_A"]),
        ]
        res = solver.optimize(controls, budget=5000.0, baseline_eal=50000.0, include_frontier=False)
        sel = res.selected_control_ids
        assert not ("M_A" in sel and "M_B" in sel), f"Both conflicting mandatory controls were selected: {sel}"
        assert len(sel) == 1
        assert res.is_budget_satisfied is True

    def test_missing_prerequisite_control(self):
        """
        Control child requires prerequisite that does not exist in candidate pool.
        Child must never be selected.
        """
        solver = OptimizationSolver()
        c = SecurityControl(
            control_id="ORPHAN",
            name="Orphan",
            category="cat",
            cost_usd=500.0,
            effectiveness=0.9,
            prerequisites=["GHOST_PARENT"],
        )
        res = solver.optimize([c], budget=5000.0, baseline_eal=50000.0, include_frontier=False)
        assert len(res.selected_control_ids) == 0, "Control with missing prerequisite was selected!"
        assert res.allocated_spend == 0.0

    def test_zero_baseline_eal(self):
        """Baseline EAL of 0 returns 0 spend and 0 mitigation."""
        solver = OptimizationSolver()
        c = SecurityControl(control_id="C1", name="C1", category="cat", cost_usd=500.0, effectiveness=0.5)
        res = solver.optimize([c], budget=5000.0, baseline_eal=0.0, include_frontier=False)
        assert res.allocated_spend == 0.0
        assert res.risk_mitigated == 0.0
        assert res.residual_eal == 0.0
        assert res.is_budget_satisfied is True
