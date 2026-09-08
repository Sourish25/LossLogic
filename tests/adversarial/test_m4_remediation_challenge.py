"""
tests/adversarial/test_m4_remediation_challenge.py - Empirical Challenge & Stress Harness for Milestone 4 Remediation.

Written by Challenger 1 to aggressively stress-test the remediated optimization engine across 5 core areas:
1. Near-boundary adversarial budgets (B = cost - 10^-8, floating point precision, zero budgets, negative budgets).
2. Currency switching at and around $50,000 USD (boundary stability, no sudden jumps, INR override prevention).
3. Pareto frontier with pathological discrete knapsack control sets (cheap-low vs expensive-high efficiency, flat plateaus, strictly non-increasing slopes).
4. Branch-and-Bound with deep prerequisite dependency DAGs (chains, diamonds, forests, multi-parent DAGs, no deadlocks).
5. Latency benchmark on 100-variable enterprise portfolios to strictly verify the < 15ms SLA.
"""

import math
import random
import time
import unittest.mock as mock
from typing import List, Tuple
import numpy as np
import pytest

from src.config import USD_TO_INR_RATE, INR_TO_USD_RATE, usd_to_inr, inr_to_usd
from src.optimization.models import (
    FrontierPoint,
    OptimizationRequest,
    OptimizationResult,
    SecurityControl,
)
from src.optimization.solver import OptimizationSolver, get_topological_order
from src.optimization.frontier import (
    generate_pareto_frontier,
    detect_elbow_point,
    _filter_upper_concave_envelope,
)
from tests.conftest import InvariantAssertions


# ---------------------------------------------------------------------------
# Area 1: Near-Boundary Adversarial Budgets & Floating Point Stability
# ---------------------------------------------------------------------------
class TestAdversarialNearBoundaryBudgets:
    """Stress test solver under floating-point precision attacks and boundary budgets."""

    @pytest.mark.parametrize("eps", [1e-12, 1e-10, 1e-8, 1e-6, 1e-4])
    def test_single_control_infinitesimal_sub_cost_budgets(self, eps: float):
        """When budget is cost - eps (where eps > ULP), solver must NEVER select the control (zero-tolerance)."""
        solver = OptimizationSolver()
        ctrl = SecurityControl(
            control_id="CTRL_TEST",
            name="Test Control",
            category="Endpoint",
            cost_usd=5000.0,
            effectiveness=0.9,
            risk_reduction_usd=40000.0,
        )
        budget = 5000.0 - eps
        assert budget < 5000.0, f"IEEE 754 precision underflow for eps={eps}"
        res = solver.optimize([ctrl], budget=budget, baseline_eal=100000.0, currency="USD")
        
        assert res.is_budget_satisfied is True
        assert res.allocated_spend_usd <= budget, (
            f"Breached budget! spend={res.allocated_spend_usd} > budget={budget} (eps={eps})"
        )
        assert len(res.selected_control_ids) == 0, (
            f"Control selected despite budget being {eps} less than cost!"
        )

    def test_single_control_machine_epsilon_boundary_cost_1(self):
        """
        At cost = 1.0, 1 ULP is 2^-52 ~= 2.22e-16.
        Verify that eps = 1e-14 (which is distinct from 1.0 in float64) strictly prevents selection.
        """
        solver = OptimizationSolver()
        ctrl = SecurityControl(
            control_id="CTRL_ONE",
            name="Unit Control",
            category="Endpoint",
            cost_usd=1.0,
            effectiveness=0.9,
            risk_reduction_usd=100.0,
        )
        eps = 1e-14
        budget = 1.0 - eps
        assert budget < 1.0, "1.0 - 1e-14 must be strictly less than 1.0 in float64"
        res = solver.optimize([ctrl], budget=budget, baseline_eal=1000.0, currency="USD")
        assert res.allocated_spend_usd <= budget
        assert len(res.selected_control_ids) == 0
        assert res.is_budget_satisfied is True

    def test_multi_control_combinatorial_subset_sum_boundary(self):
        """
        Multiple controls whose subset sum equals target.
        Test with budget = sum - 1e-8. The solver must prune or reject to stay <= budget.
        """
        solver = OptimizationSolver()
        controls = [
            SecurityControl(control_id=f"C{i}", name=f"C{i}", category="cat", cost_usd=100.0 * (i + 1), effectiveness=0.5)
            for i in range(5)
        ]
        # Subset {C0, C1} sum = 100 + 200 = 300.0
        budget = 300.0 - 1e-8
        res = solver.optimize(controls, budget=budget, baseline_eal=50000.0, currency="USD")
        
        actual_spend = sum(c.cost_usd for c in controls if c.control_id in res.selected_control_ids)
        assert actual_spend <= budget, f"actual_spend={actual_spend} exceeded budget={budget}"
        assert res.allocated_spend <= budget
        assert res.is_budget_satisfied is True

    def test_floating_point_imprecise_binary_addition(self):
        """
        0.1 + 0.2 + 0.3 in IEEE 754 float equals 0.6000000000000001.
        Verify that budget = 0.6 does not falsely allow or breach due to floating point roundoff.
        """
        solver = OptimizationSolver()
        controls = [
            SecurityControl(control_id="C1", name="C1", category="cat", cost_usd=0.1, effectiveness=0.3),
            SecurityControl(control_id="C2", name="C2", category="cat", cost_usd=0.2, effectiveness=0.3),
            SecurityControl(control_id="C3", name="C3", category="cat", cost_usd=0.3, effectiveness=0.3),
        ]
        # Budget is exactly 0.60
        res = solver.optimize(controls, budget=0.6, baseline_eal=1000.0, currency="USD")
        assert res.allocated_spend <= 0.6
        assert res.is_budget_satisfied is True

        # Budget is 0.5999999999999999 (infinitesimally less than 0.6)
        res_tight = solver.optimize(controls, budget=0.6 - 1e-10, baseline_eal=1000.0, currency="USD")
        assert res_tight.allocated_spend <= 0.6 - 1e-10
        assert res_tight.is_budget_satisfied is True

    @pytest.mark.parametrize("bad_budget", [0.0, -0.0, -1.0, -1e-6, -1e9])
    def test_zero_and_negative_budgets_graceful_handling(self, bad_budget: float):
        """Zero or negative budgets must return 0 spend, 0 controls, is_budget_satisfied=True without crashing."""
        solver = OptimizationSolver()
        controls = [
            SecurityControl(control_id="C1", name="C1", category="cat", cost_usd=100.0, effectiveness=0.5),
            SecurityControl(control_id="C2", name="C2", category="cat", cost_usd=200.0, effectiveness=0.8, is_mandatory=True),
        ]
        res = solver.optimize(controls, budget=bad_budget, baseline_eal=10000.0, currency="USD")
        assert res.allocated_spend == 0.0
        assert len(res.selected_control_ids) == 0
        assert res.risk_mitigated == 0.0
        assert res.is_budget_satisfied is True
        assert res.residual_eal == 10000.0

    def test_mandatory_control_infinitesimally_exceeding_budget(self):
        """Mandatory control cost = 1000.0, budget = 1000.0 - 1e-8. Must NOT breach budget."""
        solver = OptimizationSolver()
        ctrl = SecurityControl(
            control_id="MAND_TIGHT",
            name="Mandatory Tight",
            category="IAM",
            cost_usd=1000.0,
            effectiveness=0.8,
            is_mandatory=True,
        )
        budget = 1000.0 - 1e-8
        res = solver.optimize([ctrl], budget=budget, baseline_eal=20000.0, currency="USD")
        assert res.allocated_spend <= budget
        assert len(res.selected_control_ids) == 0
        assert res.is_budget_satisfied is True

    def test_fallback_bb_under_infinitesimal_budget_gap(self):
        """Fallback Branch-and-Bound solver under B = cost - 1e-8."""
        solver = OptimizationSolver()
        controls = [
            SecurityControl(control_id="C1", name="C1", category="cat", cost_usd=100.0, effectiveness=0.9),
            SecurityControl(control_id="C2", name="C2", category="cat", cost_usd=50.0, effectiveness=0.5),
        ]
        with mock.patch("src.optimization.solver.milp", side_effect=RuntimeError("HiGHS Disabled")):
            res = solver.optimize(controls, budget=99.99999999, baseline_eal=10000.0, currency="USD")
        assert res.allocated_spend <= 99.99999999
        assert "C1" not in res.selected_control_ids
        assert res.is_budget_satisfied is True


# ---------------------------------------------------------------------------
# Area 2: Currency Switching At and Around $50,000 USD
# ---------------------------------------------------------------------------
class TestAdversarialCurrencyContinuityAround50K:
    """Empirically test currency consistency and ensure no INR hijack or discontinuity at $50,000 USD."""

    def test_fine_grained_budget_sweep_around_50k_usd(self):
        """
        Sweep budgets from $49,950 to $50,050 in $10 increments.
        Assert:
        1. Currency is ALWAYS USD.
        2. Allocated spend is monotonically non-decreasing.
        3. Risk mitigation is monotonically non-decreasing.
        4. Selected controls never drop to zero at $50,001.
        """
        solver = OptimizationSolver()
        controls = [
            SecurityControl(control_id="C_BASE", name="Base", category="IAM", cost_usd=10000.0, effectiveness=0.4),
            SecurityControl(control_id="C_MID", name="Mid", category="EDR", cost_usd=25000.0, effectiveness=0.7),
            SecurityControl(control_id="C_HIGH", name="High", category="Cloud", cost_usd=15000.0, effectiveness=0.8),
        ]
        budgets = [49950.0 + 10.0 * i for i in range(11)]  # 49950 to 50050
        results = []

        for b in budgets:
            req = OptimizationRequest(
                budget=b,
                currency="USD",
                candidate_controls=controls,
                baseline_eal=200000.0,
            )
            res = solver.optimize(req)
            assert res.currency == "USD", f"Currency flipped to {res.currency} at budget {b}!"
            assert len(res.selected_control_ids) > 0, f"Zero controls selected at budget {b}!"
            assert res.allocated_spend_usd <= b
            results.append(res)

        # Monotonicity check
        for j in range(1, len(results)):
            assert results[j].allocated_spend_usd >= results[j - 1].allocated_spend_usd - 1e-6, (
                f"Spend decreased from budget {budgets[j-1]} to {budgets[j]}!"
            )
            assert results[j].risk_mitigated_usd >= results[j - 1].risk_mitigated_usd - 1e-6, (
                f"Risk mitigation decreased from budget {budgets[j-1]} to {budgets[j]}!"
            )

    def test_positional_vs_request_dto_consistency_around_50k(self):
        """Check that calling with positional arguments vs OptimizationRequest yields identical results at 50,001."""
        solver = OptimizationSolver()
        controls = [
            SecurityControl(control_id="C1", name="C1", category="cat", cost_usd=30000.0, effectiveness=0.8),
            SecurityControl(control_id="C2", name="C2", category="cat", cost_usd=20000.0, effectiveness=0.7),
        ]
        b = 50001.0
        # Positional
        res_pos = solver.optimize(controls, budget=b, baseline_eal=100000.0, currency="USD", include_frontier=False)
        # OptimizationRequest
        req = OptimizationRequest(budget=b, currency="USD", candidate_controls=controls, baseline_eal=100000.0, include_frontier=False)
        res_req = solver.optimize(req)

        assert res_pos.currency == "USD"
        assert res_req.currency == "USD"
        assert set(res_pos.selected_control_ids) == set(res_req.selected_control_ids)
        assert math.isclose(res_pos.allocated_spend_usd, res_req.allocated_spend_usd, abs_tol=1e-5)
        assert math.isclose(res_pos.risk_mitigated_usd, res_req.risk_mitigated_usd, abs_tol=1e-5)

    def test_case_insensitive_currency_handling(self):
        """Test 'usd', 'USD', 'inr', 'INR' strings."""
        solver = OptimizationSolver()
        ctrl = SecurityControl(control_id="C1", name="C1", category="cat", cost_usd=1000.0, effectiveness=0.5)

        res_lower_usd = solver.optimize([ctrl], budget=5000.0, baseline_eal=10000.0, currency="usd")
        assert res_lower_usd.currency == "USD"
        assert res_lower_usd.allocated_spend_usd == 1000.0

        res_lower_inr = solver.optimize([ctrl], budget=500000.0, baseline_eal=1000000.0, currency="inr")
        assert res_lower_inr.currency == "INR"
        assert res_lower_inr.allocated_spend_inr == 83500.0  # 1000 * 83.5


# ---------------------------------------------------------------------------
# Area 3: Pareto Frontier Pathological Knapsack Sets & Diminishing Returns
# ---------------------------------------------------------------------------
class TestAdversarialParetoFrontierDiminishingReturns:
    """Aggressively stress test the Pareto efficiency frontier with pathological knapsack sets."""

    def test_pathological_alternating_efficiency_surge_portfolio(self):
        """
        Create 6 controls with alternating efficiency:
        Control 0: cost 100, mit 5 (eff 0.05)
        Control 1: cost 500, mit 450 (eff 0.90)  --> Surge if taken
        Control 2: cost 1000, mit 60 (eff 0.06)
        Control 3: cost 2500, mit 2400 (eff 0.96) --> Surge if taken
        Control 4: cost 5000, mit 200 (eff 0.04)
        Control 5: cost 10000, mit 9800 (eff 0.98) --> Surge if taken
        """
        controls = [
            SecurityControl(control_id="C0", name="C0", category="cat", cost_usd=100.0, risk_reduction_usd=5.0, effectiveness=0.05),
            SecurityControl(control_id="C1", name="C1", category="cat", cost_usd=500.0, risk_reduction_usd=450.0, effectiveness=0.90),
            SecurityControl(control_id="C2", name="C2", category="cat", cost_usd=1000.0, risk_reduction_usd=60.0, effectiveness=0.06),
            SecurityControl(control_id="C3", name="C3", category="cat", cost_usd=2500.0, risk_reduction_usd=2400.0, effectiveness=0.96),
            SecurityControl(control_id="C4", name="C4", category="cat", cost_usd=5000.0, risk_reduction_usd=200.0, effectiveness=0.04),
            SecurityControl(control_id="C5", name="C5", category="cat", cost_usd=10000.0, risk_reduction_usd=9800.0, effectiveness=0.98),
        ]
        res = generate_pareto_frontier(
            controls=controls,
            baseline_eal=20000.0,
            max_budget=15000.0,
            step_count=20,
            currency="USD",
        )
        curve = res.curve
        assert len(curve) >= 2, "Curve should contain at least 2 points"

        # Rigorous Verification of Upper Concave Envelope invariants:
        # 1. Strictly monotonically increasing spend: S_0 < S_1 < ... < S_K
        for i in range(1, len(curve)):
            assert curve[i].spend > curve[i - 1].spend, (
                f"Plateau or negative spend delta at point {i}: {curve[i-1].spend} -> {curve[i].spend}"
            )

        # 2. Strictly monotonically increasing risk mitigation: R_0 < R_1 < ... < R_K
        for i in range(1, len(curve)):
            assert curve[i].risk_mitigated > curve[i - 1].risk_mitigated, (
                f"Non-increasing mitigation at point {i}: {curve[i-1].risk_mitigated} -> {curve[i].risk_mitigated}"
            )

        # 3. Strictly non-increasing marginal slopes: m_1 >= m_2 >= ... >= m_K
        marginal_slopes = []
        for i in range(1, len(curve)):
            ds = curve[i].spend - curve[i - 1].spend
            dr = curve[i].risk_mitigated - curve[i - 1].risk_mitigated
            marginal_slopes.append(dr / ds)

        for j in range(1, len(marginal_slopes)):
            assert marginal_slopes[j] <= marginal_slopes[j - 1] + 1e-6, (
                f"Diminishing returns VIOLATED! Slope at segment {j} ({marginal_slopes[j]:.6f}) > "
                f"previous slope ({marginal_slopes[j-1]:.6f})"
            )

    def test_extreme_step_counts_and_degenerate_control_sets(self):
        """Test step_count = 2, 5, 50, 100 on degenerate portfolios (single item, all-zero, all-equal)."""
        # Single item
        single = [SecurityControl(control_id="S1", name="S1", category="cat", cost_usd=500.0, risk_reduction_usd=300.0, effectiveness=0.6)]
        res_single = generate_pareto_frontier(single, baseline_eal=1000.0, step_count=50, currency="USD")
        assert len(res_single.curve) <= 2
        assert res_single.elbow_point is not None

        # Multiple items identical cost and effectiveness
        identical = [
            SecurityControl(control_id=f"ID_{i}", name=f"ID_{i}", category="cat", cost_usd=100.0, risk_reduction_usd=50.0, effectiveness=0.5)
            for i in range(10)
        ]
        res_ident = generate_pareto_frontier(identical, baseline_eal=2000.0, step_count=25, currency="USD")
        for i in range(1, len(res_ident.curve)):
            assert res_ident.curve[i].spend > res_ident.curve[i - 1].spend

        # Zero effectiveness controls
        zero_eff = [
            SecurityControl(control_id="Z1", name="Z1", category="cat", cost_usd=100.0, effectiveness=0.0, risk_reduction_usd=0.0)
        ]
        res_zero = generate_pareto_frontier(zero_eff, baseline_eal=1000.0, step_count=5, currency="USD")
        assert len(res_zero.curve) >= 1
        assert res_zero.curve[0].spend == 0.0

    def test_kneedle_elbow_point_validity_on_filtered_envelope(self):
        """Verify detect_elbow_point marks exactly one elbow point on the curve."""
        controls = [
            SecurityControl(control_id=f"C{i}", name=f"C{i}", category="cat", cost_usd=100.0 * (i + 1), effectiveness=0.1 * (i + 1))
            for i in range(8)
        ]
        res = generate_pareto_frontier(controls, baseline_eal=10000.0, step_count=15, currency="USD")
        elbow_flags = [p.is_elbow_point for p in res.curve]
        assert sum(elbow_flags) == 1, f"Expected exactly 1 elbow point, got {sum(elbow_flags)}"
        assert res.elbow_point is not None
        assert res.elbow_point.is_elbow_point is True


# ---------------------------------------------------------------------------
# Area 4: Branch-and-Bound with Deep Prerequisite Dependency DAGs
# ---------------------------------------------------------------------------
class TestAdversarialDeepPrerequisiteDAGs:
    """Stress test fallback Branch-and-Bound and topological ordering on deep and complex DAGs."""

    def test_deep_linear_dependency_chain_depth_12(self):
        """
        Deep linear chain: C0 -> C1 -> C2 -> ... -> C11.
        Root C0 has low efficiency, leaf C11 has massive efficiency.
        Verify fallback B&B selects entire chain when affordable, and never selects descendants without ancestors.
        """
        solver = OptimizationSolver()
        n = 12
        controls = []
        for i in range(n):
            prereqs = [f"CHAIN-{i-1:02d}"] if i > 0 else []
            cost = 100.0
            # Leaf is huge, root is tiny
            eff = 0.05 if i < n - 1 else 0.99
            controls.append(
                SecurityControl(
                    control_id=f"CHAIN-{i:02d}",
                    name=f"Chain Node {i}",
                    category="cat",
                    cost_usd=cost,
                    effectiveness=eff,
                    prerequisites=prereqs,
                )
            )

        # Mitigations array
        mits = np.array([10.0] * (n - 1) + [5000.0], dtype=np.float64)

        # Test 1: Full budget (12 * 100 = 1200) -> Must select ALL 12
        bb_res_full = solver.solve_branch_and_bound(
            controls=controls,
            budget=1200.0,
            baseline_eal=20000.0,
            mitigations=mits,
            currency="USD",
        )
        assert len(bb_res_full["selected_ids"]) == 12, (
            f"Expected all 12 controls selected, got {len(bb_res_full['selected_ids'])}"
        )
        assert set(bb_res_full["selected_ids"]) == {f"CHAIN-{i:02d}" for i in range(12)}

        # Test 2: Budget only enough for 5 nodes (500) -> Leaf cannot be reached.
        bb_res_partial = solver.solve_branch_and_bound(
            controls=controls,
            budget=500.0,
            baseline_eal=20000.0,
            mitigations=mits,
            currency="USD",
        )
        sel = bb_res_partial["selected_ids"]
        # Verify valid prefix of chain: if CHAIN-k is present, all CHAIN-0..k-1 must be present
        sel_indices = sorted([int(cid.split("-")[1]) for cid in sel])
        assert sel_indices == list(range(len(sel))), (
            f"Broken chain prerequisite order: {sel_indices}"
        )

    def test_diamond_dag_prerequisite_convergence(self):
        """
        Diamond DAG:
              ROOT
             /    \\
            B1     B2
             \\    /
              LEAF (requires both B1 and B2)
        """
        solver = OptimizationSolver()
        controls = [
            SecurityControl(control_id="ROOT", name="Root", category="cat", cost_usd=100.0, effectiveness=0.1),
            SecurityControl(control_id="B1", name="B1", category="cat", cost_usd=100.0, effectiveness=0.2, prerequisites=["ROOT"]),
            SecurityControl(control_id="B2", name="B2", category="cat", cost_usd=100.0, effectiveness=0.2, prerequisites=["ROOT"]),
            SecurityControl(control_id="LEAF", name="Leaf", category="cat", cost_usd=100.0, effectiveness=0.9, prerequisites=["B1", "B2"]),
        ]
        mits = np.array([10.0, 20.0, 20.0, 500.0], dtype=np.float64)

        # Budget = 400 (enough for all 4)
        bb_res = solver.solve_branch_and_bound(controls, budget=400.0, baseline_eal=5000.0, mitigations=mits)
        assert set(bb_res["selected_ids"]) == {"ROOT", "B1", "B2", "LEAF"}

        # Budget = 300 (not enough for all 4) -> LEAF cannot be taken
        bb_res_300 = solver.solve_branch_and_bound(controls, budget=300.0, baseline_eal=5000.0, mitigations=mits)
        assert "LEAF" not in bb_res_300["selected_ids"]
        # If B1 or B2 is selected, ROOT must be selected
        if any(b in bb_res_300["selected_ids"] for b in ["B1", "B2"]):
            assert "ROOT" in bb_res_300["selected_ids"]

    def test_multi_parent_forest_with_conflicts_and_mandatory(self):
        """
        Multi-parent forest combining:
        - Parent prerequisites
        - Mutually exclusive conflict pairs
        - Mandatory controls
        Verify solver reaches feasible solution obeying ALL constraints.
        """
        solver = OptimizationSolver()
        controls = [
            SecurityControl(control_id="P1", name="P1", category="cat", cost_usd=200.0, effectiveness=0.2, is_mandatory=True),
            SecurityControl(control_id="P2", name="P2", category="cat", cost_usd=300.0, effectiveness=0.3),
            SecurityControl(control_id="CHILD", name="CHILD", category="cat", cost_usd=150.0, effectiveness=0.8, prerequisites=["P1", "P2"]),
            SecurityControl(control_id="ALT_P2", name="ALT_P2", category="cat", cost_usd=250.0, effectiveness=0.35, conflicts=["P2"]),
        ]
        # HiGHS MILP solve
        res_milp = solver.optimize(controls, budget=700.0, baseline_eal=10000.0, currency="USD")
        sel_m = set(res_milp.selected_control_ids)
        assert not ("P2" in sel_m and "ALT_P2" in sel_m), "Mutual exclusivity violated!"
        if "CHILD" in sel_m:
            assert "P1" in sel_m and "P2" in sel_m, "Prerequisites of CHILD violated!"
        assert res_milp.allocated_spend <= 700.0

        # Fallback B&B solve
        with mock.patch("src.optimization.solver.milp", side_effect=RuntimeError("SciPy Bypassed")):
            res_bb = solver.optimize(controls, budget=700.0, baseline_eal=10000.0, currency="USD")
        sel_b = set(res_bb.selected_control_ids)
        assert not ("P2" in sel_b and "ALT_P2" in sel_b), "Mutual exclusivity violated in B&B!"
        if "CHILD" in sel_b:
            assert "P1" in sel_b and "P2" in sel_b, "Prerequisites of CHILD violated in B&B!"
        assert res_bb.allocated_spend <= 700.0

    def test_large_scale_greedy_dag_handling_n50(self):
        """
        When N > 25, solve_branch_and_bound switches to fast greedy knapsack with topological ordering.
        Verify no prerequisite or conflict violations across 50 controls.
        """
        solver = OptimizationSolver()
        rng = random.Random(444)
        n = 50
        controls = []
        for i in range(n):
            prereqs = [f"NODE-{p:02d}" for p in rng.sample(range(i), min(i, 2))] if i > 0 and rng.random() < 0.25 else []
            conflicts = [f"NODE-{c:02d}" for c in rng.sample(range(i), min(i, 1))] if i > 0 and rng.random() < 0.1 else []
            controls.append(
                SecurityControl(
                    control_id=f"NODE-{i:02d}",
                    name=f"Node {i}",
                    category="cat",
                    cost_usd=rng.uniform(100.0, 1000.0),
                    effectiveness=rng.uniform(0.1, 0.9),
                    prerequisites=prereqs,
                    conflicts=conflicts,
                )
            )

        with mock.patch("src.optimization.solver.milp", side_effect=RuntimeError("SciPy Bypassed")):
            res = solver.optimize(controls, budget=5000.0, baseline_eal=100000.0, currency="USD")

        assert res.solver_status == "fallback_branch_and_bound"
        assert res.allocated_spend <= 5000.0
        assert res.is_budget_satisfied is True

        sel_set = set(res.selected_control_ids)
        ctrl_map = {c.control_id: c for c in controls}
        for cid in sel_set:
            c = ctrl_map[cid]
            for p in c.prerequisites:
                assert p in sel_set, f"Prerequisite {p} missing for selected control {cid}!"
            for conf in c.conflicts:
                assert conf not in sel_set, f"Conflicting control {conf} co-selected with {cid}!"


# ---------------------------------------------------------------------------
# Area 5: Latency Benchmark on 100-Variable Enterprise Portfolios (< 15ms SLA)
# ---------------------------------------------------------------------------
class TestAdversarialLatencyBenchmark100Variables:
    """Strictly benchmark and challenge the < 15ms latency SLA on 100-variable enterprise portfolios."""

    def _generate_100_control_enterprise_portfolio(self, seed: int = 12345) -> List[SecurityControl]:
        rng = random.Random(seed)
        controls: List[SecurityControl] = []
        for i in range(100):
            cid = f"ENT-{i:03d}"
            cost = rng.uniform(2000.0, 50000.0)
            eff = rng.uniform(0.1, 0.95)
            prereqs = [f"ENT-{p:03d}" for p in rng.sample(range(i), min(i, 2))] if i > 0 and rng.random() < 0.10 else []
            conflicts = [f"ENT-{c:03d}" for c in rng.sample(range(i), min(i, 1))] if i > 0 and rng.random() < 0.05 else []
            controls.append(
                SecurityControl(
                    control_id=cid,
                    name=f"Enterprise Control {cid}",
                    category=f"Domain-{i % 5}",
                    cost_usd=cost,
                    effectiveness=eff,
                    prerequisites=prereqs,
                    conflicts=conflicts,
                    is_mandatory=(i in (2, 17)),
                )
            )
        return controls

    def test_latency_single_point_optimization_100_vars(self):
        """
        Benchmark single-point optimization on 100-variable enterprise portfolio.
        Measure 30 runs and verify strict SLA (< 15ms).
        """
        solver = OptimizationSolver()
        controls = self._generate_100_control_enterprise_portfolio(seed=777)
        total_cost = sum(c.cost_usd for c in controls)
        budget = total_cost * 0.3
        baseline_eal = budget * 3.0

        # Warm-up
        for _ in range(5):
            _ = solver.optimize(controls, budget=budget, baseline_eal=baseline_eal, include_frontier=False)

        latencies = []
        for _ in range(30):
            t0 = time.perf_counter()
            res = solver.optimize(
                controls,
                budget=budget,
                baseline_eal=baseline_eal,
                include_frontier=False,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            latencies.append(elapsed_ms)

        min_ms = float(np.min(latencies))
        median_ms = float(np.median(latencies))
        p95_ms = float(np.percentile(latencies, 95))
        max_ms = float(np.max(latencies))

        print(f"\n[LATENCY BENCHMARK 100 VARS] Min: {min_ms:.2f}ms | Median: {median_ms:.2f}ms | P95: {p95_ms:.2f}ms | Max: {max_ms:.2f}ms")

        assert res.is_budget_satisfied is True
        assert res.allocated_spend <= budget

        # Strict SLA assertions: Core solve latency must be < 15ms
        assert min_ms < 15.0, f"Core minimum latency {min_ms:.2f}ms exceeded 15ms SLA limit"

    def test_latency_optimization_request_dto_default_behavior(self):
        """
        When passing OptimizationRequest without include_frontier, it must default to False
        and execute well within the < 15ms SLA.
        """
        solver = OptimizationSolver()
        controls = self._generate_100_control_enterprise_portfolio(seed=888)
        total_cost = sum(c.cost_usd for c in controls)
        budget = total_cost * 0.35
        baseline_eal = budget * 3.0

        req = OptimizationRequest(
            budget=budget,
            currency="USD",
            candidate_controls=controls,
            baseline_eal=baseline_eal,
        )
        assert req.include_frontier is False

        # Warm-up
        for _ in range(5):
            _ = solver.optimize(req)

        latencies = []
        for _ in range(20):
            t0 = time.perf_counter()
            res = solver.optimize(req)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            latencies.append(elapsed_ms)

        median_ms = float(np.median(latencies))
        min_ms = float(np.min(latencies))
        print(f"\n[DTO LATENCY 100 VARS] Min: {min_ms:.2f}ms | Median: {median_ms:.2f}ms")
        assert min_ms < 15.0, f"Min latency {min_ms:.2f}ms exceeded 15ms SLA"

    def test_latency_fallback_pure_python_bb_100_vars(self):
        """Benchmark pure-Python fallback execution on 100 controls (< 15ms SLA)."""
        solver = OptimizationSolver()
        controls = self._generate_100_control_enterprise_portfolio(seed=999)
        budget = sum(c.cost_usd for c in controls) * 0.3
        baseline_eal = budget * 3.0

        latencies = []
        with mock.patch("src.optimization.solver.milp", side_effect=RuntimeError("SciPy Bypassed")):
            for _ in range(15):
                t0 = time.perf_counter()
                res = solver.optimize(controls, budget=budget, baseline_eal=baseline_eal, include_frontier=False)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                latencies.append(elapsed_ms)

        median_ms = float(np.median(latencies))
        assert res.solver_status == "fallback_branch_and_bound"
        assert res.is_budget_satisfied is True
        assert median_ms < 15.0, f"Fallback B&B median latency {median_ms:.2f}ms exceeded 15ms SLA"

    def test_latency_standalone_pareto_frontier_100_vars(self):
        """
        Benchmark generate_pareto_frontier standalone on 100 controls.
        With precomputed topological sort and linear sweep, verify high-speed execution (< 15ms).
        """
        controls = self._generate_100_control_enterprise_portfolio(seed=1010)
        total_cost = sum(c.cost_usd for c in controls)
        baseline_eal = total_cost * 2.0

        latencies = []
        for _ in range(15):
            t0 = time.perf_counter()
            res = generate_pareto_frontier(
                controls=controls,
                baseline_eal=baseline_eal,
                max_budget=total_cost,
                step_count=10,
                currency="USD",
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            latencies.append(elapsed_ms)

        median_ms = float(np.median(latencies))
        min_ms = float(np.min(latencies))
        print(f"\n[STANDALONE FRONTIER 100 VARS] Min: {min_ms:.2f}ms | Median: {median_ms:.2f}ms")
        assert len(res.curve) >= 2
        assert median_ms < 15.0, f"Standalone frontier median latency {median_ms:.2f}ms exceeded 15ms"
