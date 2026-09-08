"""
tests/invariants/test_optimization_adversarial.py - Adversarial Stress Tests & Solver Invariants.

Challenger 1 empirical stress test harness for Milestone 4 (ROSI Optimization Engine):
1. Floating-point zero-tolerance budget breaches: Near-boundary epsilon attacks.
2. Diminishing marginal returns failure: Flat intermediate steps disabling slope capping on Pareto frontier.
3. Circular dependency chains: MILP co-requisite bundling vs Branch-and-Bound deadlock divergence.
4. Mutual exclusivity cliques: Pairwise cliques of size 3, 5, and 10 under infinite and constrained budgets.
5. Infeasible mandatory controls: Exceeding budget alone and in conjunction with prerequisite closures.
6. Topological inversion in Branch-and-Bound: High-efficiency child pruning when parent sorted later.
7. Currency auto-detection hijacking: Budget > 50,000 USD silent flip to INR causing empty selection.
8. Extreme scale & numerical stability: Huge monetary values ($10^15), zero costs, negative budgets.
"""

import math
import random
import time
from typing import List
import numpy as np
import pytest

from src.optimization.models import (
    FrontierPoint,
    OptimizationRequest,
    OptimizationResult,
    SecurityControl,
)
from src.optimization.solver import OptimizationSolver
from src.optimization.frontier import generate_pareto_frontier, detect_elbow_point
from src.optimization.rosi import (
    calculate_marginal_cbr,
    calculate_net_financial_benefit,
    calculate_rosi,
    convert_currency,
)
from tests.conftest import InvariantAssertions


@pytest.mark.invariants
class TestOptimizationAdversarialSuite:
    """Adversarial stress tests challenging optimization engine invariants."""

    def test_adversarial_floating_point_budget_breach_near_boundary(self):
        """
        Adversarial Challenge 1: Zero-Tolerance Budget Ceiling Enforcement.
        Probes solver behavior when budget B is infinitesimally smaller than an item subset sum:
        B = sum(c_i) - eps, where eps in [1e-12, 1e-7].
        Because the MILP formulation and solver use a tolerance of 1e-6 (spend_check <= budget_val + 1e-6),
        HiGHS accepts solutions where sum(c_i) > B, violating strict mathematical zero-tolerance.
        """
        solver = OptimizationSolver()
        controls = [
            SecurityControl(control_id=f"C{i}", name=f"C{i}", category="cat", cost_usd=float(100 * (i + 1)), effectiveness=0.5)
            for i in range(5)
        ]

        target_cost = 100.0  # Cost of C0
        eps_breach = 1e-8
        budget_tight = target_cost - eps_breach

        res = solver.optimize(controls, budget=budget_tight, baseline_eal=10000.0, currency="USD")
        actual_spend = sum(c.cost_usd for c in controls if c.control_id in res.selected_control_ids)

        # Invariant: actual spend must strictly never exceed budget ceiling under zero tolerance
        assert actual_spend <= budget_tight, (
            f"Zero-tolerance budget breach! actual_spend={actual_spend} > budget={budget_tight}"
        )
        assert res.is_budget_satisfied is True

    def test_random_100_budgets_standard_tolerance(self):
        """
        Adversarial Challenge 1B: Standard 100 Random Budgets Verification.
        Verifies that across 100 randomly sampled budgets from [0, 1.2 * total_cost],
        actual spend never exceeds budget by more than standard numerical tolerance (1e-6).
        """
        solver = OptimizationSolver()
        rng = random.Random(999)
        controls = [
            SecurityControl(
                control_id=f"CTRL-{i:02d}",
                name=f"Control {i}",
                category=f"Cat-{i % 3}",
                cost_usd=round(rng.uniform(500.0, 10000.0), 2),
                effectiveness=round(rng.uniform(0.1, 0.9), 2),
                is_mandatory=(i in (0, 7)),
                conflicts=[f"CTRL-{i+1:02d}"] if i % 5 == 0 and i < 19 else [],
                prerequisites=[f"CTRL-{i-1:02d}"] if i % 4 == 0 and i > 0 else [],
            )
            for i in range(20)
        ]
        total_cost = sum(c.cost_usd for c in controls)

        for _ in range(100):
            b = rng.uniform(0.0, total_cost * 1.1)
            res = solver.optimize(controls, budget=b, baseline_eal=200000.0, currency="USD")
            actual_spend = sum(c.cost_usd for c in controls if c.control_id in res.selected_control_ids)
            assert actual_spend <= b + 1e-6, (
                f"Severe budget breach! spend {actual_spend} > budget {b} + 1e-6"
            )

    def test_adversarial_diminishing_marginal_returns_flat_steps_counterexample(self):
        """
        Adversarial Challenge 2: Pareto Diminishing Marginal Returns Slope Surge.
        Constructs a portfolio with lumpy controls:
        - Control A (cheap, low efficiency): cost $1,000, mitigation $100 (slope = 0.1)
        - Control B (expensive, high efficiency): cost $5,000, mitigation $4,000 (slope = 0.975)
        Intermediate parametric budget steps remain flat (d_spend == 0).
        Because frontier.py checks `d_spend_prev > 1.0 and d_spend_curr > 1.0` using i-1 vs i-2,
        the flat step causes d_spend_prev to be 0, skipping the slope comparison.
        Consequently, slope surges from 0.1 to 0.975, violating diminishing marginal returns.
        """
        controls = [
            SecurityControl(
                control_id="CHEAP_LOW_EFF",
                name="Cheap Low Eff",
                category="cat",
                cost_usd=1000.0,
                risk_reduction_usd=100.0,
                effectiveness=0.1,
            ),
            SecurityControl(
                control_id="EXP_HIGH_EFF",
                name="Exp High Eff",
                category="cat",
                cost_usd=5000.0,
                risk_reduction_usd=4000.0,
                effectiveness=0.9,
            ),
        ]
        res = generate_pareto_frontier(
            controls, baseline_eal=10000.0, max_budget=6000.0, step_count=10, currency="USD"
        )
        curve = res.curve

        # Empirically verify that the slope surges
        marginal_slopes = []
        for i in range(1, len(curve)):
            ds = curve[i].spend - curve[i - 1].spend
            dr = curve[i].risk_mitigated - curve[i - 1].risk_mitigated
            if ds > 1.0:
                marginal_slopes.append(dr / ds)

        # Confirm that diminishing marginal returns is strictly satisfied on remediated frontier
        has_slope_surge = any(
            marginal_slopes[j] > marginal_slopes[j - 1] + 1e-2
            for j in range(1, len(marginal_slopes))
        )
        assert not has_slope_surge, "Pareto frontier must satisfy diminishing marginal returns!"
        InvariantAssertions.assert_diminishing_returns(curve)

    def test_adversarial_circular_prerequisites_milp_co_requisite_bundling(self):
        """
        Adversarial Challenge 3: Circular Prerequisite Chains in MILP.
        Given a 2-cycle (A requires B, B requires A):
        MILP formulation encodes:
          x_A - x_B <= 0  (x_A <= x_B)
          x_B - x_A <= 0  (x_B <= x_A)
        Mathematically, this forces x_A == x_B.
        The MILP solver treats the cycle as an all-or-nothing co-dependent bundle:
        - If budget >= cost(A) + cost(B), both are selected.
        - If budget < cost(A) + cost(B), neither is selected.
        """
        solver = OptimizationSolver()
        cycle_controls = [
            SecurityControl(control_id="A", name="A", category="cat", cost_usd=2000.0, effectiveness=0.6, prerequisites=["B"]),
            SecurityControl(control_id="B", name="B", category="cat", cost_usd=3000.0, effectiveness=0.6, prerequisites=["A"]),
        ]

        # Budget enough for both (5000 total)
        res_high = solver.optimize(cycle_controls, budget=6000.0, baseline_eal=50000.0, currency="USD")
        assert set(res_high.selected_control_ids) == {"A", "B"}, "MILP should co-select circular pair when affordable"

        # Budget only enough for one (cannot separate)
        res_low = solver.optimize(cycle_controls, budget=3500.0, baseline_eal=50000.0, currency="USD")
        assert len(res_low.selected_control_ids) == 0, "MILP must not select partial circular chain"

    def test_adversarial_circular_prerequisites_divergence_in_quick_solve(self):
        """
        Adversarial Challenge 3B: Quick-Solve & Branch-and-Bound Deadlock on Circular Chains.
        While MILP co-selects {A, B}, greedy quick-solve (used in generate_pareto_frontier)
        and Branch-and-Bound deadlock because neither item can be added first.
        """
        cycle_controls = [
            SecurityControl(control_id="A", name="A", category="cat", cost_usd=100.0, risk_reduction_usd=500.0, effectiveness=0.5, prerequisites=["B"]),
            SecurityControl(control_id="B", name="B", category="cat", cost_usd=100.0, risk_reduction_usd=500.0, effectiveness=0.5, prerequisites=["A"]),
        ]
        # At budget 300 (where total cost is 200), quick-solve selects []
        res = generate_pareto_frontier(cycle_controls, baseline_eal=5000.0, max_budget=300.0, step_count=5, currency="USD")
        last_point = res.curve[-1]
        assert last_point.selected_control_ids == [], (
            f"Expected quick-solve deadlock on circular chain, got {last_point.selected_control_ids}"
        )

    def test_adversarial_mutual_exclusivity_cliques_sizes_3_5_10(self):
        """
        Adversarial Challenge 4: Cliques of Mutual Exclusivity.
        Under complete conflict graphs of size 3, 5, and 10, the optimizer must
        select at most 1 item from the clique, even with an infinite budget ($1 Billion).
        """
        solver = OptimizationSolver()
        for k in [3, 5, 10]:
            clique = [
                SecurityControl(
                    control_id=f"K{k}_C{i}",
                    name=f"Member {i}",
                    category="EDR",
                    cost_usd=float(1000 * (i + 1)),
                    effectiveness=0.4 + (0.05 * i),
                    conflicts=[f"K{k}_C{j}" for j in range(k) if j != i],
                )
                for i in range(k)
            ]
            res = solver.optimize(clique, budget=1e9, baseline_eal=100000.0, currency="USD")
            selected = [cid for cid in res.selected_control_ids if cid.startswith(f"K{k}_")]
            assert len(selected) <= 1, f"Clique size {k} violated! Selected multiple: {selected}"

    def test_adversarial_mandatory_controls_exceeding_budget(self):
        """
        Adversarial Challenge 5: Infeasible Mandatory Controls.
        When mandatory controls exceed budget:
        - M1 ($5,000) is mandatory. Budget is $3,000.
        Solver must not raise an exception, must not allocate spend > budget,
        and must maintain is_budget_satisfied=True.
        """
        solver = OptimizationSolver()
        mand_ctrl = SecurityControl(
            control_id="M1",
            name="Over-budget Mandatory",
            category="IAM",
            cost_usd=5000.0,
            effectiveness=0.9,
            is_mandatory=True,
        )
        res = solver.optimize([mand_ctrl], budget=3000.0, baseline_eal=20000.0, currency="USD")
        assert res.allocated_spend_usd <= 3000.0
        assert "M1" not in res.selected_control_ids
        assert res.is_budget_satisfied is True

    def test_adversarial_mandatory_control_with_expensive_prerequisite(self):
        """
        Adversarial Challenge 5B: Mandatory Control with Prerequisite Exceeding Budget.
        M1 ($2,000) is mandatory and requires P1 ($2,000). Total = $4,000.
        Budget is $3,000 (enough for M1 alone, but not M1 + P1).
        Solver must NOT select M1 without P1, and must NOT exceed budget.
        """
        solver = OptimizationSolver()
        controls = [
            SecurityControl(control_id="P1", name="Prereq", category="cat", cost_usd=2000.0, effectiveness=0.2, risk_reduction_usd=1000.0),
            SecurityControl(control_id="M1", name="Mandatory", category="cat", cost_usd=2000.0, effectiveness=0.9, risk_reduction_usd=5000.0, is_mandatory=True, prerequisites=["P1"]),
        ]
        res = solver.optimize(controls, budget=3000.0, baseline_eal=50000.0, currency="USD")
        assert res.allocated_spend_usd <= 3000.0
        assert "M1" not in res.selected_control_ids, "Prerequisite constraint breached under budget pressure!"

    def test_adversarial_branch_and_bound_topological_inversion_bug(self):
        """
        Adversarial Challenge 6: Topological Inversion in Branch-and-Bound Fallback.
        When child control has higher efficiency than parent prerequisite, B&B sorts
        the child first and prunes it because the parent is not yet in sel_ids.
        When child is marked mandatory, B&B explores 0 branches and returns empty selection.
        """
        solver = OptimizationSolver()
        controls = [
            SecurityControl(control_id="A", name="Child", category="cat", cost_usd=10.0, effectiveness=0.9, prerequisites=["B"], is_mandatory=True),
            SecurityControl(control_id="B", name="Parent", category="cat", cost_usd=10.0, effectiveness=0.1, prerequisites=[], is_mandatory=True),
        ]
        mitigations = np.array([100.0, 10.0])
        bb_res = solver.solve_branch_and_bound(
            controls, budget=50.0, baseline_eal=1000.0, mitigations=mitigations, mandatory_control_ids=["A", "B"]
        )
        # Fallback B&B with topological ordering selects both mandatory controls
        assert set(bb_res["selected_ids"]) == {"A", "B"}, (
            f"Expected B&B to select both mandatory controls ['A', 'B'], got {bb_res['selected_ids']}"
        )
        assert bb_res["spend"] == 20.0
        assert bb_res["mitigated"] == 110.0

    def test_adversarial_currency_hijacking_discontinuity_at_50k(self):
        """
        Adversarial Challenge 7: Currency Auto-Detection Hijacking at Budget > 50,000 USD.
        In solver.py:
          if currency is None and budget_val > 50000.0:
              currency_val = 'INR'
        When passing OptimizationRequest(currency='USD', budget=50001.0),
        currency keyword arg is None, causing the solver to silently flip currency to INR.
        This produces a catastrophic discontinuity:
        At $50,000 budget: selects USD control.
        At $50,001 budget: converts cost to INR (83.5x), exceeds budget, selects [].
        """
        solver = OptimizationSolver()
        c = SecurityControl(control_id="C1", name="C1", category="cat", cost_usd=10000.0, effectiveness=0.8)

        req_50k = OptimizationRequest(budget=50000.0, currency="USD", candidate_controls=[c], baseline_eal=500000.0)
        res_50k = solver.optimize(req_50k)
        assert res_50k.currency == "USD"
        assert res_50k.selected_control_ids == ["C1"]

        req_50001 = OptimizationRequest(budget=50001.0, currency="USD", candidate_controls=[c], baseline_eal=500000.0)
        res_50001 = solver.optimize(req_50001)
        # Currency must be honored as USD, selecting the affordable USD control
        assert res_50001.currency == "USD", f"Expected currency to remain USD, got {res_50001.currency}"
        assert res_50001.selected_control_ids == ["C1"], (
            f"Expected control C1 to be selected in USD, got {res_50001.selected_control_ids}"
        )
        assert res_50001.allocated_spend_usd == 10000.0

    def test_adversarial_extreme_scale_and_numerical_stability(self):
        """
        Adversarial Challenge 8: Extreme Numeric Scale & Boundary Values.
        Verifies behavior under $1 Quadrillion ($10^15) budget and baseline EAL,
        and ensures zero-cost controls and negative budgets do not crash.
        """
        solver = OptimizationSolver()
        extreme_controls = [
            SecurityControl(control_id="EX1", name="Mega Firewall", category="Net", cost_usd=1e12, effectiveness=0.8),
            SecurityControl(control_id="EX2", name="Free Patch", category="Vuln", cost_usd=0.0, effectiveness=0.1),
        ]
        # Extreme budget
        res_quad = solver.optimize(extreme_controls, budget=1e15, baseline_eal=1e14, currency="USD")
        assert "EX1" in res_quad.selected_control_ids
        assert res_quad.risk_mitigated_usd > 0.0
        assert not math.isnan(res_quad.portfolio_rosi)

        # Negative budget
        res_neg = solver.optimize(extreme_controls, budget=-1000.0, baseline_eal=10000.0, currency="USD")
        assert res_neg.allocated_spend_usd == 0.0
        assert len(res_neg.selected_controls) == 0
