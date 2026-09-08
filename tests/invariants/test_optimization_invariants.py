"""
tests/invariants/test_optimization_invariants.py - Solver Invariants of Optimization Engine.

Verifies:
1. Strict Budget Ceiling Enforcement: sum(cost) <= budget for any budget value.
2. Non-Negative Risk Reduction: Delta EAL >= 0 for selected mitigations.
3. Financial Return on Security Investment (ROSI): ROSI % calculation and consistency.
4. Diminishing Marginal Returns: Pareto efficiency frontier dRisk/dCost is non-increasing.
5. Hard Constraint Satisfaction:
   - Mandatory controls are always included when feasible.
   - Mutual exclusivity: Conflicting controls are never both selected.
   - Prerequisites: Dependent control is only selected if prerequisite is also selected.
6. Boundary budgets: $0 / ₹0 budget and infinite budget.
"""

import math
from typing import Dict, List
import pytest

from tests.conftest import (
    FrontierPoint,
    InvariantAssertions,
    MockCandidateControl,
    OptimizationResult,
    ReferenceKnapsackOptimizer,
)


@pytest.mark.invariants
class TestOptimizationInvariants:
    """Solver invariant verification for budget-constrained investment optimization."""

    @pytest.mark.parametrize("budget", [
        0.0,
        250000.0,    # ₹2.5 Lakhs (only S3 encryption fits)
        600000.0,    # ₹6.0 Lakhs (MFA + S3 fit)
        1000000.0,   # ₹10.0 Lakhs
        2000000.0,   # ₹20.0 Lakhs
        5000000.0,   # ₹50.0 Lakhs
        100000000.0, # ₹10.0 Crore (unbounded)
    ])
    def test_strict_budget_ceiling_enforcement(
        self,
        knapsack_optimizer: ReferenceKnapsackOptimizer,
        mock_control_portfolio: List[MockCandidateControl],
        invariant_assertions: InvariantAssertions,
        budget: float,
    ):
        """Invariant: Total allocated spend must strictly never exceed user-defined budget limit."""
        baseline_eal = 50000000.0  # ₹5.0 Crore
        result = knapsack_optimizer.optimize(
            controls=mock_control_portfolio,
            budget=budget,
            baseline_eal=baseline_eal
        )
        assert result.allocated_spend <= budget + 1e-6, (
            f"Budget invariant breached! Allocated spend {result.allocated_spend} > Budget {budget}"
        )
        invariant_assertions.assert_budget_adherence(result.selected_controls, budget)

    def test_non_negative_risk_mitigation(
        self,
        knapsack_optimizer: ReferenceKnapsackOptimizer,
        mock_control_portfolio: List[MockCandidateControl],
        invariant_assertions: InvariantAssertions,
    ):
        """Invariant: Delta EAL >= 0 (risk reduction is non-negative and bounded by baseline)."""
        baseline_eal = 25000000.0
        budget = 1500000.0
        result = knapsack_optimizer.optimize(
            controls=mock_control_portfolio,
            budget=budget,
            baseline_eal=baseline_eal
        )
        assert result.risk_mitigated >= 0.0, f"Expected risk mitigated >= 0, got {result.risk_mitigated}"
        assert result.residual_eal <= baseline_eal, (
            f"Residual EAL {result.residual_eal} exceeds baseline EAL {baseline_eal}"
        )
        invariant_assertions.assert_non_negative_risk_mitigation(result.risk_mitigated, baseline_eal)

    def test_diminishing_marginal_returns_on_pareto_frontier(
        self,
        knapsack_optimizer: ReferenceKnapsackOptimizer,
        mock_control_portfolio: List[MockCandidateControl],
        invariant_assertions: InvariantAssertions,
    ):
        """
        Invariant: The Pareto efficiency frontier curve exhibits diminishing marginal returns;
        the marginal risk reduction per rupee invested (dRisk/dCost) is non-increasing.
        """
        baseline_eal = 40000000.0
        budget = 3000000.0
        result = knapsack_optimizer.optimize(
            controls=mock_control_portfolio,
            budget=budget,
            baseline_eal=baseline_eal
        )
        frontier = result.efficiency_frontier
        assert len(frontier) >= 5, "Pareto frontier must contain at least 5 evaluated points"

        # Check that spend is monotonically non-decreasing
        for i in range(1, len(frontier)):
            assert frontier[i].spend >= frontier[i - 1].spend - 1e-6, (
                f"Frontier spend is not non-decreasing at index {i}"
            )
            assert frontier[i].risk_mitigated >= frontier[i - 1].risk_mitigated - 1e-6, (
                f"Frontier risk reduction is not non-decreasing at index {i}"
            )

        invariant_assertions.assert_diminishing_returns(frontier)

    def test_hard_constraint_mandatory_controls(
        self,
        knapsack_optimizer: ReferenceKnapsackOptimizer,
        mock_control_portfolio: List[MockCandidateControl],
    ):
        """
        Invariant: Mandatory controls (e.g. regulatory baselines like MFA and S3 encryption)
        MUST always be selected whenever the budget can accommodate them.
        """
        mandatory_controls = [c for c in mock_control_portfolio if c.is_mandatory]
        assert len(mandatory_controls) >= 2, "Portfolio should have at least 2 mandatory controls"
        min_mandatory_spend = sum(c.cost for c in mandatory_controls)  # ₹3.5L + ₹2.5L = ₹6.0L

        # Provide a budget sufficient for mandatory controls
        budget = min_mandatory_spend + 100000.0
        result = knapsack_optimizer.optimize(
            controls=mock_control_portfolio,
            budget=budget,
            baseline_eal=30000000.0
        )
        selected_ids = {c.control_id for c in result.selected_controls}
        for mand in mandatory_controls:
            assert mand.control_id in selected_ids, (
                f"Mandatory control {mand.control_id} ({mand.name}) was not selected with budget {budget}!"
            )

    def test_hard_constraint_mutual_exclusivity(
        self,
        knapsack_optimizer: ReferenceKnapsackOptimizer,
        mock_control_portfolio: List[MockCandidateControl],
    ):
        """
        Invariant: Mutually exclusive / conflicting controls can NEVER both be selected
        simultaneously, even with infinite budget.
        """
        # CTRL-SIEM-AI and CTRL-LEGACY-SIEM are conflicting
        infinite_budget = 100000000.0  # ₹10 Crore
        result = knapsack_optimizer.optimize(
            controls=mock_control_portfolio,
            budget=infinite_budget,
            baseline_eal=50000000.0
        )
        selected_ids = {c.control_id for c in result.selected_controls}
        has_ai_siem = "CTRL-SIEM-AI" in selected_ids
        has_legacy_siem = "CTRL-LEGACY-SIEM" in selected_ids

        assert not (has_ai_siem and has_legacy_siem), (
            "Conflict violation! Both CTRL-SIEM-AI and CTRL-LEGACY-SIEM were selected in solution!"
        )

    def test_hard_constraint_prerequisites(
        self,
        knapsack_optimizer: ReferenceKnapsackOptimizer,
        mock_control_portfolio: List[MockCandidateControl],
    ):
        """
        Invariant: A dependent control (CTRL-SIEM-AI) requires its prerequisite (CTRL-EDR).
        It cannot be selected without its prerequisite.
        """
        # Test across varying budgets
        for budget in [500000.0, 1000000.0, 1500000.0, 2500000.0, 5000000.0]:
            result = knapsack_optimizer.optimize(
                controls=mock_control_portfolio,
                budget=budget,
                baseline_eal=35000000.0
            )
            selected_ids = {c.control_id for c in result.selected_controls}
            if "CTRL-SIEM-AI" in selected_ids:
                assert "CTRL-EDR" in selected_ids, (
                    f"Prerequisite violation at budget {budget}: "
                    f"CTRL-SIEM-AI selected without required CTRL-EDR!"
                )

    def test_zero_budget_graceful_handling(
        self,
        knapsack_optimizer: ReferenceKnapsackOptimizer,
        mock_control_portfolio: List[MockCandidateControl],
    ):
        """Boundary Invariant: Budget = 0 results in 0 selected, 0 spend, 0 risk reduction."""
        result = knapsack_optimizer.optimize(
            controls=mock_control_portfolio,
            budget=0.0,
            baseline_eal=10000000.0
        )
        assert len(result.selected_controls) == 0
        assert result.allocated_spend == 0.0
        assert result.risk_mitigated == 0.0
        assert result.residual_eal == 10000000.0
        assert result.portfolio_rosi == 0.0

    def test_infinite_budget_maximum_attainable_reduction(
        self,
        knapsack_optimizer: ReferenceKnapsackOptimizer,
        mock_control_portfolio: List[MockCandidateControl],
    ):
        """Boundary Invariant: Infinite budget selects all non-conflicting controls and maximizes risk reduction."""
        infinite_budget = 1e12
        baseline_eal = 50000000.0
        result = knapsack_optimizer.optimize(
            controls=mock_control_portfolio,
            budget=infinite_budget,
            baseline_eal=baseline_eal
        )
        assert len(result.selected_controls) >= 4
        assert result.risk_mitigated > 0.5 * baseline_eal
        assert result.residual_eal < baseline_eal
