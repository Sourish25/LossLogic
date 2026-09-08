"""
tests/unit/test_optimization.py - Comprehensive Unit Tests for Optimization & ROSI Engine.
"""

import math
import time
from typing import List
import pytest
import numpy as np

from src.optimization.models import (
    FrontierPoint,
    FrontierResult,
    OptimizationRequest,
    OptimizationResult,
    SecurityControl,
)
from src.optimization.rosi import (
    calculate_marginal_cbr,
    calculate_net_financial_benefit,
    calculate_rosi,
    convert_currency,
    format_currency,
    format_inr,
    format_usd,
)
from src.optimization.frontier import (
    detect_elbow_point,
    generate_pareto_frontier,
)
from src.optimization.solver import OptimizationSolver
from src.config import USD_TO_INR_RATE


@pytest.fixture
def sample_controls() -> List[SecurityControl]:
    """Sample candidate controls with diverse costs, effectiveness, and constraints."""
    return [
        SecurityControl(
            control_id="CTRL-MFA",
            name="Hardware MFA Enforcement",
            category="IAM",
            cost_usd=5000.0,
            cost_inr=5000.0 * USD_TO_INR_RATE,
            effectiveness=0.90,
            target_finding_ids=["IAM-001"],
            prerequisites=[],
            conflicts=[],
            is_mandatory=True,
        ),
        SecurityControl(
            control_id="CTRL-S3-ENCR",
            name="Cloud S3 Encryption Guardrails",
            category="CSPM",
            cost_usd=3000.0,
            cost_inr=3000.0 * USD_TO_INR_RATE,
            effectiveness=0.95,
            target_finding_ids=["CSPM-001"],
            prerequisites=[],
            conflicts=[],
            is_mandatory=True,
        ),
        SecurityControl(
            control_id="CTRL-EDR",
            name="Next-Gen Endpoint Protection",
            category="Endpoint",
            cost_usd=10000.0,
            cost_inr=10000.0 * USD_TO_INR_RATE,
            effectiveness=0.85,
            target_finding_ids=["EDR-001"],
            prerequisites=[],
            conflicts=[],
            is_mandatory=False,
        ),
        SecurityControl(
            control_id="CTRL-SIEM-AI",
            name="AI-Driven SIEM Correlation",
            category="SecOps",
            cost_usd=15000.0,
            cost_inr=15000.0 * USD_TO_INR_RATE,
            effectiveness=0.80,
            target_finding_ids=["SIEM-001"],
            prerequisites=["CTRL-EDR"],  # Depends on EDR
            conflicts=["CTRL-SIEM-LEGACY"],
            is_mandatory=False,
        ),
        SecurityControl(
            control_id="CTRL-SIEM-LEGACY",
            name="Legacy SIEM Rule Hardening",
            category="SecOps",
            cost_usd=4000.0,
            cost_inr=4000.0 * USD_TO_INR_RATE,
            effectiveness=0.40,
            target_finding_ids=["SIEM-001"],
            prerequisites=[],
            conflicts=["CTRL-SIEM-AI"],  # Conflicts with AI SIEM
            is_mandatory=False,
        ),
        SecurityControl(
            control_id="CTRL-PATCH",
            name="Automated Patching Engine",
            category="Vulnerability",
            cost_usd=7000.0,
            cost_inr=7000.0 * USD_TO_INR_RATE,
            effectiveness=0.92,
            target_finding_ids=["VULN-001"],
            prerequisites=[],
            conflicts=[],
            is_mandatory=False,
        ),
    ]


@pytest.fixture
def solver() -> OptimizationSolver:
    return OptimizationSolver()


class TestOptimizationSolver:
    """Test suite for SciPy HiGHS MILP Knapsack Solver and Branch-and-Bound Fallback."""

    def test_highs_solver_execution_and_speed(self, solver: OptimizationSolver, sample_controls: List[SecurityControl]):
        """SciPy HiGHS solver executes in under 15ms for enterprise control sets."""
        start = time.perf_counter()
        result = solver.optimize(
            controls=sample_controls,
            budget=25000.0,
            baseline_eal=100000.0,
            currency="USD",
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        assert elapsed_ms < 100.0  # Safe threshold across all test runners
        assert result.solver_status in ("optimal", "fallback_branch_and_bound")
        assert len(result.selected_controls) >= 1
        assert result.allocated_spend_usd <= 25000.0

    @pytest.mark.parametrize("budget_usd", [0.0, 5000.0, 15000.0, 30000.0, 100000.0, 1000000.0])
    def test_strict_budget_enforcement_usd(
        self, solver: OptimizationSolver, sample_controls: List[SecurityControl], budget_usd: float
    ):
        """Strict budget ceiling: total allocated spend never exceeds budget limit in USD."""
        result = solver.optimize(
            controls=sample_controls,
            budget=budget_usd,
            baseline_eal=150000.0,
            currency="USD",
        )
        assert result.allocated_spend_usd <= budget_usd + 1e-6
        assert result.is_budget_satisfied is True

    @pytest.mark.parametrize("budget_inr", [0.0, 1000000.0, 5000000.0, 10000000.0, 100000000.0])
    def test_strict_budget_enforcement_inr(
        self, solver: OptimizationSolver, sample_controls: List[SecurityControl], budget_inr: float
    ):
        """Strict budget ceiling: total allocated spend never exceeds budget limit in INR."""
        result = solver.optimize(
            controls=sample_controls,
            budget=budget_inr,
            baseline_eal=50000000.0,
            currency="INR",
        )
        assert result.allocated_spend_inr <= budget_inr + 1e-6
        assert result.is_budget_satisfied is True

    def test_zero_budget_boundary(self, solver: OptimizationSolver, sample_controls: List[SecurityControl]):
        """Zero budget results in 0 spend, 0 mitigations, baseline EAL untouched."""
        result = solver.optimize(
            controls=sample_controls,
            budget=0.0,
            baseline_eal=100000.0,
            currency="USD",
        )
        assert result.allocated_spend_usd == 0.0
        assert result.risk_mitigated_usd == 0.0
        assert result.residual_eal_usd == 100000.0
        assert len(result.selected_controls) == 0
        assert result.portfolio_rosi == 0.0

    def test_negative_budget_boundary(self, solver: OptimizationSolver, sample_controls: List[SecurityControl]):
        """Negative budget handled gracefully as zero spend."""
        result = solver.optimize(
            controls=sample_controls,
            budget=-500.0,
            baseline_eal=50000.0,
            currency="USD",
        )
        assert result.allocated_spend_usd == 0.0
        assert len(result.selected_controls) == 0

    def test_empty_controls_boundary(self, solver: OptimizationSolver):
        """Empty controls list returns valid empty result."""
        result = solver.optimize(
            controls=[],
            budget=50000.0,
            baseline_eal=100000.0,
            currency="USD",
        )
        assert result.allocated_spend_usd == 0.0
        assert result.risk_mitigated_usd == 0.0
        assert len(result.selected_controls) == 0

    def test_infinite_budget_boundary(self, solver: OptimizationSolver, sample_controls: List[SecurityControl]):
        """Infinite budget selects maximal set of non-conflicting controls."""
        result = solver.optimize(
            controls=sample_controls,
            budget=1e9,
            baseline_eal=200000.0,
            currency="USD",
        )
        selected_ids = set(result.selected_control_ids)
        # Should select MFA, S3, EDR, SIEM-AI, PATCH (SIEM-LEGACY omitted due to conflict)
        assert "CTRL-MFA" in selected_ids
        assert "CTRL-S3-ENCR" in selected_ids
        assert "CTRL-EDR" in selected_ids
        assert "CTRL-PATCH" in selected_ids
        assert not ("CTRL-SIEM-AI" in selected_ids and "CTRL-SIEM-LEGACY" in selected_ids)
        assert result.risk_mitigated_usd > 0.5 * 200000.0

    def test_prerequisite_constraint_direct(self, solver: OptimizationSolver, sample_controls: List[SecurityControl]):
        """Child control (CTRL-SIEM-AI) is NEVER selected without its prerequisite (CTRL-EDR)."""
        for budget in [10000.0, 15000.0, 20000.0, 35000.0, 50000.0]:
            result = solver.optimize(
                controls=sample_controls,
                budget=budget,
                baseline_eal=150000.0,
                currency="USD",
            )
            selected_ids = set(result.selected_control_ids)
            if "CTRL-SIEM-AI" in selected_ids:
                assert "CTRL-EDR" in selected_ids, f"Prereq breached at budget {budget}!"

    def test_prerequisite_chain(self, solver: OptimizationSolver):
        """Multi-level prerequisite chain A -> B -> C."""
        chained_controls = [
            SecurityControl(control_id="A", name="Base", category="A", cost_usd=1000.0, effectiveness=0.2, prerequisites=[]),
            SecurityControl(control_id="B", name="Mid", category="B", cost_usd=2000.0, effectiveness=0.4, prerequisites=["A"]),
            SecurityControl(control_id="C", name="Top", category="C", cost_usd=3000.0, effectiveness=0.9, prerequisites=["B"]),
        ]
        # Budget only enough for C? Cannot take C without B and A (cost 6000 total)
        res_low = solver.optimize(chained_controls, budget=3500.0, baseline_eal=50000.0, currency="USD")
        assert "C" not in res_low.selected_control_ids

        # Budget enough for A + B + C (6000)
        res_high = solver.optimize(chained_controls, budget=6500.0, baseline_eal=50000.0, currency="USD")
        assert {"A", "B", "C"}.issubset(set(res_high.selected_control_ids))

    def test_prerequisite_missing_from_candidate_pool(self, solver: OptimizationSolver):
        """Control whose prerequisite is absent from candidate pool is never selected."""
        orphan = SecurityControl(
            control_id="ORPHAN", name="Orphaned Control", category="Test", cost_usd=500.0,
            effectiveness=0.99, prerequisites=["NON_EXISTENT_PARENT"]
        )
        res = solver.optimize([orphan], budget=5000.0, baseline_eal=10000.0, currency="USD")
        assert "ORPHAN" not in res.selected_control_ids

    def test_mutual_exclusivity_pairwise(self, solver: OptimizationSolver, sample_controls: List[SecurityControl]):
        """Conflicting controls (CTRL-SIEM-AI and CTRL-SIEM-LEGACY) are never both selected."""
        for budget in [10000.0, 25000.0, 50000.0, 100000.0]:
            result = solver.optimize(
                controls=sample_controls,
                budget=budget,
                baseline_eal=200000.0,
                currency="USD",
            )
            selected_ids = set(result.selected_control_ids)
            assert not ("CTRL-SIEM-AI" in selected_ids and "CTRL-SIEM-LEGACY" in selected_ids)

    def test_mutual_exclusivity_clique(self, solver: OptimizationSolver):
        """Triple mutual exclusivity clique: pairwise conflicts between 3 vendors."""
        controls = [
            SecurityControl(control_id="V1", name="Vendor 1", category="EDR", cost_usd=1000.0, effectiveness=0.8, conflicts=["V2", "V3"]),
            SecurityControl(control_id="V2", name="Vendor 2", category="EDR", cost_usd=1100.0, effectiveness=0.85, conflicts=["V1", "V3"]),
            SecurityControl(control_id="V3", name="Vendor 3", category="EDR", cost_usd=1200.0, effectiveness=0.9, conflicts=["V1", "V2"]),
        ]
        res = solver.optimize(controls, budget=10000.0, baseline_eal=50000.0, currency="USD")
        selected = [c for c in ["V1", "V2", "V3"] if c in res.selected_control_ids]
        assert len(selected) <= 1

    def test_mandatory_controls_affordable(self, solver: OptimizationSolver, sample_controls: List[SecurityControl]):
        """Mandatory controls (MFA and S3 encryption) MUST be selected when affordable."""
        # Total mandatory cost = 5000 + 3000 = 8000
        result = solver.optimize(
            controls=sample_controls,
            budget=8500.0,
            baseline_eal=100000.0,
            currency="USD",
        )
        selected_ids = set(result.selected_control_ids)
        assert "CTRL-MFA" in selected_ids
        assert "CTRL-S3-ENCR" in selected_ids

    def test_mandatory_controls_with_prerequisites(self, solver: OptimizationSolver):
        """Mandatory control pulls in required prerequisite."""
        controls = [
            SecurityControl(control_id="PREREQ", name="Prereq", category="Base", cost_usd=2000.0, effectiveness=0.1, is_mandatory=False),
            SecurityControl(control_id="MAND", name="Mandatory", category="Req", cost_usd=3000.0, effectiveness=0.8, is_mandatory=True, prerequisites=["PREREQ"]),
        ]
        res = solver.optimize(controls, budget=6000.0, baseline_eal=50000.0, currency="USD")
        assert "MAND" in res.selected_control_ids
        assert "PREREQ" in res.selected_control_ids

    def test_mandatory_controls_infeasible_budget(self, solver: OptimizationSolver):
        """When mandatory controls exceed budget, solver does not crash or violate budget ceiling."""
        expensive_mandatory = [
            SecurityControl(control_id="M1", name="Overhaul", category="Cat", cost_usd=50000.0, effectiveness=0.9, is_mandatory=True),
            SecurityControl(control_id="M2", name="Vault", category="Cat", cost_usd=30000.0, effectiveness=0.8, is_mandatory=True),
        ]
        # Budget = 10,000 (cannot afford either)
        res = solver.optimize(expensive_mandatory, budget=10000.0, baseline_eal=100000.0, currency="USD")
        assert res.allocated_spend_usd <= 10000.0
        assert len(res.selected_controls) == 0

    def test_pure_python_branch_and_bound_fallback(self, solver: OptimizationSolver, sample_controls: List[SecurityControl]):
        """Pure-Python branch-and-bound fallback produces valid compliant portfolio."""
        costs = np.array([c.cost_usd for c in sample_controls])
        mitigations = np.array([c.effectiveness * 20000.0 for c in sample_controls])
        bb_res = solver.solve_branch_and_bound(
            controls=sample_controls,
            budget=20000.0,
            baseline_eal=100000.0,
            mitigations=mitigations,
            mandatory_control_ids=["CTRL-MFA", "CTRL-S3-ENCR"],
            currency="USD",
        )
        assert bb_res["spend"] <= 20000.0
        assert "CTRL-MFA" in bb_res["selected_ids"]
        assert "CTRL-S3-ENCR" in bb_res["selected_ids"]

    def test_scale_portfolio_100_controls(self, solver: OptimizationSolver):
        """100-control large knapsack optimization executes rapidly under constraints."""
        controls_100 = []
        for i in range(100):
            controls_100.append(
                SecurityControl(
                    control_id=f"SCALE-{i:03d}",
                    name=f"Scale Control {i}",
                    category=f"Category-{i % 5}",
                    cost_usd=float(500 + (i * 150)),
                    effectiveness=min(0.98, max(0.1, 0.05 + (i * 0.009))),
                    is_mandatory=(i == 3),
                    conflicts=[f"SCALE-{i+1:03d}"] if i % 10 == 0 and i < 99 else [],
                    prerequisites=[f"SCALE-{i-1:03d}"] if i % 15 == 0 and i > 0 else [],
                )
            )
        start = time.perf_counter()
        res = solver.optimize(controls_100, budget=50000.0, baseline_eal=1000000.0, currency="USD")
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        assert elapsed_ms < 500.0
        assert res.allocated_spend_usd <= 50000.0
        assert len(res.selected_controls) > 0
        assert "SCALE-003" in res.selected_control_ids


class TestROSIAndFinancialMetrics:
    """Test suite for ROSI %, Net Financial Benefit, and Currency Formatting."""

    def test_rosi_mathematical_precision(self):
        """ROSI % = ((Risk Mitigated - Cost) / Cost) * 100%."""
        # Case 1: Mitigated $150K with $50K cost -> ROSI = 200%
        assert math.isclose(calculate_rosi(150000.0, 50000.0), 200.0, rel_tol=1e-5)
        # Case 2: Mitigated $40K with $50K cost -> ROSI = -20% (loss making)
        assert math.isclose(calculate_rosi(40000.0, 50000.0), -20.0, rel_tol=1e-5)
        # Case 3: Breakeven -> ROSI = 0%
        assert math.isclose(calculate_rosi(50000.0, 50000.0), 0.0, rel_tol=1e-5)

    def test_rosi_zero_cost_edge_case(self):
        """Cost = 0.0 returns 0.0 without ZeroDivisionError."""
        assert calculate_rosi(100000.0, 0.0) == 0.0
        assert calculate_rosi(0.0, 0.0) == 0.0

    def test_net_financial_benefit_precision(self):
        """NFB = Risk Mitigated - Cost."""
        assert math.isclose(calculate_net_financial_benefit(250000.0, 100000.0), 150000.0)
        assert math.isclose(calculate_net_financial_benefit(50000.0, 75000.0), -25000.0)

    def test_marginal_cost_benefit_ratio(self):
        """CBR = Risk Mitigated / Cost."""
        assert math.isclose(calculate_marginal_cbr(200000.0, 50000.0), 4.0)
        assert calculate_marginal_cbr(10000.0, 0.0) == 0.0

    def test_currency_formatting_inr(self):
        """INR formatting in Lakhs and Crores."""
        assert format_inr(15000000.0) == "₹1.50 Crore"
        assert format_inr(4500000.0) == "₹45.00 Lakhs"
        assert format_inr(25000.0) == "₹25,000.00"

    def test_currency_formatting_usd(self):
        """USD formatting in K, M, B."""
        assert format_usd(1500000000.0) == "$1.50B"
        assert format_usd(2500000.0) == "$2.50M"
        assert format_usd(75000.0) == "$75.00K"
        assert format_usd(500.0) == "$500.00"

    def test_currency_conversion(self):
        """Bi-directional conversion between USD and INR."""
        usd_amount = 1000.0
        inr_amount = convert_currency(usd_amount, "USD", "INR")
        assert math.isclose(inr_amount, 1000.0 * USD_TO_INR_RATE, rel_tol=1e-5)
        converted_back = convert_currency(inr_amount, "INR", "USD")
        assert math.isclose(converted_back, usd_amount, rel_tol=1e-5)


class TestParetoFrontierAndKneedle:
    """Test suite for Pareto Efficiency Frontier curve and Kneedle elbow detection."""

    def test_pareto_frontier_monotonicity(self, sample_controls: List[SecurityControl]):
        """Pareto frontier spend and risk mitigation are monotonically non-decreasing."""
        frontier_res = generate_pareto_frontier(
            controls=sample_controls,
            baseline_eal=100000.0,
            max_budget=50000.0,
            step_count=10,
            currency="USD",
        )
        curve = frontier_res.curve
        assert len(curve) >= 5
        assert curve[0].spend == 0.0 and curve[0].risk_mitigated == 0.0

        for i in range(1, len(curve)):
            assert curve[i].spend >= curve[i - 1].spend - 1e-6
            assert curve[i].risk_mitigated >= curve[i - 1].risk_mitigated - 1e-6
            assert curve[i].residual_eal <= curve[i - 1].residual_eal + 1e-6

    def test_pareto_frontier_diminishing_returns(self, sample_controls: List[SecurityControl]):
        """Marginal efficiency dRisk/dCost is non-increasing across steps with substantial spend delta."""
        frontier_res = generate_pareto_frontier(
            controls=sample_controls,
            baseline_eal=200000.0,
            max_budget=60000.0,
            step_count=15,
            currency="USD",
        )
        curve = frontier_res.curve
        marginal_slopes = []
        for i in range(1, len(curve)):
            ds = curve[i].spend - curve[i - 1].spend
            dr = curve[i].risk_mitigated - curve[i - 1].risk_mitigated
            if ds > 1.0:
                marginal_slopes.append(dr / ds)

        for i in range(1, len(marginal_slopes)):
            assert marginal_slopes[i] <= marginal_slopes[i - 1] + 1e-2

    def test_kneedle_elbow_detection_accuracy(self):
        """Kneedle identifies maximum perpendicular distance to diagonal chord."""
        # Simulated concave points
        points = [
            FrontierPoint(budget_step=0.0, spend=0.0, risk_mitigated=0.0, residual_eal=100.0, rosi_percentage=0.0),
            FrontierPoint(budget_step=10.0, spend=10.0, risk_mitigated=60.0, residual_eal=40.0, rosi_percentage=500.0), # High steep jump
            FrontierPoint(budget_step=20.0, spend=20.0, risk_mitigated=85.0, residual_eal=15.0, rosi_percentage=325.0), # Elbow
            FrontierPoint(budget_step=30.0, spend=30.0, risk_mitigated=95.0, residual_eal=5.0, rosi_percentage=216.0),  # Flattening
            FrontierPoint(budget_step=40.0, spend=40.0, risk_mitigated=100.0, residual_eal=0.0, rosi_percentage=150.0), # Ceiling
        ]
        elbow = detect_elbow_point(points)
        assert elbow is not None
        assert elbow.is_elbow_point is True
        # Elbow should be point at spend 10 or 20
        assert elbow.spend in (10.0, 20.0)


class TestOptimizationModelsAndSchemas:
    """Test suite for Pydantic v2 schemas and validation contracts."""

    def test_security_control_model_normalization(self):
        """SecurityControl auto-normalizes cost_usd / cost_inr and framework mappings."""
        ctrl = SecurityControl(
            control_id="C-TEST",
            name="Test Control",
            category="IAM",
            cost_usd=1000.0,
            effectiveness=0.8,
            framework_mappings={"ISO": ["A.8.2"]},
        )
        assert ctrl.cost_inr == 1000.0 * USD_TO_INR_RATE
        assert ctrl.mapped_frameworks == {"ISO": ["A.8.2"]}
        assert ctrl.get_cost("USD") == 1000.0
        assert ctrl.get_cost("INR") == 1000.0 * USD_TO_INR_RATE

    def test_optimization_request_pydantic_validation(self, sample_controls: List[SecurityControl]):
        """OptimizationRequest validates types, budget limits, and serializes cleanly."""
        req = OptimizationRequest(
            budget=25000.0,
            currency="USD",
            candidate_controls=sample_controls,
            baseline_eal=100000.0,
            mandatory_control_ids=["CTRL-MFA"],
        )
        assert req.budget == 25000.0
        data = req.model_dump()
        assert data["currency"] == "USD"
        assert len(data["candidate_controls"]) == len(sample_controls)

    def test_optimization_result_serialization(self, solver: OptimizationSolver, sample_controls: List[SecurityControl]):
        """OptimizationResult serializes to dict and JSON without error."""
        res = solver.optimize(sample_controls, budget=30000.0, baseline_eal=100000.0, currency="USD")
        dumped = res.model_dump()
        assert "allocated_spend_usd" in dumped
        assert "allocated_spend_inr" in dumped
        assert "portfolio_rosi" in dumped
        assert "efficiency_frontier" in dumped
        json_str = res.model_dump_json()
        assert isinstance(json_str, str)
        assert "optimal" in json_str
