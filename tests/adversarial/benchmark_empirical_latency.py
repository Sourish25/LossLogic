"""
tests/adversarial/benchmark_empirical_latency.py
Challenger 1 Empirical Latency Benchmark Harness for Milestone 4 Iteration 3.

Empirically benchmarks OptimizationSolver single-point solve latency on 100-variable
enterprise portfolios under varying configurations and simulated background load.
"""

import gc
import json
import math
import random
import sys
import threading
import time
import unittest.mock as mock
from typing import Dict, List, Any
import numpy as np

from src.optimization.models import OptimizationRequest, SecurityControl
from src.optimization.solver import OptimizationSolver


def generate_portfolio(
    n: int = 100,
    dep_density: float = 0.10,
    conf_density: float = 0.05,
    mandatory_ratio: float = 0.05,
    seed: int = 42,
) -> List[SecurityControl]:
    rng = random.Random(seed)
    controls = []
    for i in range(n):
        cid = f"ENT-{i:03d}"
        cost = rng.uniform(2000.0, 50000.0)
        eff = rng.uniform(0.1, 0.95)
        prereqs = (
            [f"ENT-{p:03d}" for p in rng.sample(range(i), min(i, 2))]
            if i > 0 and rng.random() < dep_density
            else []
        )
        conflicts = (
            [f"ENT-{c:03d}" for c in rng.sample(range(i), min(i, 1))]
            if i > 0 and rng.random() < conf_density
            else []
        )
        is_mand = rng.random() < mandatory_ratio
        controls.append(
            SecurityControl(
                control_id=cid,
                name=f"Enterprise Defense {cid}",
                category=f"Domain-{i % 5}",
                cost_usd=cost,
                effectiveness=eff,
                prerequisites=prereqs,
                conflicts=conflicts,
                is_mandatory=is_mand,
            )
        )
    return controls


def compute_metrics(latencies: List[float]) -> Dict[str, float]:
    arr = np.array(latencies, dtype=np.float64)
    return {
        "count": len(arr),
        "min_ms": round(float(np.min(arr)), 3),
        "median_ms": round(float(np.median(arr)), 3),
        "mean_ms": round(float(np.mean(arr)), 3),
        "p90_ms": round(float(np.percentile(arr, 90)), 3),
        "p95_ms": round(float(np.percentile(arr, 95)), 3),
        "p99_ms": round(float(np.percentile(arr, 99)), 3),
        "max_ms": round(float(np.max(arr)), 3),
        "std_ms": round(float(np.std(arr)), 3),
    }


def cpu_stress_worker(stop_event: threading.Event):
    """Background thread to create realistic CPU load."""
    x = 1.000001
    while not stop_event.is_set():
        for _ in range(100000):
            x = math.sin(x) * math.cos(x) + 1.000001


def run_benchmarks():
    solver = OptimizationSolver()
    results = {}

    print("=" * 80)
    print("CHALLENGER 1: EMPIRICAL LATENCY BENCHMARK ON 100-VARIABLE PORTFOLIOS")
    print("=" * 80)

    # ---------------------------------------------------------
    # Benchmark 1: Standard Enterprise Portfolio (50 iterations)
    # ---------------------------------------------------------
    print("\n--- Running Benchmark 1: Standard Enterprise Portfolio (N=100) ---")
    controls = generate_portfolio(n=100, dep_density=0.10, conf_density=0.05, seed=1001)
    budget = sum(c.cost_usd for c in controls) * 0.30
    baseline_eal = budget * 3.0

    gc.collect()
    # Warmup
    for _ in range(5):
        solver.optimize(controls, budget=budget, baseline_eal=baseline_eal, include_frontier=False)

    latencies = []
    for _ in range(50):
        t0 = time.perf_counter()
        res = solver.optimize(controls, budget=budget, baseline_eal=baseline_eal, include_frontier=False)
        dt = (time.perf_counter() - t0) * 1000.0
        latencies.append(dt)
        assert res.is_budget_satisfied is True
        assert res.allocated_spend <= budget

    results["standard_enterprise_n100"] = compute_metrics(latencies)
    print("Results:", json.dumps(results["standard_enterprise_n100"], indent=2))

    # ---------------------------------------------------------
    # Benchmark 2: High Density Constraints (N=100, 25% deps, 15% confs)
    # ---------------------------------------------------------
    print("\n--- Running Benchmark 2: High Density Constraints (N=100) ---")
    controls_hd = generate_portfolio(n=100, dep_density=0.25, conf_density=0.15, mandatory_ratio=0.10, seed=2002)
    budget_hd = sum(c.cost_usd for c in controls_hd) * 0.40
    baseline_eal_hd = budget_hd * 2.5

    gc.collect()
    for _ in range(5):
        solver.optimize(controls_hd, budget=budget_hd, baseline_eal=baseline_eal_hd, include_frontier=False)

    latencies_hd = []
    for _ in range(50):
        t0 = time.perf_counter()
        res = solver.optimize(controls_hd, budget=budget_hd, baseline_eal=baseline_eal_hd, include_frontier=False)
        dt = (time.perf_counter() - t0) * 1000.0
        latencies_hd.append(dt)
        assert res.is_budget_satisfied is True

    results["high_density_n100"] = compute_metrics(latencies_hd)
    print("Results:", json.dumps(results["high_density_n100"], indent=2))

    # ---------------------------------------------------------
    # Benchmark 3: Budget Sensitivity (Tight 10% vs Loose 70%)
    # ---------------------------------------------------------
    print("\n--- Running Benchmark 3: Budget Sensitivity ---")
    for b_ratio, b_label in [(0.10, "tight_budget_10pct"), (0.70, "loose_budget_70pct")]:
        b = sum(c.cost_usd for c in controls) * b_ratio
        eal = b * 3.0
        gc.collect()
        for _ in range(5):
            solver.optimize(controls, budget=b, baseline_eal=eal, include_frontier=False)
        lats = []
        for _ in range(50):
            t0 = time.perf_counter()
            res = solver.optimize(controls, budget=b, baseline_eal=eal, include_frontier=False)
            dt = (time.perf_counter() - t0) * 1000.0
            lats.append(dt)
            assert res.is_budget_satisfied is True
        results[b_label] = compute_metrics(lats)
        print(f"Results ({b_label}):", json.dumps(results[b_label], indent=2))

    # ---------------------------------------------------------
    # Benchmark 4: OptimizationRequest DTO Default Path
    # ---------------------------------------------------------
    print("\n--- Running Benchmark 4: OptimizationRequest DTO Default Path ---")
    req = OptimizationRequest(
        budget=budget,
        currency="USD",
        candidate_controls=controls,
        baseline_eal=baseline_eal,
    )
    assert req.include_frontier is False

    gc.collect()
    for _ in range(5):
        solver.optimize(req)

    latencies_dto = []
    for _ in range(50):
        t0 = time.perf_counter()
        res = solver.optimize(req)
        dt = (time.perf_counter() - t0) * 1000.0
        latencies_dto.append(dt)
        assert res.is_budget_satisfied is True

    results["dto_default_path"] = compute_metrics(latencies_dto)
    print("Results:", json.dumps(results["dto_default_path"], indent=2))

    # ---------------------------------------------------------
    # Benchmark 5: Fallback Pure-Python Branch-and-Bound (HiGHS bypassed)
    # ---------------------------------------------------------
    print("\n--- Running Benchmark 5: Pure-Python Fallback B&B (N=100) ---")
    gc.collect()
    with mock.patch("src.optimization.solver.milp", side_effect=RuntimeError("HiGHS Bypassed")):
        for _ in range(5):
            solver.optimize(controls, budget=budget, baseline_eal=baseline_eal, include_frontier=False)
        latencies_bb = []
        for _ in range(50):
            t0 = time.perf_counter()
            res = solver.optimize(controls, budget=budget, baseline_eal=baseline_eal, include_frontier=False)
            dt = (time.perf_counter() - t0) * 1000.0
            latencies_bb.append(dt)
            assert res.solver_status == "fallback_branch_and_bound"
            assert res.is_budget_satisfied is True

    results["fallback_pure_python_n100"] = compute_metrics(latencies_bb)
    print("Results:", json.dumps(results["fallback_pure_python_n100"], indent=2))

    # ---------------------------------------------------------
    # Benchmark 6: Under Active Background System Load (CPU Contention)
    # ---------------------------------------------------------
    print("\n--- Running Benchmark 6: Under Background CPU Contention ---")
    stop_workers = threading.Event()
    num_threads = 3
    threads = [threading.Thread(target=cpu_stress_worker, args=(stop_workers,)) for _ in range(num_threads)]
    for th in threads:
        th.daemon = True
        th.start()

    time.sleep(0.1)  # Let threads spin up and saturate CPU

    latencies_load = []
    try:
        gc.collect()
        for _ in range(5):
            solver.optimize(controls, budget=budget, baseline_eal=baseline_eal, include_frontier=False)

        for _ in range(50):
            t0 = time.perf_counter()
            res = solver.optimize(controls, budget=budget, baseline_eal=baseline_eal, include_frontier=False)
            dt = (time.perf_counter() - t0) * 1000.0
            latencies_load.append(dt)
            assert res.is_budget_satisfied is True
    finally:
        stop_workers.set()
        for th in threads:
            th.join(timeout=1.0)

    results["under_cpu_contention_n100"] = compute_metrics(latencies_load)
    print("Results:", json.dumps(results["under_cpu_contention_n100"], indent=2))

    # ---------------------------------------------------------
    # Summary of SLA Compliance (< 15ms)
    # ---------------------------------------------------------
    print("\n" + "=" * 80)
    print("BENCHMARK SUMMARY & SLA VERIFICATION (< 15ms):")
    print("=" * 80)
    for name, m in results.items():
        median_pass = m["median_ms"] < 15.0
        min_pass = m["min_ms"] < 15.0
        p95_pass = m["p95_ms"] < 15.0
        print(
            f"{name:30s} | Min: {m['min_ms']:5.2f}ms | Median: {m['median_ms']:5.2f}ms | "
            f"P95: {m['p95_ms']:5.2f}ms | Max: {m['max_ms']:5.2f}ms | "
            f"Median < 15ms: {'PASS' if median_pass else 'FAIL'} | "
            f"Min < 15ms: {'PASS' if min_pass else 'FAIL'}"
        )

    return results


if __name__ == "__main__":
    run_benchmarks()
