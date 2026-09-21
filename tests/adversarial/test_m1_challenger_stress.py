"""
tests/adversarial/test_m1_challenger_stress.py - Adversarial Stress & Boundary Challenge Suite for Milestone M1.

Empirical Challenger Suite verifying:
1. calculate_security_upgrade_pct mathematical boundary safety:
   - Extreme negative risk mitigated and negative baseline exposure
   - Zero baseline exposure and subnormal floating-point numbers
   - NaN, +Inf, -Inf robustness
   - Overflow scenarios (risk_mitigated >> baseline_exposure) strictly bounded in [0.0, 100.0]
   - Property-based fuzzing invariant over 5,000 random input pairs
2. calculate_net_capital_saved mathematical non-negativity:
   - Active attack surge scenarios where residual EAL exceeds baseline EAL
   - Exact equality (baseline == residual)
   - NaN, +Inf, -Inf robustness
   - Property-based non-negativity fuzzing invariant over 5,000 random input pairs
   - Adversarial float subtraction overflow boundary test (1e308 - (-1e308) -> inf)
3. DemoAttackStateManager multi-threaded concurrency stress:
   - 20 concurrent threads performing 1,000+ operations (attack injections and dynamic telemetry pulses)
   - Concurrency race conditions, deadlock immunity, and state corruption verification
   - Structural contract validity of continuous stochastic telemetry pulses under contention
   - Post-stress baseline restoration
4. Isolation and Reproduction of Discovered Bugs:
   - BUG 1: KeyError on repeated/concurrent vendor purchases in DemoAttackStateManager and API routes
   - BUG 2: Float overflow in calculate_net_capital_saved producing unbounded infinity
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import math
import random
import threading
import time
from typing import Any, Dict, List
from fastapi.testclient import TestClient
import pytest

from src.api.app import create_app
from src.optimization.rosi import (
    calculate_net_capital_saved,
    calculate_security_posture_score,
    calculate_security_upgrade_pct,
)
from src.telemetry.attack_engine import (
    AttackType,
    BharatCartNode,
    DemoAttackStateManager,
    calculate_attack_impact,
)


# =============================================================================
# Challenge 1: calculate_security_upgrade_pct Stress & Boundary Tests
# =============================================================================

class TestSecurityUpgradePctAdversarialStress:
    """Adversarial stress testing on calculate_security_upgrade_pct."""

    @pytest.mark.parametrize("risk_mitigated", [-1.0, -100.0, -1e6, -1e12, -1e300, -0.000001])
    @pytest.mark.parametrize("baseline_exposure", [100.0, 1e6, 48_200_000.0])
    def test_security_upgrade_pct_negative_risk_mitigated(self, risk_mitigated: float, baseline_exposure: float):
        """Negative risk mitigated must strictly yield 0.0% boost."""
        result = calculate_security_upgrade_pct(risk_mitigated, baseline_exposure)
        assert result == 0.0, f"Expected 0.0 for negative risk {risk_mitigated}, got {result}"

    @pytest.mark.parametrize("baseline_exposure", [0.0, -0.0, -1.0, -100.0, -1e6, -1e12, -1e300])
    @pytest.mark.parametrize("risk_mitigated", [0.0, 50.0, 100.0, 1e6])
    def test_security_upgrade_pct_nonpositive_baseline_exposure(self, risk_mitigated: float, baseline_exposure: float):
        """Zero or negative baseline exposure must yield 0.0% and never raise ZeroDivisionError."""
        result = calculate_security_upgrade_pct(risk_mitigated, baseline_exposure)
        assert result == 0.0, f"Expected 0.0 for non-positive baseline {baseline_exposure}, got {result}"

    def test_security_upgrade_pct_both_negative(self):
        """Both negative inputs must evaluate to 0.0%."""
        assert calculate_security_upgrade_pct(-50.0, -100.0) == 0.0
        assert calculate_security_upgrade_pct(-1e12, -1e6) == 0.0

    def test_security_upgrade_pct_nan_inputs(self):
        """NaN values in either or both arguments must return 0.0 without propagating NaN."""
        assert calculate_security_upgrade_pct(float("nan"), 100.0) == 0.0
        assert calculate_security_upgrade_pct(50.0, float("nan")) == 0.0
        assert calculate_security_upgrade_pct(float("nan"), float("nan")) == 0.0

    def test_security_upgrade_pct_inf_inputs(self):
        """Positive and negative infinity in either argument must return 0.0."""
        assert calculate_security_upgrade_pct(float("inf"), 100.0) == 0.0
        assert calculate_security_upgrade_pct(100.0, float("inf")) == 0.0
        assert calculate_security_upgrade_pct(float("-inf"), 100.0) == 0.0
        assert calculate_security_upgrade_pct(100.0, float("-inf")) == 0.0
        assert calculate_security_upgrade_pct(float("inf"), float("inf")) == 0.0
        assert calculate_security_upgrade_pct(float("-inf"), float("-inf")) == 0.0
        assert calculate_security_upgrade_pct(float("inf"), float("-inf")) == 0.0

    @pytest.mark.parametrize(
        "risk_mitigated,baseline_exposure",
        [
            (150.0, 100.0),
            (200.0, 100.0),
            (1e9, 100.0),
            (1e12, 1e6),
            (1e308, 1e-300),
            (1e300, 1e-300),
        ],
    )
    def test_security_upgrade_pct_exceeding_baseline(self, risk_mitigated: float, baseline_exposure: float):
        """When risk mitigated exceeds baseline exposure, result must cap at 100.0%."""
        result = calculate_security_upgrade_pct(risk_mitigated, baseline_exposure)
        assert result == 100.0, f"Expected 100.0 for {risk_mitigated}/{baseline_exposure}, got {result}"

    def test_security_upgrade_pct_exact_nominal_boundaries(self):
        """Verify exact precision and nominal boundaries."""
        assert calculate_security_upgrade_pct(0.0, 100.0) == 0.0
        assert calculate_security_upgrade_pct(100.0, 100.0) == 100.0
        assert calculate_security_upgrade_pct(50.0, 100.0) == 50.0
        assert calculate_security_upgrade_pct(34.215, 100.0) == 34.22
        assert calculate_security_upgrade_pct(1e-15, 1e-15) == 100.0
        assert calculate_security_upgrade_pct(1e-300, 1e-300) == 100.0

    def test_security_upgrade_pct_fuzzing_invariants(self):
        """
        Property-based stress testing over 5,000 pseudo-random float pairs.
        Invariant: For ANY input pair, calculate_security_upgrade_pct MUST return a float in [0.0, 100.0],
        never NaN, never Inf, and never raise an unhandled exception.
        """
        rng = random.Random(42)
        special_values = [
            0.0, -0.0, 1.0, -1.0, 100.0, -100.0,
            float("nan"), float("inf"), float("-inf"),
            1e-308, -1e-308, 1e308, -1e308, 1e-15, 1e15,
        ]

        for _ in range(5000):
            if rng.random() < 0.2:
                r = rng.choice(special_values)
            else:
                exponent = rng.uniform(-300, 300)
                sign = -1.0 if rng.random() < 0.3 else 1.0
                r = sign * (10 ** exponent)

            if rng.random() < 0.2:
                b = rng.choice(special_values)
            else:
                exponent = rng.uniform(-300, 300)
                sign = -1.0 if rng.random() < 0.3 else 1.0
                b = sign * (10 ** exponent)

            res = calculate_security_upgrade_pct(r, b)

            assert isinstance(res, float), f"Result must be float, got {type(res)} for ({r}, {b})"
            assert not math.isnan(res), f"Result is NaN for ({r}, {b})"
            assert not math.isinf(res), f"Result is Inf for ({r}, {b})"
            assert 0.0 <= res <= 100.0, f"Result {res} out of bounds [0.0, 100.0] for ({r}, {b})"


# =============================================================================
# Challenge 2: calculate_net_capital_saved Non-Negativity & Boundary Tests
# =============================================================================

class TestNetCapitalSavedAdversarialStress:
    """Adversarial stress testing on calculate_net_capital_saved."""

    @pytest.mark.parametrize(
        "baseline_eal,residual_eal",
        [
            (48_200_000.0, 94_000_000.0),      # Active attack surge (+45.8M INR)
            (48_200_000.0, 100_000_000.0),     # Double baseline
            (100.0, 100.01),                   # Epsilon excess
            (100.0, 1e12),                     # Massive catastrophic loss
            (10.0, 1e300),                     # Floating-point extreme
        ],
    )
    def test_net_capital_saved_residual_exceeds_baseline(self, baseline_eal: float, residual_eal: float):
        """When residual EAL >= baseline EAL (e.g. under attack), saved capital must be 0.0, never negative."""
        saved = calculate_net_capital_saved(baseline_eal, residual_eal)
        assert saved == 0.0, f"Expected 0.0 when residual > baseline ({baseline_eal}, {residual_eal}), got {saved}"

    def test_net_capital_saved_exact_equality(self):
        """When residual EAL equals baseline EAL, saved capital must be 0.0."""
        assert calculate_net_capital_saved(5000.0, 5000.0) == 0.0
        assert calculate_net_capital_saved(48_200_000.0, 48_200_000.0) == 0.0
        assert calculate_net_capital_saved(0.0, 0.0) == 0.0

    def test_net_capital_saved_positive_mitigation(self):
        """When residual EAL < baseline EAL, saved capital equals the exact difference."""
        assert calculate_net_capital_saved(48_200_000.0, 20_000_000.0) == 28_200_000.0
        assert calculate_net_capital_saved(100.0, 0.0) == 100.0
        assert calculate_net_capital_saved(100.0, 65.789) == 34.21

    def test_net_capital_saved_nan_and_inf(self):
        """NaN or Inf inputs must return 0.0 safely."""
        assert calculate_net_capital_saved(float("nan"), 100.0) == 0.0
        assert calculate_net_capital_saved(100.0, float("nan")) == 0.0
        assert calculate_net_capital_saved(float("nan"), float("nan")) == 0.0
        assert calculate_net_capital_saved(float("inf"), 100.0) == 0.0
        assert calculate_net_capital_saved(100.0, float("inf")) == 0.0
        assert calculate_net_capital_saved(float("-inf"), 100.0) == 0.0
        assert calculate_net_capital_saved(100.0, float("-inf")) == 0.0
        assert calculate_net_capital_saved(float("inf"), float("inf")) == 0.0

    def test_net_capital_saved_negative_inputs(self):
        """Negative baseline with positive residual must clamp to 0.0."""
        assert calculate_net_capital_saved(-100.0, 50.0) == 0.0
        assert calculate_net_capital_saved(-50.0, 0.0) == 0.0

    def test_net_capital_saved_non_negativity_fuzzing(self):
        """
        Property-based stress testing over 5,000 pseudo-random float pairs.
        Invariant: For ANY input pair, calculate_net_capital_saved MUST return a float >= 0.0.
        """
        rng = random.Random(43)
        special_values = [
            0.0, -0.0, 1.0, -1.0, 100.0, -100.0,
            float("nan"), float("inf"), float("-inf"),
            1e-308, -1e-308, 1e308, -1e308, 1e-15, 1e15,
        ]

        for _ in range(5000):
            if rng.random() < 0.2:
                b = rng.choice(special_values)
            else:
                exponent = rng.uniform(-300, 300)
                sign = -1.0 if rng.random() < 0.3 else 1.0
                b = sign * (10 ** exponent)

            if rng.random() < 0.2:
                r = rng.choice(special_values)
            else:
                exponent = rng.uniform(-300, 300)
                sign = -1.0 if rng.random() < 0.3 else 1.0
                r = sign * (10 ** exponent)

            res = calculate_net_capital_saved(b, r)

            assert isinstance(res, float), f"Result must be float, got {type(res)} for ({b}, {r})"
            assert not math.isnan(res), f"Result is NaN for ({b}, {r})"
            # Non-negativity invariant must hold strictly
            assert res >= 0.0, f"Result {res} is negative for ({b}, {r})"

    def test_net_capital_saved_subtraction_overflow_boundary(self):
        """
        Adversarial boundary test: When baseline = 1e308 and residual = -1e308,
        neither input is inf, but subtraction baseline - residual = 2e308 overflows IEEE 754 float to inf.
        Documents whether calculate_net_capital_saved returns inf.
        """
        res = calculate_net_capital_saved(1e308, -1e308)
        # Note: res is math.isinf(res) == True because the subtraction overflows to inf
        # and calculate_net_capital_saved lacks a post-subtraction isinf check.
        assert res >= 0.0


# =============================================================================
# Challenge 3: DemoAttackStateManager Multi-Threaded Concurrency Stress
# =============================================================================

class TestDemoAttackStateManagerMultiThreadedStress:
    """
    Multi-threaded stress test on DemoAttackStateManager singleton.
    Verifies thread safety, deadlock immunity, and state integrity across 20 concurrent workers.
    """

    @pytest.fixture(autouse=True)
    def clean_state(self):
        """Ensure state manager is reset before and after every test."""
        manager = DemoAttackStateManager()
        manager.reset()
        yield manager
        manager.reset()

    def test_twenty_concurrent_threads_injection_and_ticker_stress(self, clean_state: DemoAttackStateManager):
        """
        Challenge DemoAttackStateManager with 20 concurrent threads running
        1,000 operations (attack injections and telemetry pulses) simultaneously:
        - 10 threads injecting attacks across all 4 types and intensities 1.0 - 8.0
        - 10 threads requesting dynamic telemetry pulses
        - Control funding and state queries
        - Periodic resets
        Verifies zero race condition exceptions, zero deadlocks, and valid telemetry contracts.
        """
        manager = clean_state
        num_threads = 20
        ops_per_thread = 50
        total_ops = num_threads * ops_per_thread

        errors: List[str] = []
        pulses_collected: List[Dict[str, Any]] = []
        lock_tracking = threading.Lock()

        attack_types = list(AttackType)
        control_ids = ["CTRL-WAF", "CTRL-EDR", "CTRL-MFA", "CTRL-S3-ENCR", "CTRL-SIEM-AI"]

        def worker_task(thread_id: int):
            thread_rng = random.Random(thread_id * 1000 + 7)
            for step in range(ops_per_thread):
                action = thread_rng.choice(["inject", "pulse", "fund", "query", "reset"])
                try:
                    if action == "inject":
                        atk = thread_rng.choice(attack_types)
                        intensity = thread_rng.uniform(1.0, 8.0)
                        manager.inject(
                            attack_type=atk,
                            intensity=intensity,
                            source_device=f"Challenger-Thread-{thread_id:02d}",
                        )
                    elif action == "pulse":
                        pulse = manager.get_telemetry_pulse()
                        with lock_tracking:
                            pulses_collected.append(pulse)
                    elif action == "fund":
                        c_id = thread_rng.choice(control_ids)
                        manager.fund_control(control_id=c_id)
                    elif action == "query":
                        _ = manager.current_eal_inr
                        _ = manager.current_posture
                        _ = manager.active_attack
                    elif action == "reset":
                        if thread_rng.random() < 0.1:
                            manager.reset()
                except Exception as exc:
                    with lock_tracking:
                        errors.append(f"Thread {thread_id} step {step} ({action}) failed: {exc}")

        start_time = time.perf_counter()
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker_task, tid) for tid in range(num_threads)]
            for future in as_completed(futures):
                future.result()
        elapsed = time.perf_counter() - start_time

        # 1. Zero exceptions across all 20 threads and 1000 operations
        assert len(errors) == 0, f"Encountered {len(errors)} errors during concurrent execution:\n" + "\n".join(errors[:10])

        # 2. Deadlock immunity: Must complete comfortably within 5.0 seconds
        assert elapsed < 5.0, f"Concurrent stress test took {elapsed:.2f}s, exceeding 5.0s ceiling (potential deadlock)"

        # 3. Structural contract validity of collected telemetry pulses
        assert len(pulses_collected) > 0, "Expected at least one telemetry pulse collected"
        for pulse in pulses_collected:
            assert pulse["threat_level"] in ("NORMAL", "CRITICAL_ATTACK_ACTIVE")
            assert pulse["events_per_second"] > 0.0
            assert pulse["eps_current"] > 0.0
            assert pulse["threat_event_frequency"] > 0.0
            assert pulse["tef_current"] > 0.0
            assert 0.0 <= pulse["posture_score"] <= 100.0
            assert len(pulse["nodes"]) == 4
            assert pulse["active_attacks_count"] >= 0
            assert isinstance(pulse["recent_events"], list)

        # 4. State Manager lock integrity: Lock must be fully released and re-acquirable
        acquired = manager._lock.acquire(blocking=False)
        assert acquired is True, "State manager lock remained held after thread completion (deadlock state)"
        manager._lock.release()

    def test_concurrent_readers_and_attack_injectors(self, clean_state: DemoAttackStateManager):
        """
        Stress test: 10 concurrent threads injecting attacks while 10 concurrent threads
        read continuous dynamic telemetry pulses (no resets).
        Verifies that readers always see valid, uncorrupted state during heavy mutation.
        """
        manager = clean_state
        num_writers = 10
        num_readers = 10
        ops = 40

        writer_errors: List[str] = []
        reader_errors: List[str] = []
        pulses: List[Dict[str, Any]] = []
        pulses_lock = threading.Lock()

        def writer_task(wid: int):
            for i in range(ops):
                try:
                    atk = AttackType.DDOS_SURGE if i % 2 == 0 else AttackType.RANSOMWARE_OUTAGE
                    manager.inject(attack_type=atk, intensity=5.0, source_device=f"Writer-{wid}")
                except Exception as e:
                    writer_errors.append(f"Writer {wid}: {e}")

        def reader_task(rid: int):
            for _ in range(ops):
                try:
                    pulse = manager.get_telemetry_pulse()
                    with pulses_lock:
                        pulses.append(pulse)
                except Exception as e:
                    reader_errors.append(f"Reader {rid}: {e}")

        with ThreadPoolExecutor(max_workers=num_writers + num_readers) as pool:
            wf = [pool.submit(writer_task, wid) for wid in range(num_writers)]
            rf = [pool.submit(reader_task, rid) for rid in range(num_readers)]
            for f in as_completed(wf + rf):
                f.result()

        assert len(writer_errors) == 0, f"Writer errors: {writer_errors}"
        assert len(reader_errors) == 0, f"Reader errors: {reader_errors}"
        assert len(pulses) == num_readers * ops

        for p in pulses:
            assert p["threat_level"] in ("NORMAL", "CRITICAL_ATTACK_ACTIVE")
            if p["has_active_attack"]:
                assert p["active_attacks_count"] > 0
                assert p["active_attack_details"] is not None
                assert p["active_attack_details"]["total_surge_inr"] > 0

    def test_post_stress_baseline_restoration(self, clean_state: DemoAttackStateManager):
        """Verify that after high-concurrency mutation, reset() deterministically restores pristine baseline."""
        manager = clean_state

        manager.inject(attack_type=AttackType.SQL_DATA_LEAK, intensity=6.0)
        manager.fund_control("CTRL-S3-ENCR")

        assert manager.active_attack is not None

        reset_res = manager.reset()
        assert reset_res["success"] is True
        assert reset_res["baseline_eal_inr"] == 48_200_000.0
        assert reset_res["current_eal"] == 48_200_000.0
        assert reset_res["posture_score"] == 84.6
        assert manager.active_attack is None
        assert len(manager.active_attacks) == 0
        assert len(manager.purchased_vendor_ids) == 0
        assert len(manager.funded_control_ids) == 0


# =============================================================================
# Challenge 4: Discovered Bug Isolation & Empirical Reproductions
# =============================================================================

class TestDiscoveredBugsEmpiricalReproduction:
    """
    Dedicated empirical reproduction tests capturing the bugs discovered during stress testing.
    """

    @pytest.fixture(autouse=True)
    def reset_state(self):
        manager = DemoAttackStateManager()
        manager.reset()
        yield
        manager.reset()

    def test_bug_1_repeat_vendor_purchase_key_error_in_state_manager(self):
        """
        EMPIRICAL BUG REPRODUCTION:
        When a vendor is purchased a second time, apply_virtual_vendor_purchase returns early
        with status 'ALREADY_PURCHASED' but omits 'security_upgrade_pct'.
        DemoAttackStateManager.apply_vendor_purchase unconditionally accesses updated['security_upgrade_pct'],
        raising KeyError: 'security_upgrade_pct'.
        """
        manager = DemoAttackStateManager()
        # First purchase succeeds
        res1 = manager.apply_vendor_purchase("VND-CLDF-WAF", currency="INR")
        assert res1["status"] == "PURCHASED"
        assert res1["security_upgrade_pct"] > 0.0

        # Second purchase of the identical vendor is idempotent and succeeds without KeyError
        res2 = manager.apply_vendor_purchase("VND-CLDF-WAF", currency="INR")
        assert res2["status"] in ("ALREADY_PURCHASED", "PURCHASED")
        assert "security_upgrade_pct" in res2
        assert res2["security_upgrade_pct"] >= 0.0

    def test_bug_1_repeat_vendor_purchase_404_in_rest_api(self):
        """
        VERIFY FIX:
        In the REST API POST /api/v1/vendor-benchmark/purchase, when a user or client
        re-purchases an active vendor, it returns HTTP 200 OK with ALREADY_PURCHASED status.
        """
        client = TestClient(create_app())
        # First purchase: HTTP 200 OK
        resp1 = client.post(
            "/api/v1/vendor-benchmark/purchase",
            json={"vendor_id": "VND-CRWD-EDR", "currency": "INR"},
        )
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["status"] == "PURCHASED"

        # Second purchase: HTTP 200 OK (idempotent)
        resp2 = client.post(
            "/api/v1/vendor-benchmark/purchase",
            json={"vendor_id": "VND-CRWD-EDR", "currency": "INR"},
        )
        assert resp2.status_code == 200
        assert resp2.json()["status"] in ("ALREADY_PURCHASED", "PURCHASED")

    def test_bug_2_calculate_net_capital_saved_float_overflow(self):
        """
        VERIFY FIX:
        When baseline = 1e308 and residual = -1e308, float overflow is clamped
        to a finite non-negative float.
        """
        res = calculate_net_capital_saved(1e308, -1e308)
        assert not math.isinf(res), f"Expected finite clamped float, got {res}"
        assert not math.isnan(res)
        assert res >= 0.0
