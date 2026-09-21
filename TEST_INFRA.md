# LossLogic Test Infrastructure Specification (TEST_INFRA.md)
## 4-Tier Opaque-Box Test Architecture for Hackathon Live Capabilities (R1–R6)

**Target Platform:** LossLogic Enterprise Cyber Risk Quantification & Investment Optimization Platform  
**Version:** 1.0.0-PROD  
**Author:** E2E Test Suite Designer & Writer (`e2e_test_writer`)  
**Specification Reference:** `ORIGINAL_REQUEST.md`, `PROJECT.md`, `survey_spec_report.md`  

---

## 1. Executive Summary & Testing Philosophy

LossLogic bridges the fundamental communication chasm between technical SecOps telemetry and executive fiduciary decision-making through rigorous actuarial quantification (FAIR Monte Carlo simulation) and mathematical capital allocation (SciPy HiGHS MILP 0/1 knapsack solver). 

For the Live Jury Hackathon Demonstration, five mission-critical capabilities (R1 through R5) and an invariant-preserving verification track (R6) have been added:
1. **R1: Live Virtual Investment Impact Visualizer & Security Factor Gauge** (<50ms latency, dual-currency ₹/$ side-by-side exposure and Net Capital Saved).
2. **R2: Future Problem-Solving Capabilities & Multi-Threat Immunity Matrix** (5 canonical threat vectors, structured `future_threat_shields`, and protective mechanisms).
3. **R3: Live E-Commerce ("BharatCart") Multi-Device Attack Injection & Dynamic Telemetry** (unauthenticated `POST /api/v1/demo/inject-attack`, TEF/EAL surges, posture degradation, and continuous background telemetry ticker).
4. **R4: Explicit Security Upgrade Percentage (+X.X% Protection Boost)** (bounded in $[0.0\%, 100.0\%]$, monotonic scaling, zero-division safeguard).
5. **R5: Executive CEO Vendor Benchmarking & Product Comparison Matrix** (CrowdStrike, Microsoft, Cloudflare, Okta, Wiz with 1-click virtual purchase updating risk posture).
6. **R6: Automated Test Suite & Invariant Preservation** (preservation of 414 baseline tests, positive EAL $> 0$, strict Value-at-Risk ordering $\text{VaR}_{90} < \text{VaR}_{95} < \text{VaR}_{99}$, zero-tolerance budget ceilings, diminishing marginal returns).

### 1.1 Opaque-Box, Requirement-Driven Methodology
The testing infrastructure operates on strict **opaque-box principles**:
- Tests assert against **published interface contracts, mathematical invariants, and observable behavioral outputs** (HTTP status codes, response schemas, latency bounds, and numerical properties).
- Tests do not bind to private internal state or transient implementation details.
- Every expected output is derived from authoritative requirements in `ORIGINAL_REQUEST.md` and `PROJECT.md`.
- **Progressive Testability**: Tests provide authoritative reference models as fallbacks so test suites execute reliably across all implementation stages while testing live endpoints and modules when loaded.

---

## 2. 4-Tier Test Architecture

The test suite is structured into four distinct, hierarchically escalating tiers:

```
┌────────────────────────────────────────────────────────────────────────┐
│               Tier 4: Real-World Application Scenarios                 │
│      (BharatCart Multi-Device Attack Injection & Active Mitigation)     │
├────────────────────────────────────────────────────────────────────────┤
│             Tier 3: Cross-Feature Combinations (Pairwise)              │
│       (Attack Surge + Virtual Purchase, Slider + Dynamic Ticker)       │
├────────────────────────────────────────────────────────────────────────┤
│             Tier 2: Boundary, Extreme & Corner Cases                   │
│   (₹0/Infinite Budget, Zero Baseline Exposure, Saturation, Max Clamps) │
├────────────────────────────────────────────────────────────────────────┤
│             Tier 1: Isolated Feature Coverage (>=5 per R)              │
│   (R1: Visualizer, R2: Threat Shields, R3: Injections, R4: SUP %, ...) │
└────────────────────────────────────────────────────────────────────────┘
```

### Tier 1: Isolated Feature Coverage ($\ge 5$ tests per feature)
- **Objective:** Exhaustively test each requirement R1 through R6 in isolation.
- **Coverage Criteria:**
  - Minimum 5 distinct test cases / assertions for each requirement (R1, R2, R3, R4, R5, R6), totaling $\ge 30$ Tier 1 test cases.
  - Verification of nominal happy paths, schema validity, field types, default states, and standard calculations.

### Tier 2: Boundary, Extreme & Corner Cases ($\ge 5$ tests per feature)
- **Objective:** Subject every requirement to extreme inputs, mathematical limits, and stress boundaries.
- **Coverage Criteria:**
  - Minimum 5 distinct edge-case tests per requirement (totaling $\ge 30$ Tier 2 tests).
  - Test conditions:
    * **R1:** Budget = ₹0, Budget = ₹100 Cr (surplus), sub-millisecond execution times, extreme exchange rate precision.
    * **R2:** Controls with 0% immunity, 100% immunity, empty attack type arrays, unmapped threat vectors.
    * **R3:** Intensity at exact minimum (1.0) and maximum (10.0), invalid attack types, unknown target nodes, malformed JSON payloads.
    * **R4:** Zero baseline exposure ($\text{EAL}_{\text{base}} = 0 \implies \text{SUP} = 0.0\%$), over-mitigation ($\Delta\text{EAL} > \text{EAL}_{\text{base}} \implies \text{SUP} = 100.0\%$), negative risk reduction clamped to 0.0%.
    * **R5:** Virtual purchase of non-existent vendor, purchasing when cost exceeds remaining budget, duplicate re-purchases (idempotency).
    * **R6:** Empty threat pool ($\text{EAL} = 0$), flat loss distributions, single-finding portfolios, near-zero budget constraints.

### Tier 3: Cross-Feature Combinations (Pairwise & Multi-Feature Interactions)
- **Objective:** Verify combinatorial stability and state transitions when multiple features interact simultaneously.
- **Coverage Criteria:**
  - Minimum 10 integration and pairwise interaction tests.
  - Interaction Matrix:
    1. **R1 + R4:** Budget slider adjustments dynamically recalculate SUP % in lockstep with side-by-side EAL bars.
    2. **R3 + R1:** Remote attack injection immediately degrades the Security Factor Gauge and spikes baseline EAL displayed on the visualizer.
    3. **R3 + R5:** Attack injection recommends a specific vendor product; 1-click virtual purchase neutralizes the attack surge.
    4. **R2 + R5:** Vendor product catalog correctly exposes multi-threat shields matching R2 schema requirements.
    5. **R3 + R4:** Live attack surge expands total exposure, dynamically altering the denominator for subsequent SUP % calculations.
    6. **R5 + R6:** Successive virtual purchases strictly respect the cumulative budget ceiling and maintain $\text{VaR}_{90} < \text{VaR}_{95} < \text{VaR}_{99}$.

### Tier 4: Real-World Application Scenarios (End-to-End Hackathon Journey)
- **Objective:** Simulate the complete hackathon jury presentation workflow from start to finish.
- **Scenario Breakdown:**
  1. **Scenario 4.1: BharatCart Festive Sale DDoS Assault & Cloudflare Edge Mitigation**
     - Initial State: BharatCart API Gateway & Flash Sale Microservice operating under nominal baseline.
     - Action 1: External jury mobile device triggers Layer 7 DDoS Surge at intensity 8.5 via unauthenticated REST endpoint.
     - Verification: Threat Event Frequency quadruples, EAL surges by $> ₹3.5\text{ Cr}$, Posture score drops into Crimson ($<50\%$), and Cloudflare WAF is recommended.
     - Action 2: Executive clicks 1-Click Virtual Purchase for Cloudflare WAF.
     - Verification: DDoS immunity (99.4%) mitigates surge, Posture recovers to Guarded/Resilient ($>75\%$), SUP % increases, spend deducted correctly.
  2. **Scenario 4.2: Ransomware Lateral Propagation & CrowdStrike Host Isolation**
     - Action 1: Inject Ransomware Outage against Payment Gateway (`BC-PAY-GW-01`).
     - Action 2: Verify high-severity financial exposure alert, cascading impact to PII vault.
     - Action 3: Virtual purchase of CrowdStrike Falcon Insight XDR neutralizes lateral traversal.
  3. **Scenario 4.3: Multi-Threat Compounding Stress Test**
     - Simultaneous injection of Credential Stuffing and SQL Data Leak while user adjusts investment slider, validating sub-50ms visualizer responsiveness under load.

---

## 3. Detailed Requirement Verification Matrix (R1–R6)

| Req | Domain | Verification Methods | Authoritative Source | Target Invariant / SLA |
|---|---|---|---|---|
| **R1** | Visualizer & Posture | Client & Server calculation latency benchmark, currency conversion tests, pre/post delta math | `ORIGINAL_REQUEST.md` § R1, `PROJECT.md` F01–F07 | Latency $< 50\text{ms}$; $\Delta\text{EAL} \ge 0$; $1\text{ USD} = 83.50\text{ INR}$ |
| **R2** | Multi-Threat Shields | Pydantic model validation, 5-vector presence, immunity percentage range check $[0, 100]$ | `ORIGINAL_REQUEST.md` § R2, `PROJECT.md` F08–F14 | 5 vectors covered; immunity $\in [0, 100]$; non-empty mechanisms |
| **R3** | BharatCart Attack & Ticker | REST calls to `/demo/inject-attack`, telemetry jitter test `/demo/telemetry-ticker`, CORS headers | `ORIGINAL_REQUEST.md` § R3, `PROJECT.md` F15–F27 | HTTP 200 unauthenticated; CORS `*`; TEF surge $\ge 1.0 + 0.5 \times I$; Ticker stochastic |
| **R4** | Security Upgrade % | Bounded monotonic property tests, zero baseline fallback, INR/USD formatting | `ORIGINAL_REQUEST.md` § R4, `PROJECT.md` F28–F32 | $\text{SUP} \in [0.0\%, 100.0\%]$; monotonic with mitigated risk |
| **R5** | Vendor Matrix & Purchase | Catalog completeness check (5 vendors, 4 categories), purchase state transition, spend deduction | `ORIGINAL_REQUEST.md` § R5, `PROJECT.md` F33–F42 | 5 vendors present; purchase updates portfolio & reduces EAL |
| **R6** | Invariant Preservation | Monte Carlo statistical tests, HiGHS solver budget ceiling check, VaR ordering | `ORIGINAL_REQUEST.md` § R6, `PROJECT.md` F43–F46 | $\text{EAL} > 0$; $\text{VaR}_{90} < \text{VaR}_{95} < \text{VaR}_{99}$; $\sum \text{Cost} \le \text{Budget}$ |

---

## 4. Test Execution & CI/CD Integration

### 4.1 Test Runner Commands
- **Full E2E Hackathon Live Suite:**
  ```powershell
  pytest tests/e2e/test_hackathon_live_capabilities.py -v
  ```
- **Tier-Specific Execution:**
  ```powershell
  pytest tests/e2e/test_hackathon_live_capabilities.py -m tier1 -v
  pytest tests/e2e/test_hackathon_live_capabilities.py -m tier2 -v
  pytest tests/e2e/test_hackathon_live_capabilities.py -m tier3 -v
  pytest tests/e2e/test_hackathon_live_capabilities.py -m tier4 -v
  ```
- **Complete Enterprise Test Suite (Baseline + Live Capabilities):**
  ```powershell
  pytest --ignore=tests/api -q
  ```

### 4.2 Pass/Fail Criteria
- **100% Pass Rate:** Zero failures, zero uncaught exceptions, zero timeouts.
- **Execution Performance:** Full E2E live capabilities suite executes in $< 10\text{ seconds}$.
- **Invariant Guarantee:** No test execution may violate mathematical consistency ($\text{EAL} > 0$, $\text{VaR}_{90} < \text{VaR}_{95} < \text{VaR}_{99}$, $\text{Spend} \le \text{Budget}$).
