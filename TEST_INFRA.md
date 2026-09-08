# TEST_INFRA.md — CyberRiskQuant Test Architecture & Quality Framework

## 1. Test Philosophy & Principles

CyberRiskQuant is an enterprise-grade AI-powered continuous cyber risk quantification and investment optimization platform. Because high-stakes executive capital allocations, cyber insurance valuations, and regulatory filings (RBI, SEBI, ISO 27001, NIST CSF) depend on the integrity of this platform, the verification framework is built on four core tenets:

1. **Opaque-Box & Requirement-Driven Testing**: Tests are decoupled from internal class private details and focus strictly on behavioral specifications, public contracts, and observable financial metrics (EAL, VaR percentiles, ROSI, Pareto curves).
2. **Progressive Testability & Contract Fidelity**: The test harness defines authoritative reference interfaces and mock contracts (`tests/conftest.py`) adhering to `PROJECT.md` and `ORIGINAL_REQUEST.md`. As implementation modules land in `src/`, tests automatically bind to production modules or verify equivalence against mathematical reference contracts.
3. **Deterministic Mathematical Invariants**: Statistical simulations (vectorized Monte Carlo) and optimization solvers (MILP knapsack) are held to non-negotiable physical and financial invariants:
   - Positive Expected Annual Loss ($EAL > 0$) for non-empty threat landscapes, with exact $EAL = 0$ for empty pools.
   - Monotonic Value-at-Risk percentile ordering: $VaR_{90} \le VaR_{95} \le VaR_{99}$ globally, with strict inequality for continuous loss distributions.
   - Non-negative loss boundaries: $\min(\text{Loss}) \ge 0.0$.
   - Bit-exact PRNG seed reproducibility across platforms.
   - Subadditivity and Portfolio Diversification Benefit: $VaR_{95}(\text{Portfolio}) \le \sum_i VaR_{95}(\text{Asset}_i)$.
   - Hard budget constraint satisfaction: $\sum \text{Cost} \le \text{Budget}$.
   - Diminishing marginal returns: The Pareto efficiency frontier curve $\frac{\Delta \text{Risk}}{\Delta \text{Cost}}$ is strictly non-increasing.
4. **Adversarial & Multi-Tier Verification**: A 4-tier E2E testing pyramid ensuring thorough coverage from isolated feature units to deep combinatorial corner cases and complex enterprise failure scenarios.

---

## 2. Directory Layout & Architecture

```
tests/
├── conftest.py                             # Master test fixtures, mock generators, and assertion helpers
├── invariants/
│   ├── __init__.py
│   ├── test_monte_carlo_invariants.py      # Statistical & FAIR simulation invariants (EAL, VaR, Seed)
│   └── test_optimization_invariants.py     # Solver invariants (Budget, ROSI, Pareto diminishing returns)
└── e2e/
    ├── __init__.py
    ├── test_tier1_feature_coverage.py      # Tier 1: Feature Coverage (F01 through F31 isolated happy paths)
    ├── test_tier2_boundary_corner.py       # Tier 2: Boundary & Corner Cases (Extreme scores, zero/inf budget)
    ├── test_tier3_pairwise_combinations.py # Tier 3: Cross-Feature Combinations (Severity x Tier, What-If x Currencies)
    └── test_tier4_real_world_scenarios.py  # Tier 4: Real-World Enterprise Scenarios (Ransomware, S3 Leak, M&A)
```

---

## 3. Feature Inventory Mapping

| Feature ID | Feature Name | Primary Requirement | Test Suite & Tier | Invariant / Contract Verified |
|---|---|---|---|---|
| **F01** | Multi-Domain Telemetry Schemas | R1 (Telemetry) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | 5 domains (CVE, SIEM, IAM, EDR, CSPM) validation |
| **F02** | Extensible Telemetry Adapters | R1 (Telemetry) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | Format parsing (JSON, CSV, REST) & normalization |
| **F03** | Synthetic Telemetry Generator | R1 (Telemetry) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | Multi-BU enterprise generation & distribution sanity |
| **F04** | Asset Valuation & Sensitivity Model | R1 (Criticality) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | 4-tier data sensitivity & monetary asset valuations |
| **F05** | Service Dependency DAG | R1 (Criticality) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | NetworkX DAG propagation & upstream percolation |
| **F06** | Dynamic Criticality Impact Modifier | R1 (Criticality) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | Tier 1 finding loss $> 10\times$ Tier 4 finding loss |
| **F07** | Telemetry to FAIR Translation | R2 (FAIR Engine) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | Mapping telemetry to TEF, TCap, RS, Vuln, LEF |
| **F08** | Vectorized Monte Carlo Simulation | R2 (FAIR Engine) | `tests/invariants/test_monte_carlo_invariants.py` | Compound Poisson-LogNormal speed (<100ms) & loss array |
| **F09** | Financial Risk Metrics (EAL & VaR) | R2 (FAIR Engine) | `tests/invariants/test_monte_carlo_invariants.py` | $EAL > 0$, $VaR_{90} < VaR_{95} < VaR_{99}$, LEC curve |
| **F10** | Multi-Level Portfolio Aggregation | R2 (FAIR Engine) | `tests/invariants/test_monte_carlo_invariants.py` | Asset $\to$ BU $\to$ Enterprise roll-up & subadditivity |
| **F11** | Deterministic Seed Reproducibility | R2 (FAIR Engine) | `tests/invariants/test_monte_carlo_invariants.py` | Bit-exact metrics across runs with seed=42 |
| **F12** | Threat Trajectory Forecasting | R3 (Decision) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | 30/60/90-day risk forecasting with EPSS velocity |
| **F13** | What-If Counterfactual Simulation | R3 (Decision) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | $\Delta EAL > 0$ when mitigating; Common Random Numbers |
| **F14** | Compounding Delayed Remediation Cost | R3 (Decision) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | Non-linear cost of delay & hazard rate surge |
| **F15** | Deterministic NLQ Query Parser | R3 (Decision) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | Intent extraction, entity slot filling, currency parsing |
| **F16** | Executive Narrative Generator | R3 (Decision) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | High-level synthesis, top loss drivers, plain language |
| **F17** | Multi-Constraint MILP Knapsack | R4 (Optimization)| `tests/invariants/test_optimization_invariants.py` | Optimal 0-1 knapsack formulation with constraints |
| **F18** | Strict Budget Ceiling Enforcement | R4 (Optimization)| `tests/invariants/test_optimization_invariants.py` | Total selected cost $\le$ budget across all budget inputs |
| **F19** | Advanced Control Constraint System | R4 (Optimization)| `tests/invariants/test_optimization_invariants.py` | Mandatory baselines, prerequisites, mutual exclusivity |
| **F20** | Financial Optimization Metrics | R4 (Optimization)| `tests/invariants/test_optimization_invariants.py` | $ROSI = \frac{\Delta \text{Risk} - \text{Cost}}{\text{Cost}} \times 100\%$, Net Benefit |
| **F21** | Pareto Efficiency Frontier Generator | R4 (Optimization)| `tests/invariants/test_optimization_invariants.py` | Parametric budget sweep, concavity / diminishing returns |
| **F22** | ISO/IEC 27001 Catalog & Mapping | R5 (Compliance) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | 93 Annex A controls mapping & telemetry triggers |
| **F23** | NIST CSF 2.0 Catalog & Mapping | R5 (Compliance) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | 6 Functions (Govern, Identify, Protect, Detect, etc.) |
| **F24** | CIS Controls v8 Catalog & Mapping | R5 (Compliance) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | 18 Control categories & implementation groups |
| **F25** | RBI Cyber Security Framework | R5 (Compliance) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | Banking circular controls (PAM, C-SOC, SLA) |
| **F26** | SEBI CSCRF Regulatory Mapping | R5 (Compliance) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | 5 Resilience pillars (Anticipate, Withstand, etc.) |
| **F27** | Compliance Scoring & Risk Attribution | R5 (Compliance) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | Weighted compliance % & non-compliant sum(EAL) |
| **F28** | Executive / Board View Dashboard | R5 (Dashboard) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | Executive KPIs, VaR cards, loss exceedance curve |
| **F29** | Technical SecOps View Dashboard | R5 (Dashboard) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | 5-domain telemetry counts, finding list, backlog |
| **F30** | Currency Switch & Responsive UI | R5 (Dashboard) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | INR (₹ Lakhs/Crores) and USD ($ Millions) scaling |
| **F31** | Unified FastAPI REST API Backend | R5 (API) | `tests/e2e/test_tier1_feature_coverage.py` [T1] | REST endpoints, DTO contracts, status codes (200/422) |
| **F32** | Automated Pytest Verification Suite | R6 (Verification)| Entire `tests/` tree | 100% test pass rate across all invariants and tiers |

---

## 4. 4-Tier E2E Testing Structure

### Tier 1: Feature Coverage (`tests/e2e/test_tier1_feature_coverage.py`)
- **Scope**: Features F01 through F31 tested in isolation.
- **Coverage**: Every feature has at least 5 distinct test assertions or parameterizations testing nominal happy paths, default states, type constraints, and standard responses.

### Tier 2: Boundary & Corner Cases (`tests/e2e/test_tier2_boundary_corner.py`)
- **Scope**: Extreme operational boundaries, edge inputs, and potential numerical instability points.
- **Scenarios**:
  1. *Zero Budget ($0 / ₹0)*: Optimizer must return 0 selected controls and 0 cost without exception.
  2. *Infinite Budget ($100M+ / ₹1000 Cr)*: Optimizer must select all non-conflicting controls cleanly.
  3. *Empty Telemetry Stream (0 findings, 0 alerts)*: Risk engine must return $EAL = 0.0$ and $VaR = 0.0$ with zero NaN or division-by-zero errors.
  4. *Extreme EPSS (0.0 and 1.0) and CVSS (0.0 and 10.0)*: Validated bounded risk scaling.
  5. *Deep DAG Topology (10 levels deep)*: Validates upstream revenue percolation without stack overflow or infinite graph cycles.
  6. *High-Scale Control Portfolios (100+ controls)*: Optimization solver solves within 1 second.
  7. *Catastrophic Single Loss Outlier (₹500 Crore)*: LogNormal/Beta-PERT tail captures extreme loss without numeric overflow.

### Tier 3: Cross-Feature Combinations (`tests/e2e/test_tier3_pairwise_combinations.py`)
- **Scope**: Combinatorial interaction across different architectural subsystems.
- **Scenarios**:
  1. *Telemetry Severity $\times$ Asset Criticality Matrix*: 4 severities $\times$ 4 asset tiers validating that criticality dominates raw vulnerability severity.
  2. *Monte Carlo Loss Distribution $\times$ What-If Control Removal*: Verifies risk surge when stripping controls from Tier 1 assets vs Tier 4 assets.
  3. *Budget Optimization $\times$ Mandatory Regulatory Constraints*: Verifies that regulatory requirements (e.g. RBI PAM and SEBI WORM) act as hard knapsack constraints that must be funded before optional controls.
  4. *Currency Scaling $\times$ API Data Serialization*: Verifies bidirectional conversion between INR Lakhs/Crores and USD Millions with round-trip floating point precision.
  5. *Multi-Domain Telemetry Clustering*: Co-located vulnerabilities, disabled EDR, and IAM privilege on the same critical asset produces non-linear risk compounding.

### Tier 4: Real-World Enterprise Scenarios (`tests/e2e/test_tier4_real_world_scenarios.py`)
- **Scope**: End-to-end holistic simulation of realistic corporate cyber crisis events.
- **Scenarios**:
  1. *Scenario 1: Core Banking Ransomware Infection Path*: Endpoint with disabled EDR connects via lateral movement to Core Banking DB with unpatched critical CVE (high EPSS) and excessive IAM admin privileges. Simulates entire attack chain, loss quantification, and remediation verification.
  2. *Scenario 2: Cloud S3 Financial Data Leakage*: Public CSPM S3 misconfiguration hosting PCI-DSS cardholder data triggers immediate compliance failure across ISO 27001 (A.8.24), RBI (DAT-01), and SEBI (WIT-03), computing non-compliant financial penalty attribution.
  3. *Scenario 3: Annual Cybersecurity Budget Allocation Exercise*: Enterprise CIO allocates ₹1 Crore budget across 20 competing initiatives with prerequisite dependencies and mutually exclusive solutions, validating Pareto efficiency and maximum ROSI.
  4. *Scenario 4: M&A Subsidiary Onboarding*: Rapid risk assessment of an acquired entity with legacy infrastructure, computing aggregate parent-subsidiary risk and attributing compliance gaps.
  5. *Scenario 5: Emergency Zero-Day Remediation Prioritization*: Evaluates cost of delay for 30 days on zero-day vulnerability (CVSS 9.8, EPSS 0.95) versus the cost of expedited weekend emergency patching.

---

## 5. Mathematical & Optimization Invariant Specifications

### 5.1 Monte Carlo Simulation Invariants (`tests/invariants/test_monte_carlo_invariants.py`)

1. **Strict Percentile Ordering**:
   $$\forall \text{ valid runs with } N \ge 1000, \quad VaR_{90} \le VaR_{95} \le VaR_{99}$$
   For non-degenerate distributions with $>0$ loss variance, strict inequality holds:
   $$VaR_{90} < VaR_{95} < VaR_{99}$$

2. **Positive Expected Annual Loss**:
   $$\text{EAL} = \frac{1}{N} \sum_{i=1}^N L_i > 0 \quad \text{for any non-empty finding set}$$
   $$\text{EAL} = 0.0 \quad \text{iff finding set is empty}$$

3. **Loss Non-Negativity**:
   $$\min(L_i) \ge 0.0 \quad \forall i \in \{1, \dots, N\}$$

4. **Bit-Exact Seed Reproducibility**:
   $$\text{Engine}(\text{seed}=S, \text{params}) \equiv \text{Engine}(\text{seed}=S, \text{params})$$
   Metric values must match to within $10^{-6}$ relative tolerance.

5. **Portfolio Diversification Benefit (Subadditivity of Risk)**:
   $$VaR_{95}\left(\sum_{k=1}^K \text{Asset}_k\right) \le \sum_{k=1}^K VaR_{95}(\text{Asset}_k)$$
   For imperfectly correlated threats across distributed assets, the portfolio tail risk is strictly less than the uncoordinated sum of individual asset tail risks.

---

### 5.2 Optimization Solver Invariants (`tests/invariants/test_optimization_invariants.py`)

1. **Strict Budget Ceiling Enforcement**:
   $$\sum_{c \in C_{\text{selected}}} \text{Cost}(c) \le \text{Budget} \quad \forall \text{Budget} \in [0, \infty)$$

2. **Non-Negative Risk Reduction & ROSI**:
   $$\Delta \text{EAL} = \text{EAL}_{\text{baseline}} - \text{EAL}_{\text{mitigated}} \ge 0$$
   $$\text{ROSI} = \frac{\Delta \text{EAL} - \sum \text{Cost}}{\sum \text{Cost}} \times 100\% \ge -100\%$$

3. **Diminishing Marginal Returns (Frontier Concavity)**:
   Let $P_1, P_2, \dots, P_m$ be successive points along the Pareto efficiency frontier with increasing spend:
   $$\frac{\Delta \text{Risk}_k}{\Delta \text{Spend}_k} \ge \frac{\Delta \text{Risk}_{k+1}}{\Delta \text{Spend}_{k+1}} \quad \forall k$$

4. **Hard Constraint Satisfaction**:
   - *Mandatory Controls*: If $c$ has `is_mandatory = True` and $\text{Cost}(c) \le \text{Budget}$, $c \in C_{\text{selected}}$.
   - *Mutual Exclusivity*: If $c_1$ and $c_2$ conflict, $\{c_1, c_2\} \not\subseteq C_{\text{selected}}$.
   - *Prerequisites*: If $c_2$ requires $c_1$, then $c_2 \in C_{\text{selected}} \implies c_1 \in C_{\text{selected}}$.

---

## 6. Execution & Quality Gates

### Running the Test Suite
```bash
# Run all invariant tests
pytest tests/invariants -v

# Run all E2E test suites (Tiers 1 - 4)
pytest tests/e2e -v

# Run entire test suite with summary
pytest tests/ -v --tb=short
```

### Quality Thresholds
- **Pass Rate**: 100% passing tests (0 failures, 0 unexpected errors).
- **Execution Time**: The complete invariant and E2E suite executes in under 20 seconds.
- **Coverage**: Every feature F01 through F31 has dedicated assertions across the 4-tier matrix.
