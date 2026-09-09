# LossLogic: Complete Technical Specification & AI Agent Reference Guide

> **Smart India Hackathon 2026** • **Problem Statement ID: 26105**  
> **Organization:** Ministry / AICTE Cyber Security Cell  
> **Repository:** https://github.com/Sourish25/LossLogic  
> **Primary Technology Stack:** Python 3.11+, FastAPI, SciPy (HiGHS MILP), NumPy, NetworkX, Pydantic v2, HTML5/CSS3/Vanilla JS (Apple Liquid Glass UI System).

---

## 1. System Identity & Mission

### 1.1 The Fundamental Problem
Enterprise cybersecurity risk management is broken by a communication and quantification chasm:
- **Security Practitioners (CISOs)** communicate in CVE counts, CVSS severity scores (e.g., 9.8 Critical), and subjective 5×5 colored heatmaps (*Red, Amber, Green*).
- **Executive Leadership (CFOs, Boards, Risk Committees)** allocate capital based on **currency loss exposure ($ / ₹)**, **Expected Annual Loss (EAL)**, **Value-at-Risk (VaR)**, **EBITDA protection**, and **Return on Security Investment (ROSI)**.

### 1.2 Mathematical Failure of Qualitative 5×5 Matrices
Traditional risk matrices multiply arbitrary ordinal numbers (e.g., Likelihood "4" × Impact "5" = Score "20"):
1. **Ordinal Scales Cannot Be Multiplied**: Numerically, 20 is not twice as severe as 10. Ordinal numbers have rank, but no proportional distance.
2. **Range Compression & Rank Reversal**: Low-frequency high-impact existential risks (e.g., catastrophic ransomware shutting down payment gateways) receive identical scores to high-frequency nuisance events (e.g., lost employee keycard).
3. **Arbitrary Prioritization**: CISOs mark everything as "Critical" to secure budget, leaving executive boards with zero defensible allocation strategy.

### 1.3 The LossLogic Solution
LossLogic models risk strictly in **real monetary currency ($ USD / ₹ INR)** using actuarial science and mathematical optimization:
1. Translates telemetry into **Open FAIR™ probabilistic parameters** (Threat Event Frequency, Vulnerability, Resistance Strength, Primary & Secondary Loss Magnitude).
2. Runs **10,000 Monte Carlo stochastic trials** using Beta-PERT and Log-Normal distributions to compute **Expected Annual Loss (EAL)** and **Value-at-Risk (VaR 90%, 95%, 99%)**.
3. Models cascading failures across enterprise IT/OT via a **NetworkX Directed Acyclic Graph (DAG)** to measure structural blast radii.
4. Allocates budget using **SciPy's HiGHS Mixed-Integer Linear Programming (MILP)** 0/1 Knapsack optimizer, guaranteeing the mathematically optimal control selection under budget and prerequisite constraints.
5. Crosswalks funded controls across 5 major regulatory frameworks: **RBI Cyber Security Framework**, **SEBI CSCRF 2024**, **ISO/IEC 27001:2022**, **NIST CSF 2.0**, and **CIS Controls v8**.

---

## 2. Codebase Structure & Architecture

```
LossLogic/
├── src/
│   ├── api/
│   │   ├── app.py             # FastAPI application factory, CORS, static/template mounting
│   │   ├── routes.py          # REST endpoints (/api/v1/health, /optimize, /what-if, /nlq, etc.)
│   │   └── schemas.py         # Pydantic v2 DTOs for request/response serialization
│   ├── assets/
│   │   ├── graph.py           # EnterpriseDependencyGraph (NetworkX DAG, blast radius percolation)
│   │   ├── models.py          # AssetRecord, BusinessService, EnvironmentTier, DataSensitivityTier
│   │   └── scoring.py         # Asset Criticality Scoring (ACS) & financial valuation
│   ├── compliance/
│   │   ├── catalog.py         # Control catalogs for ISO 27001, NIST CSF, CIS v8, RBI CSF, SEBI CSCRF
│   │   ├── mapper.py          # Bidirectional finding-to-regulatory-control mapper
│   │   └── scoring.py         # Weighted compliance scoring and financial loss attribution
│   ├── dashboard/
│   │   ├── app.py             # Dashboard static file router
│   │   ├── static/            # CSS, JS, liquidGL.js (Apple Liquid Glass design system)
│   │   └── templates/         # index.html (Responsive dark/light executive interface)
│   ├── decision_support/
│   │   ├── delay_cost.py      # Exponential compounding remediation delay cost model
│   │   ├── narrative.py       # Executive briefing and financial rationale generator
│   │   ├── nlq_parser.py      # Deterministic natural language query regex/slot parser
│   │   ├── trajectory.py      # 30/60/90-day predictive threat trajectory with EPSS velocity
│   │   └── what_if.py         # Counterfactual simulation with Common Random Numbers (CRN)
│   ├── optimization/
│   │   ├── frontier.py        # Andrew's Monotone Chain Pareto convex hull & saturation detector
│   │   ├── models.py          # SecurityControl, OptimizationRequest, OptimizationResult
│   │   ├── rosi.py            # Return on Security Investment (ROSI %) & marginal cost-benefit
│   │   └── solver.py          # SciPy HiGHS MILP 0/1 knapsack solver & Branch-and-Bound fallback
│   ├── quant/
│   │   ├── fair_mapper.py     # Telemetry-to-FAIR probabilistic parameter translator
│   │   ├── monte_carlo.py     # Vectorized Compound Poisson-LogNormal Monte Carlo simulator
│   │   └── portfolio.py       # Hierarchical aggregation (Asset -> Business Unit -> Enterprise)
│   ├── telemetry/
│   │   ├── adapters.py        # Telemetry ingestion adapters for CrowdStrike, Tenable, Wiz, etc.
│   │   ├── generator.py       # High-fidelity synthetic banking enterprise data generator (65 assets)
│   │   ├── models.py          # Pydantic models for CVE, SIEM, IAM, EDR, CSPM findings
│   │   └── normalizer.py      # Normalizes findings into unified risk vectors
│   └── config.py              # Global rates (USD to INR = 83.5), regulatory limits, environment multipliers
├── tests/                     # 429 automated unit, adversarial, stress, and invariant tests
├── run_server.py              # Production ASGI entry point (binds to 0.0.0.0:$PORT)
├── requirements.txt           # Minimal, verified production dependencies
├── LossLogic_Project_Report.pdf # Printable 6-page executive pitch guide and teammate cheat sheet
├── llms.txt                   # Standard LLM discovery sitemap
├── llms-full.txt              # Complete AI agent context
└── README.md                  # GitHub landing page with Mermaid architecture
```

---

## 3. Mathematical Foundations & Algorithms

### 3.1 Open FAIR™ Monte Carlo Simulation (`src/quant/monte_carlo.py`)
- **Threat Event Frequency (TEF)**: Modeled using a Beta-PERT distribution calibrated from historical external probing and SIEM anomaly frequencies:
  $$	ext{Beta-PERT}(	ext{min}, 	ext{mode}, 	ext{max})$$
- **Vulnerability / Resistance Strength (RS)**: Modeled using Beta distributions representing the capability of defenses to repel an attack.
- **Loss Event Frequency (LEF)**: Compound Bernoulli trial where breach occurs if $	ext{Threat Capability} > 	ext{Resistance Strength}$.
- **Loss Magnitude (LM)**: Decomposed into:
  1. **Primary Loss**: Direct incident response, forensic investigations, system downtime, customer compensation.
  2. **Secondary Loss**: Regulatory fines (RBI/SEBI statutory penalties), legal litigation, reputational churn. Modeled via **Log-Normal distribution** $	ext{Lognormal}(\mu, \sigma)$ to capture extreme long-tailed tail risk.
- **Trial Count**: 10,000 iterations per scenario.
- **Outputs**:
  - **Expected Annual Loss (EAL)**: $\mathbb{E}[	ext{Loss}] = rac{1}{N} \sum_{k=1}^N 	ext{Loss}_k$
  - **Value-at-Risk (VaR)**: Empirical percentiles from sorted loss variates:
    - $	ext{VaR}_{90}$: 90th percentile of annual loss
    - $	ext{VaR}_{95}$: 95th percentile (standard regulatory stress threshold)
    - $	ext{VaR}_{99}$: 99th percentile (existential catastrophe / insolvency threshold)

### 3.2 Asset Dependency Graph & Blast Radius (`src/assets/graph.py`)
- Modeled as a Directed Acyclic Graph $G = (V, E)$ using NetworkX.
- Vertices $V$ represent enterprise IT/OT assets (Servers, Databases, APIs, Workstations).
- Edges $(u, v) \in E$ represent dependency relations ($v$ depends on $u$).
- **Cascading Blast Radius**: If asset $u$ is compromised:
  $$	ext{BlastRadius}(u) = 1 + \sum_{v \in 	ext{Descendants}(u)} w(u, v) \cdot 	ext{Criticality}(v)$$
- Upstream root compromises (e.g., Active Directory, IAM Provider) propagate failure risk down to critical transaction systems (Core Banking, SWIFT Payment Gateway).

### 3.3 SciPy HiGHS Mixed-Integer Linear Programming (MILP) (`src/optimization/solver.py`)
The security capital allocation is mathematically formulated as an exact 0/1 Knapsack Problem with linear dependency constraints:
$$egin{aligned}
	ext{Maximize} \quad & \sum_{i=1}^n x_i \cdot \Delta	ext{EAL}_i \
	ext{Subject to} \quad & \sum_{i=1}^n x_i \cdot 	ext{Cost}_i \le 	ext{Budget} \
& x_j \le x_k \quad orall (j, k) \in 	ext{Prerequisites (Control } j 	ext{ requires Control } k) \
& x_p + x_q \le 1 \quad orall (p, q) \in 	ext{Mutual Exclusions} \
& x_i \in \{0, 1\} \quad orall i \in \{1, \dots, n\}
\end{aligned}$$
- **Solver Engine**: Solved using `scipy.optimize.milp` with the C++ **HiGHS** simplex/interior-point branch-and-cut engine.
- **Latency**: Sub-5 milliseconds for enterprise portfolios.
- **Fallback**: Includes a deterministic Branch-and-Bound solver if external solver libraries are unavailable.

### 3.4 Pareto Frontier & Diminishing Returns (`src/optimization/frontier.py`)
- Constructs the non-dominated set of investment packages by sweeping the budget space in discrete increments.
- Fits a Catmull-Rom cubic spline through milestone coordinates.
- **Return on Security Investment (ROSI)**:
  $$	ext{ROSI} = rac{\Delta	ext{EAL} - 	ext{Total Cost}}{	ext{Total Cost}} 	imes 100\%$$
- **Budget Saturation**: Detects when the available control catalog is 100% funded (e.g., at $38,900 across all 8 controls). Flags all additional capital as **Surplus Capital** so executive leadership avoids capital misallocation.

---

## 4. The Ground Truth on Testing Data & Live Dynamics

### 4.1 Why There Is No Drag-and-Drop CSV Upload
1. **Enterprise CRQ Reality**: In production financial institutions, cybersecurity risk platforms (RiskLens, Axio, Kovrr) do NOT ingest manual CSV spreadsheets. Spreadsheets are outdated immediately and introduce human error. Production platforms ingest continuous telemetry via REST/GraphQL APIs from:
   - Vulnerability Management (Tenable, Qualys, Rapid7)
   - EDR/XDR (CrowdStrike Falcon, Microsoft Defender)
   - SIEM/SOAR (Splunk, Microsoft Sentinel)
   - CMDB (ServiceNow, Jira Service Management)
   - CSPM (Wiz, Prisma Cloud, AWS Security Hub)
2. **Hackathon Focus**: Development effort was prioritized on writing mathematically defensible quant engines (Monte Carlo, graph percolation, and SciPy linear programming), rather than building generic CSV validation parsers.

### 4.2 Seed Topology vs. 100% Dynamic Engine
- **Seeded Layer**: A realistic 5-node commercial banking topology:
  1. *Core Banking Engine (PostgreSQL / Mainframe)*
  2. *SWIFT Payment Gateway (Financial Transactions)*
  3. *Customer PII Database (Restricted Data Tier)*
  4. *Public Web Portal (Perimeter)*
  5. *Active Directory / IAM Root (Identity Hub)*
- **Dynamic Layer**: **100% of calculations execute live in Python**:
  - Moving the budget slider triggers fresh SciPy HiGHS execution (~4ms).
  - Pareto curve points are derived from real mathematical sweeps.
  - Residual risk, compliance crosswalk, and ROSI percentages are re-evaluated dynamically on every request.

---

## 5. Decision Support & Google Gemini AI Integration Blueprint

### 5.1 Current Architecture (Deterministic NLG)
The decision support layer in `src/decision_support/` uses:
- Deterministic regex and grammar slot extractors (`nlq_parser.py`)
- Zero-hallucination natural language generation (`narrative.py`)
- Counterfactual what-if analysis with Common Random Numbers (`what_if.py`)

### 5.2 Google Gemini 3.5 Flash Lite Upgrade Pattern
An LLM should **never perform mathematical calculations directly**, as generative models hallucinate numbers and cannot guarantee linear constraint satisfaction. Instead, Gemini acts as the **Semantic Orchestrator** using **Function Calling (Tool Calling)**:

```
[User Natural Query: "What happens if our budget is cut by 25%?"]
                              │
                              ▼
        [Google Gemini 3.5 Flash Lite / 2.0 Flash]
        (Inspects Pydantic Tool Calling Schemas)
                              │
             Calls: run_optimizer(budget=18750)
                              │
                              ▼
            [LossLogic SciPy HiGHS MILP Engine]
       (Computes global optimum, EAL, & compliance)
                              │
                              ▼
       [Returns Exact JSON Vector to Gemini LLM]
                              │
                              ▼
     [Gemini Formats Board-Ready Narrative Response]
```

**Why Gemini 3.5 Flash Lite?**
- **Sub-250ms Latency**: Real-time conversational exploration without UI lag.
- **Strict Schema Adherence**: Flawless JSON function calling without malformed arguments.
- **1M+ Token Context Window**: Enables loading entire regulatory PDFs (RBI CSF, SEBI CSCRF circulars) into context for clause-by-clause legal attribution.
- **Commercial Viability**: Highly cost-effective for continuous enterprise querying.

---

## 6. Teammate & Judge Defense Q&A

**Q1: Is the data hardcoded or fake?**  
*Answer:* The initial banking topology (5 servers and 8 controls) is seeded to represent an RBI-regulated commercial bank so the system is immediately demonstrable. However, all calculations are 100% dynamic. Moving the budget slider executes Python's SciPy HiGHS MILP solver in real time (~4ms) to calculate the optimal 0/1 decision vector and re-render the Pareto curve.

**Q2: Why use Open FAIR instead of CVSS vulnerability scores?**  
*Answer:* CVSS only measures technical vulnerability severity in isolation (e.g., CVSS 9.8). It ignores asset value, organizational context, and exposure. A CVSS 9.8 flaw on an air-gapped test server represents $0 in financial risk, while a CVSS 6.0 flaw on the SWIFT Gateway could trigger an existential $10M loss event. Open FAIR translates risk into financial currency ($), enabling CFO-level cost-benefit allocation.

**Q3: Why is MILP Knapsack necessary over simple ROI sorting?**  
*Answer:* Greedy sorting by ROI is mathematically sub-optimal for the 0/1 Knapsack problem. Greedy approaches can easily exhaust budget on a high-cost control while missing multiple smaller controls that together yield higher risk reduction. Furthermore, MILP natively enforces structural dependency constraints (e.g., MFA requires an Identity Provider: $x_{	ext{MFA}} \le x_{	ext{IAM}}$), which greedy algorithms cannot handle.

**Q4: Why does the graph stay flat after $38,900? Is it a bug?**  
*Answer:* That is a deliberate economic feature called **Budget Saturation (Diminishing Marginal Utility)**. All 8 security controls in our catalog cost $38,900 combined. At $50,000, 100% of controls are already funded. Allocating more money cannot reduce risk further. LossLogic explicitly flags the unspent funds as **Surplus Capital ($11,100)** to prevent CFO capital waste.

**Q5: Where is the AI/ML in your project?**  
*Answer:* LossLogic utilizes **Operations Research & Decision Intelligence** (Mathematical Optimization & Monte Carlo Statistical Sampling), which is the foundational branch of AI utilized in hedge funds, aerospace, and insurance actuarial science. For conversational AI, LossLogic implements an automated Decision Support engine with a tool-calling architecture designed for Google Gemini 3.5 Flash Lite. Deterministic math handles the risk calculation, while Gemini handles natural language interaction.

**Q6: How does LossLogic help an Indian bank comply with RBI and SEBI?**  
*Answer:* Both RBI and SEBI mandate that cybersecurity spending must be defensible and proportionate to quantifiable risk. LossLogic provides an automated compliance crosswalk that maps each funded control to specific regulatory clauses (e.g., SEBI CSCRF Domain 3.2 Access Control), generating instant audit artifacts.

---

## 7. Operational Runbook & Commands

### 7.1 Local Startup
```bash
# Clone
git clone https://github.com/Sourish25/LossLogic.git
cd LossLogic

# Install dependencies
pip install -r requirements.txt

# Run server
python run_server.py
```
- Web Dashboard: `http://127.0.0.1:8000/`
- Swagger Docs: `http://127.0.0.1:8000/docs`
- Health Probe: `http://127.0.0.1:8000/api/v1/health`

### 7.2 Run Automated Tests
```bash
pytest tests/
```
All 429 tests verify:
- Vectorized Monte Carlo convergence and Poisson-LogNormal variate properties.
- NetworkX DAG topological sort, cycle detection, and blast radius percolation.
- SciPy HiGHS MILP constraint compliance, prerequisite enforcement, and frontier convexity.
- Regulatory framework mapping completeness (RBI, SEBI, NIST, ISO, CIS).
