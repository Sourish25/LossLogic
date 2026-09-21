"""
src/optimization/vendor_benchmarking.py - Executive CEO Vendor Benchmarking & Virtual Procurement Engine.
Provides market-leading vendor profiles, multi-threat immunity mappings, and virtual portfolio purchasing.
"""

from copy import deepcopy
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, model_validator

from src.config import USD_TO_INR_RATE, INR_TO_USD_RATE, usd_to_inr, inr_to_usd
from src.optimization.models import ThreatShield, ThreatVectorEnum
from src.optimization.rosi import (
    calculate_net_capital_saved,
    calculate_rosi,
    calculate_security_posture_score,
    calculate_security_upgrade_pct,
)


class VendorCategoryEnum(str, Enum):
    """Core enterprise cybersecurity categories for executive benchmarking."""
    EDR = "EDR"
    WAF = "WAF"
    IAM = "IAM"
    CSPM = "CSPM"

    @classmethod
    def _missing_(cls, value: object) -> Any:
        if isinstance(value, str):
            norm = value.strip().upper()
            if norm in cls.__members__:
                return cls.__members__[norm]
            if "ENDPOINT" in norm or "XDR" in norm:
                return cls.EDR
            if "PERIMETER" in norm or "FIREWALL" in norm or "DDOS" in norm:
                return cls.WAF
            if "IDENTITY" in norm or "ACCESS" in norm or "MFA" in norm:
                return cls.IAM
            if "CLOUD" in norm or "CNAPP" in norm or "DSPM" in norm:
                return cls.CSPM
        return None


class VendorProductProfile(BaseModel):
    """
    Comprehensive product profile for executive CEO vendor comparison.
    Captures pricing, coverage rating, future threat shields, and regulatory alignment.
    """
    vendor_id: str = Field(..., description="Unique vendor identifier e.g. VND-CRWD-EDR")
    vendor_name: str = Field(..., description="Vendor company name (CrowdStrike, Microsoft, Cloudflare, Okta, Wiz)")
    product_name: str = Field(..., description="Commercial product name")
    category: str = Field(..., description="Architectural category (EDR, WAF, IAM, CSPM)")
    annual_cost_usd: float = Field(default=0.0, ge=0.0, description="Annual licensing cost in USD")
    annual_cost_inr: float = Field(default=0.0, ge=0.0, description="Annual licensing cost in INR")
    overall_coverage_rating: float = Field(
        default=0.0, ge=0.0, le=100.0, description="Overall threat surface coverage percentage (0-100%)"
    )
    future_threat_shields: List[ThreatShield] = Field(
        default_factory=list, description="Multi-threat proactive immunity shields"
    )
    compliance_alignment: List[str] = Field(
        default_factory=list, description="Mapped regulatory frameworks (ISO 27001, NIST CSF, RBI CSF, SEBI CSCRF)"
    )
    recommendation_tags: List[str] = Field(
        default_factory=list, description="Strategic executive tags ('Best-in-Class ROSI', 'Zero-Trust Leader')"
    )
    rosi_estimate_pct: float = Field(default=0.0, description="Estimated return on security investment percentage")
    associated_control_id: str = Field(default="", description="Corresponding internal SecurityControl ID")
    target_node_ids: List[str] = Field(
        default_factory=list, description="Asset nodes in enterprise topology shielded by this solution"
    )
    is_funded: bool = Field(default=False, description="Whether product is actively funded in current portfolio")

    @model_validator(mode="before")
    @classmethod
    def _normalize_costs(cls, data: Any) -> Any:
        if isinstance(data, dict):
            cost_u = data.get("annual_cost_usd", 0.0)
            cost_i = data.get("annual_cost_inr", 0.0)
            if cost_u > 0.0 and cost_i == 0.0:
                data["annual_cost_inr"] = usd_to_inr(cost_u)
            elif cost_i > 0.0 and cost_u == 0.0:
                data["annual_cost_usd"] = inr_to_usd(cost_i)
        return data

    def get_cost(self, currency: str = "INR") -> float:
        """Get annual product cost in the requested currency."""
        curr = currency.upper().strip()
        if curr == "USD":
            return self.annual_cost_usd if self.annual_cost_usd > 0.0 else inr_to_usd(self.annual_cost_inr)
        return self.annual_cost_inr if self.annual_cost_inr > 0.0 else usd_to_inr(self.annual_cost_usd)

    def get_threat_shield(self, vector: Union[ThreatVectorEnum, str]) -> Optional[ThreatShield]:
        """Lookup threat shield by vector."""
        try:
            resolved = ThreatVectorEnum(vector) if not isinstance(vector, ThreatVectorEnum) else vector
        except (ValueError, TypeError):
            return None
        for s in self.future_threat_shields:
            if s.threat_vector == resolved:
                return s
        return None


# =========================================================================
# Canonical CEO Vendor Catalog (5 Market Leaders across 4 Pillars)
# =========================================================================

VENDOR_CATALOG: Dict[str, VendorProductProfile] = {
    # 1. Endpoint / EDR: CrowdStrike Falcon Insight XDR
    "VND-CRWD-EDR": VendorProductProfile(
        vendor_id="VND-CRWD-EDR",
        vendor_name="CrowdStrike",
        product_name="CrowdStrike Falcon Insight XDR",
        category="EDR",
        annual_cost_usd=12000.0,
        annual_cost_inr=12000.0 * USD_TO_INR_RATE,
        overall_coverage_rating=96.5,
        recommendation_tags=["Best-in-Class ROSI", "Kernel Anti-Tamper", "Jury Pick"],
        compliance_alignment=["ISO 27001", "NIST CSF", "CIS Controls", "RBI CSF", "SEBI CSCRF"],
        associated_control_id="CTRL-EDR",
        target_node_ids=["BC-PAY-GW-01", "BC-FLASH-SALE-01"],
        rosi_estimate_pct=312.4,
        future_threat_shields=[
            ThreatShield(
                threat_vector=ThreatVectorEnum.RANSOMWARE_LATERAL,
                future_immunity_pct=96.5,
                protective_mechanism="Kernel ring-0 behavioral heuristics, shadow copy tamper locking, and automated host isolation",
                neutralized_attack_types=["PsExec Spreading", "WMI Lateral Execution", "LSASS Memory Dumping", "VSS Shadow Deletion"]
            ),
            ThreatShield(
                threat_vector=ThreatVectorEnum.ZERO_DAY_RCE,
                future_immunity_pct=94.0,
                protective_mechanism="AI-based memory exploit prevention, process hollowing interception, and inline shellcode blocking",
                neutralized_attack_types=["Memory Corruption", "Heap Spray", "JIT Injection", "Unpatched Deserialization"]
            ),
            ThreatShield(
                threat_vector=ThreatVectorEnum.DATA_EXFILTRATION,
                future_immunity_pct=88.5,
                protective_mechanism="Endpoint telemetry exfiltration sensor tracking anomalous socket connections and bulk file reads",
                neutralized_attack_types=["DNS Tunneling", "Encrypted Staging", "Cloud Storage Dumping"]
            ),
        ]
    ),

    # 2. Endpoint / IAM: Microsoft Defender & Entra Suite
    "VND-MSFT-SEC": VendorProductProfile(
        vendor_id="VND-MSFT-SEC",
        vendor_name="Microsoft",
        product_name="Microsoft Defender for Cloud & Entra ID Suite",
        category="EDR",
        annual_cost_usd=9500.0,
        annual_cost_inr=9500.0 * USD_TO_INR_RATE,
        overall_coverage_rating=89.5,
        recommendation_tags=["Budget Friendly", "Ecosystem Native", "Enterprise Standard"],
        compliance_alignment=["ISO 27001", "NIST CSF", "CIS Controls"],
        associated_control_id="CTRL-EDR",
        target_node_ids=["BC-PAY-GW-01", "BC-API-GW-01"],
        rosi_estimate_pct=265.8,
        future_threat_shields=[
            ThreatShield(
                threat_vector=ThreatVectorEnum.CREDENTIAL_STUFFING,
                future_immunity_pct=92.0,
                protective_mechanism="Azure AD Identity Protection with global leaked credential database correlation and risk-based conditional access",
                neutralized_attack_types=["Password Spraying", "Brute Force", "Token Replay"]
            ),
            ThreatShield(
                threat_vector=ThreatVectorEnum.RANSOMWARE_LATERAL,
                future_immunity_pct=88.0,
                protective_mechanism="Defender for Endpoint behavioral heuristics and automated remediation playbooks",
                neutralized_attack_types=["SMB Lateral Movement", "Credential Dumping"]
            ),
            ThreatShield(
                threat_vector=ThreatVectorEnum.ZERO_DAY_RCE,
                future_immunity_pct=86.5,
                protective_mechanism="Attack surface reduction rules and cloud-delivered protection definitions",
                neutralized_attack_types=["Office Macro Exploits", "Living-off-the-Land Binaries"]
            ),
        ]
    ),

    # 3. Perimeter / WAF: Cloudflare Enterprise WAF & Magic Transit
    "VND-CLDF-WAF": VendorProductProfile(
        vendor_id="VND-CLDF-WAF",
        vendor_name="Cloudflare",
        product_name="Cloudflare Enterprise WAF & Magic Transit",
        category="WAF",
        annual_cost_usd=14400.0,
        annual_cost_inr=14400.0 * USD_TO_INR_RATE,
        overall_coverage_rating=98.0,
        recommendation_tags=["Perimeter Benchmark", "Ultra Low Latency", "DDoS Shield Leader"],
        compliance_alignment=["ISO 27001", "PCI-DSS 4.0", "RBI CSF", "NIST CSF"],
        associated_control_id="CTRL-WAF",
        target_node_ids=["BC-API-GW-01", "BC-FLASH-SALE-01"],
        rosi_estimate_pct=348.5,
        future_threat_shields=[
            ThreatShield(
                threat_vector=ThreatVectorEnum.VOLUMETRIC_DDOS,
                future_immunity_pct=99.8,
                protective_mechanism="Anycast distributed edge scrubbing network with >280 Tbps capacity and sub-second automated SYN/UDP filtering",
                neutralized_attack_types=["SYN Flood", "UDP Amplification", "HTTP/2 Rapid Reset", "Slowloris"]
            ),
            ThreatShield(
                threat_vector=ThreatVectorEnum.CREDENTIAL_STUFFING,
                future_immunity_pct=96.0,
                protective_mechanism="Behavioral ML bot management, biometric fingerprinting, and frictionless Turnstile managed challenges",
                neutralized_attack_types=["Automated Botnet Login", "Dictionary Attack", "API Token Scraping"]
            ),
            ThreatShield(
                threat_vector=ThreatVectorEnum.ZERO_DAY_RCE,
                future_immunity_pct=91.5,
                protective_mechanism="Global edge WAF ruleset updated within 15 minutes of 0-day vulnerability disclosure",
                neutralized_attack_types=["SQL Injection", "Log4j JNDI RCE", "Spring4Shell", "Command Injection"]
            ),
        ]
    ),

    # 4. Identity / IAM: Okta Workforce Identity Cloud
    "VND-OKTA-IAM": VendorProductProfile(
        vendor_id="VND-OKTA-IAM",
        vendor_name="Okta",
        product_name="Okta Workforce Identity Cloud & Zero-Trust Access",
        category="IAM",
        annual_cost_usd=8500.0,
        annual_cost_inr=8500.0 * USD_TO_INR_RATE,
        overall_coverage_rating=94.5,
        recommendation_tags=["Zero-Trust Leader", "FIDO2 Phishing-Resistant", "Identity Gold Standard"],
        compliance_alignment=["ISO 27001", "NIST CSF", "CIS Controls", "RBI CSF"],
        associated_control_id="CTRL-MFA",
        target_node_ids=["BC-API-GW-01", "BC-PAY-GW-01"],
        rosi_estimate_pct=289.0,
        future_threat_shields=[
            ThreatShield(
                threat_vector=ThreatVectorEnum.CREDENTIAL_STUFFING,
                future_immunity_pct=98.5,
                protective_mechanism="FIDO2 WebAuthn phishing-resistant hardware keys and adaptive contextual risk step-up authentication",
                neutralized_attack_types=["Credential Stuffing", "AiTM Phishing", "Session Hijacking", "SIM Swapping"]
            ),
            ThreatShield(
                threat_vector=ThreatVectorEnum.RANSOMWARE_LATERAL,
                future_immunity_pct=89.0,
                protective_mechanism="Privileged Access Management with just-in-time ephemeral credential brokering and session recording",
                neutralized_attack_types=["Privilege Escalation", "Pass-the-Hash", "Kerberoasting"]
            ),
            ThreatShield(
                threat_vector=ThreatVectorEnum.DATA_EXFILTRATION,
                future_immunity_pct=85.0,
                protective_mechanism="Device posture verification and continuous token revocation upon suspicious egress behavior",
                neutralized_attack_types=["Unauthorized Portal Access", "Token Theft"]
            ),
        ]
    ),

    # 5. Cloud / CSPM: Wiz Cloud Security Platform
    "VND-WIZ-CSPM": VendorProductProfile(
        vendor_id="VND-WIZ-CSPM",
        vendor_name="Wiz",
        product_name="Wiz Cloud Security Platform (CSPM / CNAPP / DSPM)",
        category="CSPM",
        annual_cost_usd=11000.0,
        annual_cost_inr=11000.0 * USD_TO_INR_RATE,
        overall_coverage_rating=97.0,
        recommendation_tags=["Cloud Native Leader", "Full Graph Context", "DSPM Pioneer"],
        compliance_alignment=["ISO 27001", "NIST CSF", "CIS Controls", "SEBI CSCRF", "DPDP Act"],
        associated_control_id="CTRL-S3-ENCR",
        target_node_ids=["BC-PII-VAULT-01", "BC-FLASH-SALE-01"],
        rosi_estimate_pct=324.6,
        future_threat_shields=[
            ThreatShield(
                threat_vector=ThreatVectorEnum.DATA_EXFILTRATION,
                future_immunity_pct=97.5,
                protective_mechanism="Agentless cloud configuration graph correlation, automated S3 bucket public-access lockdown, and DSPM data lineage",
                neutralized_attack_types=["S3 Bucket Public Leak", "Cloud Credential Exfiltration", "Unencrypted Snapshot Sharing"]
            ),
            ThreatShield(
                threat_vector=ThreatVectorEnum.ZERO_DAY_RCE,
                future_immunity_pct=92.0,
                protective_mechanism="Container runtime vulnerability scanning and toxic risk combination graph path isolation",
                neutralized_attack_types=["Kubernetes Pod Escape", "Vulnerable Base Image RCE", "IAM Role Abuse"]
            ),
            ThreatShield(
                threat_vector=ThreatVectorEnum.RANSOMWARE_LATERAL,
                future_immunity_pct=87.0,
                protective_mechanism="Cloud infrastructure entitlement management (CIEM) enforcing least-privilege identity boundaries",
                neutralized_attack_types=["Cross-Account Lateral Movement", "Cloud KMS Key Tampering"]
            ),
        ]
    ),
}


def get_ceo_vendor_catalog() -> List[VendorProductProfile]:
    """Retrieve full list of vendor profiles for CEO decision matrix."""
    return list(VENDOR_CATALOG.values())


def get_vendor_by_id(vendor_id: str) -> Optional[VendorProductProfile]:
    """
    Retrieve vendor profile by exact ID or case-insensitive substring/alias.
    """
    if not vendor_id:
        return None
    # 1. Exact match
    if vendor_id in VENDOR_CATALOG:
        return VENDOR_CATALOG[vendor_id]

    # 2. Case-insensitive normalization
    v_norm = vendor_id.strip().upper()
    for vid, profile in VENDOR_CATALOG.items():
        if vid.upper() == v_norm:
            return profile

    # 3. Known shorthand aliases
    alias_map = {
        "VND-CRWD": "VND-CRWD-EDR",
        "VND-CROWDSTRIKE": "VND-CRWD-EDR",
        "VND-CROWDSTRIKE-EDR": "VND-CRWD-EDR",
        "CROWDSTRIKE": "VND-CRWD-EDR",
        "CROWDSTRIKE_FALCON": "VND-CRWD-EDR",
        "FALCON": "VND-CRWD-EDR",
        "VND-MSFT": "VND-MSFT-SEC",
        "VND-MICROSOFT": "VND-MSFT-SEC",
        "MICROSOFT": "VND-MSFT-SEC",
        "MICROSOFT_DEFENDER": "VND-MSFT-SEC",
        "MICROSOFT_DEFENDER_SENTINEL": "VND-MSFT-SEC",
        "DEFENDER": "VND-MSFT-SEC",
        "VND-CLDF": "VND-CLDF-WAF",
        "VND-CLOUDFLARE": "VND-CLDF-WAF",
        "VND-CLOUDFLARE-WAF": "VND-CLDF-WAF",
        "CLOUDFLARE": "VND-CLDF-WAF",
        "CLOUDFLARE_MAGIC_TRANSIT": "VND-CLDF-WAF",
        "MAGIC_TRANSIT": "VND-CLDF-WAF",
        "VND-OKTA": "VND-OKTA-IAM",
        "OKTA": "VND-OKTA-IAM",
        "OKTA_WORKFORCE_IDENTITY": "VND-OKTA-IAM",
        "VND-WIZ": "VND-WIZ-CSPM",
        "WIZ": "VND-WIZ-CSPM",
        "WIZ_CLOUD_SECURITY": "VND-WIZ-CSPM",
    }
    if v_norm in alias_map:
        return VENDOR_CATALOG[alias_map[v_norm]]

    # 4. Keyword and fuzzy brand matching
    v_clean = vendor_id.strip().lower().replace("_", " ").replace("-", " ")
    if "crowd" in v_clean or "falcon" in v_clean:
        return VENDOR_CATALOG["VND-CRWD-EDR"]
    if "cloud" in v_clean and ("flare" in v_clean or "magic" in v_clean or "transit" in v_clean):
        return VENDOR_CATALOG["VND-CLDF-WAF"]
    if "okta" in v_clean:
        return VENDOR_CATALOG["VND-OKTA-IAM"]
    if "wiz" in v_clean:
        return VENDOR_CATALOG["VND-WIZ-CSPM"]
    if "microsoft" in v_clean or "defender" in v_clean or "sentinel" in v_clean:
        return VENDOR_CATALOG["VND-MSFT-SEC"]

    for vid, profile in VENDOR_CATALOG.items():
        if vid.lower() in v_clean or profile.vendor_name.lower() in v_clean:
            return profile

    return None


CANONICAL_TO_ALIASES: Dict[str, List[str]] = {
    "VND-CRWD-EDR": ["VND-CRWD", "VND-CROWDSTRIKE", "CROWDSTRIKE"],
    "VND-MSFT-SEC": ["VND-MSFT", "VND-MICROSOFT", "MICROSOFT"],
    "VND-CLDF-WAF": ["VND-CLDF", "VND-CLOUDFLARE", "CLOUDFLARE"],
    "VND-OKTA-IAM": ["VND-OKTA", "OKTA"],
    "VND-WIZ-CSPM": ["VND-WIZ", "WIZ"],
}


def apply_virtual_vendor_purchase(vendor_id: str, current_portfolio: dict) -> dict:
    """
    Apply a one-click virtual vendor purchase to the active investment portfolio.

    Parameters:
    - vendor_id: Vendor identifier (e.g. 'VND-CRWD-EDR', 'crowdstrike', 'VND-CLDF-WAF')
    - current_portfolio: Active investment portfolio state dictionary containing:
        - selected_vendor_ids: List[str]
        - allocated_spend: float
        - baseline_eal: float
        - residual_eal: float
        - risk_mitigated: float
        - currency: str ("INR" or "USD")

    Behavior & Guarantees:
    - Idempotent: If vendor is already purchased, returns current portfolio safely with all metrics.
    - Currency Aware: Deducts cost in active currency (default "INR").
    - Diminishing Returns: Mitigates residual EAL proportionally based on vendor coverage rating.
    - Actuarial Recalculation: Recomputes net_capital_saved, security_upgrade_pct,
      security_posture_score, and portfolio_rosi.
    """
    vendor = get_vendor_by_id(vendor_id)
    if not vendor:
        raise KeyError(f"Vendor '{vendor_id}' not found in VENDOR_CATALOG")

    portfolio = deepcopy(current_portfolio)
    currency = portfolio.get("currency", "INR").upper().strip()

    # 1. Establish baseline EAL first so both duplicate and fresh purchase branches can use it
    default_baseline = 48_200_000.0 if currency == "INR" else (48_200_000.0 / USD_TO_INR_RATE)
    baseline_eal = float(portfolio.get("baseline_eal", default_baseline))
    if baseline_eal <= 0.0:
        baseline_eal = default_baseline
    portfolio["baseline_eal"] = round(baseline_eal, 2)

    matched_id = vendor_id.strip()
    canonical_id = vendor.vendor_id
    aliases = CANONICAL_TO_ALIASES.get(canonical_id, [])
    all_known_ids = {canonical_id, matched_id, *aliases}

    selected_ids = list(portfolio.get("selected_vendor_ids", []))
    if any(vid in selected_ids for vid in all_known_ids):
        current_residual = float(portfolio.get("residual_eal", baseline_eal))
        portfolio["residual_eal"] = round(current_residual, 2)

        risk_mitigated = float(portfolio.get("risk_mitigated", max(0.0, baseline_eal - current_residual)))
        portfolio["risk_mitigated"] = round(risk_mitigated, 2)

        allocated_spend = float(portfolio.get("allocated_spend", 0.0))
        portfolio["allocated_spend"] = round(allocated_spend, 2)

        portfolio["status"] = "ALREADY_PURCHASED"
        portfolio["message"] = f"{vendor.product_name} is already active in portfolio."
        portfolio["vendor_id"] = matched_id or canonical_id
        portfolio["canonical_vendor_id"] = canonical_id
        portfolio["last_purchased_vendor_id"] = canonical_id
        portfolio["last_purchased_vendor_name"] = vendor.vendor_name
        portfolio["last_purchased_product_name"] = vendor.product_name
        portfolio["purchased_vendor_ids"] = list(selected_ids)

        # Ensure all required actuarial metric keys are populated and not missing
        if "net_capital_saved" not in portfolio:
            portfolio["net_capital_saved"] = calculate_net_capital_saved(baseline_eal, current_residual)
        else:
            portfolio["net_capital_saved"] = round(float(portfolio["net_capital_saved"]), 2)

        if "security_upgrade_pct" not in portfolio:
            portfolio["security_upgrade_pct"] = calculate_security_upgrade_pct(risk_mitigated, baseline_eal)
        else:
            portfolio["security_upgrade_pct"] = round(float(portfolio["security_upgrade_pct"]), 2)

        if "security_posture_score" not in portfolio:
            portfolio["security_posture_score"] = calculate_security_posture_score(
                baseline_eal=baseline_eal,
                current_eal=current_residual,
                control_count=len(selected_ids),
            )
        else:
            portfolio["security_posture_score"] = round(float(portfolio["security_posture_score"]), 2)

        if "portfolio_rosi" not in portfolio:
            portfolio["portfolio_rosi"] = round(calculate_rosi(risk_mitigated, allocated_spend), 1)
        else:
            portfolio["portfolio_rosi"] = round(float(portfolio["portfolio_rosi"]), 1)

        return portfolio

    # 1. Add vendor to active funded list
    if canonical_id and canonical_id not in selected_ids:
        selected_ids.append(canonical_id)

    portfolio["selected_vendor_ids"] = selected_ids
    portfolio["purchased_vendor_ids"] = list(selected_ids)

    # 2. Add vendor cost to spend
    vendor_cost = vendor.get_cost(currency)
    current_spend = float(portfolio.get("allocated_spend", 0.0))
    new_spend = current_spend + vendor_cost
    portfolio["allocated_spend"] = round(new_spend, 2)

    # 3. Retrieve or establish residual EAL
    current_residual = float(portfolio.get("residual_eal", baseline_eal))

    # 4. Compute incremental risk mitigation with diminishing marginal returns
    coverage_factor = (vendor.overall_coverage_rating / 100.0)
    incremental_mitigation = min(current_residual, current_residual * coverage_factor * 0.35)

    new_residual = max(0.0, current_residual - incremental_mitigation)
    new_risk_mitigated = max(0.0, baseline_eal - new_residual)

    portfolio["residual_eal"] = round(new_residual, 2)
    portfolio["risk_mitigated"] = round(new_risk_mitigated, 2)

    # 5. Actuarial Metrics Recomputation
    portfolio["net_capital_saved"] = calculate_net_capital_saved(baseline_eal, new_residual)
    portfolio["security_upgrade_pct"] = calculate_security_upgrade_pct(new_risk_mitigated, baseline_eal)
    portfolio["security_posture_score"] = calculate_security_posture_score(
        baseline_eal=baseline_eal,
        current_eal=new_residual,
        control_count=len(selected_ids),
    )
    portfolio["portfolio_rosi"] = round(calculate_rosi(new_risk_mitigated, new_spend), 1)

    # 6. Status & metadata
    portfolio["status"] = "PURCHASED"
    portfolio["vendor_id"] = matched_id or canonical_id
    portfolio["canonical_vendor_id"] = canonical_id
    portfolio["last_purchased_vendor_id"] = canonical_id
    portfolio["last_purchased_vendor_name"] = vendor.vendor_name
    portfolio["last_purchased_product_name"] = vendor.product_name

    return portfolio
