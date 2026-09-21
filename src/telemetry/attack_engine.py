"""
src/telemetry/attack_engine.py - Attack Dynamics and Telemetry Ticker State Engine.
Provides calibrated attack impact modeling on BharatCart topology and thread-safe demonstration state.
"""

from datetime import datetime, timezone
from enum import Enum
import math
import random
import threading
from typing import Any, Dict, List, Optional, Union
import uuid
from pydantic import BaseModel, Field

from src.config import USD_TO_INR_RATE, inr_to_usd, usd_to_inr


class AttackType(str, Enum):
    DDOS_SURGE = "ddos_surge"
    RANSOMWARE_OUTAGE = "ransomware_outage"
    SQL_DATA_LEAK = "sql_data_leak"
    CREDENTIAL_STUFFING = "credential_stuffing"
    ZERO_DAY_CVE = "zero_day_cve"
    CLOUD_IAM_COMPROMISE = "cloud_iam_compromise"

    @classmethod
    def _missing_(cls, value: object) -> Any:
        if isinstance(value, str):
            norm = value.lower().strip().replace(" ", "_").replace("-", "_")
            for member in cls:
                if member.value == norm:
                    return member
                if norm in member.value:
                    return member
        return None


class BharatCartNode(str, Enum):
    API_GATEWAY = "BC-API-GW-01"
    FLASH_SALE = "BC-FLASH-SALE-01"
    PAYMENT_GATEWAY = "BC-PAY-GW-01"
    PII_VAULT = "BC-PII-VAULT-01"


DEFAULT_TARGET_NODES: Dict[AttackType, str] = {
    AttackType.DDOS_SURGE: "BC-API-GW-01",
    AttackType.RANSOMWARE_OUTAGE: "BC-PAY-GW-01",
    AttackType.SQL_DATA_LEAK: "BC-PII-VAULT-01",
    AttackType.CREDENTIAL_STUFFING: "BC-FLASH-SALE-01",
    AttackType.ZERO_DAY_CVE: "BC-FLASH-SALE-01",
    AttackType.CLOUD_IAM_COMPROMISE: "BC-API-GW-01",
}

# Nominal attack parameters calibrated to +₹4.58 Cr baseline surge at intensity 5.0
ATTACK_CALIBRATIONS: Dict[AttackType, Dict[str, Any]] = {
    AttackType.DDOS_SURGE: {
        "nominal_tef": 12.0,
        "direct_loss_inr": 5_960_000.0,
        "cascading_loss_inr": 39_840_000.0,
        "total_surge_inr": 45_800_000.0,
        "posture_alpha": 9.314,  # yields 32.6 pts drop at intensity 5.0
        "recommended_control_id": "CTRL-WAF",
        "recommended_product_id": "VND-CLDF-WAF",
        "recommended_countermeasure": (
            "Deploy Cloudflare Enterprise WAF & Layer 7 Scrubbing (CTRL-WAF) "
            "to absorb volumetric flood at edge (>280 Tbps capacity)."
        ),
        "neutralization_efficacy": 0.994,
    },
    AttackType.RANSOMWARE_OUTAGE: {
        "nominal_tef": 4.0,
        "direct_loss_inr": 27_000_000.0,
        "cascading_loss_inr": 18_800_000.0,
        "total_surge_inr": 45_800_000.0,
        "posture_alpha": 11.600,  # yields 40.6 pts drop at intensity 5.0
        "recommended_control_id": "CTRL-EDR",
        "recommended_product_id": "VND-CRWD-EDR",
        "recommended_countermeasure": (
            "Activate CrowdStrike Falcon Complete EDR (CTRL-EDR) with kernel anti-tamper "
            "and automated host isolation within 45 seconds."
        ),
        "neutralization_efficacy": 0.965,
    },
    AttackType.SQL_DATA_LEAK: {
        "nominal_tef": 2.5,
        "direct_loss_inr": 33_000_000.0,
        "cascading_loss_inr": 12_800_000.0,
        "total_surge_inr": 45_800_000.0,
        "posture_alpha": 13.314,  # yields 46.6 pts drop at intensity 5.0
        "recommended_control_id": "CTRL-S3-ENCR",
        "recommended_product_id": "VND-WIZ-CSPM",
        "recommended_countermeasure": (
            "Deploy Wiz Cloud Security Platform & Data Guardrails (CTRL-S3-ENCR) "
            "to enforce database PII egress isolation and kill query bypasses."
        ),
        "neutralization_efficacy": 0.974,
    },
    AttackType.CREDENTIAL_STUFFING: {
        "nominal_tef": 25.0,
        "direct_loss_inr": 18_000_000.0,
        "cascading_loss_inr": 27_800_000.0,
        "total_surge_inr": 45_800_000.0,
        "posture_alpha": 7.143,  # bounded to 25.0 pts drop at intensity 5.0
        "recommended_control_id": "CTRL-MFA",
        "recommended_product_id": "VND-OKTA-IAM",
        "recommended_countermeasure": (
            "Enforce Okta Workforce Identity Cloud FIDO2 Hardware MFA (CTRL-MFA) "
            "with behavioral biometrics and threat credential matching."
        ),
        "neutralization_efficacy": 0.985,
    },
    AttackType.ZERO_DAY_CVE: {
        "nominal_tef": 6.0,
        "direct_loss_inr": 21_000_000.0,
        "cascading_loss_inr": 24_800_000.0,
        "total_surge_inr": 45_800_000.0,
        "posture_alpha": 12.000,  # yields 42.0 pts drop at intensity 5.0
        "recommended_control_id": "CTRL-EDR",
        "recommended_product_id": "VND-CRWD-EDR",
        "recommended_countermeasure": (
            "Deploy CrowdStrike Falcon Complete (CTRL-EDR) zero-day behavioral sandbox "
            "and live memory protection."
        ),
        "neutralization_efficacy": 0.982,
    },
    AttackType.CLOUD_IAM_COMPROMISE: {
        "nominal_tef": 8.0,
        "direct_loss_inr": 19_500_000.0,
        "cascading_loss_inr": 26_300_000.0,
        "total_surge_inr": 45_800_000.0,
        "posture_alpha": 10.500,  # yields 36.75 pts drop at intensity 5.0
        "recommended_control_id": "CTRL-MFA",
        "recommended_product_id": "VND-OKTA-IAM",
        "recommended_countermeasure": (
            "Enforce Okta Workforce Identity PAM session revocation and privileged IAM lockdown."
        ),
        "neutralization_efficacy": 0.988,
    },
}


class AttackCalculationResult(BaseModel):
    attack_id: str
    timestamp: datetime
    attack_type: AttackType
    target_node: str
    intensity: float
    tef_spike_multiplier: float
    nominal_tef: float
    spiked_tef: float
    baseline_eal_inr: float
    direct_loss_inr: float
    cascading_loss_inr: float
    total_surge_inr: float
    spiked_eal_inr: float
    spiked_eal_usd: float
    posture_degradation_pts: float
    posture_drift_pct: float = 0.0
    posture_before: float
    posture_after: float
    var_90_inr: float = 82_000_000.0
    var_95_inr: float = 124_000_000.0
    var_99_inr: float = 241_000_000.0
    recommended_control_id: str
    recommended_product_id: str
    recommended_countermeasure: str
    neutralization_efficacy: float
    source_device: str = "Remote Network Device"


def calculate_attack_impact(
    attack_type: AttackType,
    target_node: Optional[str] = None,
    intensity: float = 5.0,
    baseline_eal_inr: float = 48_200_000.0,
    baseline_posture: float = 84.6,
    active_defense_immunity: float = 0.0,
    source_device: str = "Remote Network Device",
) -> AttackCalculationResult:
    """
    Computes mathematical impact of an injected attack:
      1. delta_tef = 1.0 + intensity * 0.5
      2. direct & cascading EAL surge (+4.58 Cr baseline surge at intensity=5.0)
      3. posture degradation bounded in [25.0, 50.0] points
      4. contextual countermeasure recommendation
    """
    if isinstance(attack_type, str):
        attack_type = AttackType(attack_type)
    calib = ATTACK_CALIBRATIONS[attack_type]
    tgt = target_node or DEFAULT_TARGET_NODES[attack_type]
    clamped_intensity = max(1.0, min(10.0, float(intensity)))

    # 1. Threat Event Frequency Surge formula & immunity normalization
    if math.isnan(active_defense_immunity) or math.isinf(active_defense_immunity):
        clamped_immunity = 0.0
    else:
        clamped_immunity = max(0.0, min(1.0, float(active_defense_immunity)))

    raw_delta_tef = 1.0 + (clamped_intensity * 0.5)
    effective_delta_tef = raw_delta_tef * (1.0 - clamped_immunity)
    nom_tef = calib["nominal_tef"]
    spiked_tef = nom_tef * (1.0 + effective_delta_tef)

    # 2. Scaled EAL Surge (+₹4.58 Cr at intensity 5.0)
    # Scaling ratio relative to reference intensity 5.0 (where raw_delta_tef = 3.5)
    scaling_ratio = raw_delta_tef / 3.5
    defense_factor = max(0.0, 1.0 - (clamped_immunity * calib["neutralization_efficacy"]))

    direct_surge = calib["direct_loss_inr"] * scaling_ratio * defense_factor
    cascading_surge = calib["cascading_loss_inr"] * scaling_ratio * defense_factor
    total_surge = direct_surge + cascading_surge
    current_eal = baseline_eal_inr + total_surge
    spiked_eal = max(1000.0, current_eal)

    # Dynamic VaR Scaling (Preserves EAL < VaR90 < VaR95 < VaR99 invariant)
    var_scale = spiked_eal / max(1.0, baseline_eal_inr)
    var_90 = round(82_000_000.0 * (1.0 + (var_scale - 1.0) * 0.85), 2)
    var_95 = round(124_000_000.0 * (1.0 + (var_scale - 1.0) * 0.88), 2)
    var_99 = round(241_000_000.0 * (1.0 + (var_scale - 1.0) * 0.92), 2)

    # Defensive mathematical invariant clamp: strictly guarantee 0 < EAL < VaR90 < VaR95 < VaR99
    var_90 = max(var_90, round(spiked_eal * 1.10, 2))
    var_95 = max(var_95, round(var_90 * 1.15, 2))
    var_99 = max(var_99, round(var_95 * 1.25, 2))

    # 3. Posture Score Degradation (bounded in [25.0, 50.0] points)
    raw_drop = calib["posture_alpha"] * raw_delta_tef * defense_factor
    clamped_drop = max(25.0, min(50.0, raw_drop))
    posture_after = max(5.0, min(100.0, baseline_posture - clamped_drop))
    posture_drift = -round((clamped_drop / max(1.0, baseline_posture)) * 100.0, 1)

    return AttackCalculationResult(
        attack_id=f"atk-{uuid.uuid4().hex[:8]}",
        timestamp=datetime.now(timezone.utc),
        attack_type=attack_type,
        target_node=tgt,
        intensity=clamped_intensity,
        tef_spike_multiplier=round(raw_delta_tef, 3),
        nominal_tef=nom_tef,
        spiked_tef=round(spiked_tef, 2),
        baseline_eal_inr=baseline_eal_inr,
        direct_loss_inr=round(direct_surge, 2),
        cascading_loss_inr=round(cascading_surge, 2),
        total_surge_inr=round(total_surge, 2),
        spiked_eal_inr=round(spiked_eal, 2),
        spiked_eal_usd=round(inr_to_usd(spiked_eal), 2),
        posture_degradation_pts=round(clamped_drop, 1),
        posture_drift_pct=posture_drift,
        posture_before=round(baseline_posture, 1),
        posture_after=round(posture_after, 1),
        var_90_inr=var_90,
        var_95_inr=var_95,
        var_99_inr=var_99,
        recommended_control_id=calib["recommended_control_id"],
        recommended_product_id=calib["recommended_product_id"],
        recommended_countermeasure=calib["recommended_countermeasure"],
        neutralization_efficacy=calib["neutralization_efficacy"],
        source_device=source_device,
    )


class DemoAttackStateManager:
    """
    Thread-safe in-memory singleton state manager tracking active attacks,
    vendor procurement, and dynamic SOC telemetry jitter.
    """
    _instance = None
    _lock = threading.RLock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DemoAttackStateManager, cls).__new__(cls)
                cls._instance._init_state()
            return cls._instance

    def _init_state(self):
        self.baseline_eal_inr: float = 48_200_000.0
        self.current_eal_inr: float = 48_200_000.0
        self.baseline_posture: float = 84.6
        self.current_posture: float = 84.6
        self.active_attack: Optional[AttackCalculationResult] = None
        self.active_attacks: List[Dict[str, Any]] = []
        self.funded_control_ids: set = set()
        self.purchased_vendor_ids: set = set()
        self.rng = random.Random(42)
        self.recent_events: List[Dict[str, Any]] = []
        self._init_seed_events()

    def _init_seed_events(self):
        now = datetime.now(timezone.utc).isoformat()
        self.recent_events = [
            {"time": now, "level": "INFO", "msg": "API Gateway rate-limiting normal (14,820 req/s)", "node": "BC-API-GW-01"},
            {"time": now, "level": "INFO", "msg": "KMS key rotation verified for PII Vault", "node": "BC-PII-VAULT-01"},
            {"time": now, "level": "WARN", "msg": "Isolated TLS 1.0 probe dropped from 185.220.101.5", "node": "BC-PAY-GW-01"},
            {"time": now, "level": "INFO", "msg": "Flash sale inventory lock heartbeat active (2ms)", "node": "BC-FLASH-SALE-01"},
        ]

    def inject(
        self,
        attack_type: Union[AttackType, str],
        target_node: Optional[str] = None,
        intensity: float = 5.0,
        source_device: str = "Remote Network Device",
    ) -> AttackCalculationResult:
        with self._lock:
            if isinstance(attack_type, str):
                attack_type = AttackType(attack_type)

            calib = ATTACK_CALIBRATIONS[attack_type]
            immunity = (
                calib["neutralization_efficacy"]
                if (calib["recommended_control_id"] in self.funded_control_ids
                    or calib["recommended_product_id"] in self.purchased_vendor_ids)
                else 0.0
            )

            res = calculate_attack_impact(
                attack_type=attack_type,
                target_node=target_node,
                intensity=intensity,
                baseline_eal_inr=self.baseline_eal_inr,
                baseline_posture=self.baseline_posture,
                active_defense_immunity=immunity,
                source_device=source_device,
            )
            self.active_attack = res
            self.current_eal_inr = max(1000.0, res.spiked_eal_inr)
            self.current_posture = res.posture_after

            attack_dict = res.model_dump()
            self.active_attacks.append(attack_dict)

            now_str = datetime.now(timezone.utc).isoformat()
            self.recent_events.insert(0, {
                "time": now_str,
                "level": "CRITICAL",
                "msg": f"ATTACK INJECTED: {attack_type.value.upper().replace('_', ' ')} on {res.target_node} (Intensity {res.intensity:.1f}x) from {source_device}",
                "node": res.target_node,
            })
            if len(self.recent_events) > 15:
                self.recent_events.pop()

            return res

    def reset(self) -> Dict[str, Any]:
        """Restores baseline state."""
        with self._lock:
            count = len(self.active_attacks)
            self.active_attack = None
            self.active_attacks.clear()
            self.purchased_vendor_ids.clear()
            self.funded_control_ids.clear()
            self.current_eal_inr = self.baseline_eal_inr
            self.current_posture = self.baseline_posture
            self._init_seed_events()
            return {
                "success": True,
                "status": "RESET_COMPLETED",
                "active_attack": False,
                "message": "BharatCart demonstration environment successfully restored to nominal baseline.",
                "baseline_eal_inr": self.baseline_eal_inr,
                "baseline_posture": self.baseline_posture,
                "active_attacks_cleared": count,
                "current_eal": self.current_eal_inr,
                "posture_score": self.current_posture,
                "currency": "INR",
            }

    def fund_control(self, control_id: str) -> None:
        with self._lock:
            self.funded_control_ids.add(control_id)

    def apply_vendor_purchase(self, vendor_id: str, currency: str = "INR") -> Dict[str, Any]:
        """Applies virtual vendor purchase to live demo state with strict idempotency."""
        with self._lock:
            from src.optimization.vendor_benchmarking import (
                get_vendor_by_id,
                apply_virtual_vendor_purchase,
                CANONICAL_TO_ALIASES,
            )
            from src.optimization.rosi import (
                calculate_security_upgrade_pct,
                calculate_net_capital_saved,
                calculate_security_posture_score,
                calculate_rosi,
            )
            vendor = get_vendor_by_id(vendor_id)
            if not vendor:
                raise ValueError(f"Vendor '{vendor_id}' not found in catalog")

            rate = 1.0 if currency.upper() == "INR" else (1.0 / USD_TO_INR_RATE)
            matched_id = vendor_id.strip()
            canonical_id = vendor.vendor_id
            aliases = CANONICAL_TO_ALIASES.get(canonical_id, [])
            all_known = {canonical_id, matched_id, *aliases}

            # Check if vendor is already purchased (Idempotency Guard)
            if any(vid in self.purchased_vendor_ids for vid in all_known):
                unique_canonical_vids = {
                    get_vendor_by_id(vid).vendor_id
                    for vid in self.purchased_vendor_ids
                    if get_vendor_by_id(vid) is not None
                }
                total_spend = sum(
                    get_vendor_by_id(vid).get_cost(currency)
                    for vid in unique_canonical_vids
                )
                mitigated_inr = max(0.0, self.baseline_eal_inr - self.current_eal_inr)
                sup_pct = calculate_security_upgrade_pct(mitigated_inr, self.baseline_eal_inr)
                net_saved = calculate_net_capital_saved(self.baseline_eal_inr * rate, self.current_eal_inr * rate)
                rosi_val = round(calculate_rosi(mitigated_inr * rate, total_spend), 1)

                return {
                    "vendor_id": matched_id or canonical_id,
                    "canonical_vendor_id": canonical_id,
                    "product_name": vendor.product_name,
                    "vendor_name": vendor.vendor_name,
                    "category": vendor.category,
                    "allocated_spend": round(total_spend, 2),
                    "allocated_spend_inr": vendor.annual_cost_inr,
                    "allocated_spend_usd": vendor.annual_cost_usd,
                    "baseline_eal": round(self.baseline_eal_inr * rate, 2),
                    "residual_eal": round(self.current_eal_inr * rate, 2),
                    "risk_mitigated": round(mitigated_inr * rate, 2),
                    "security_upgrade_pct": sup_pct,
                    "security_factor_score": self.current_posture,
                    "net_capital_saved": net_saved,
                    "security_posture_score": self.current_posture,
                    "posture_score": self.current_posture,
                    "risk_factor": round((self.current_eal_inr / self.baseline_eal_inr) * 4.8, 1),
                    "future_shields_unlocked": len(vendor.future_threat_shields) if hasattr(vendor, "future_threat_shields") else 2,
                    "portfolio_rosi": rosi_val,
                    "currency": currency.upper(),
                    "status": "ALREADY_PURCHASED",
                    "purchased_vendor_ids": list(self.purchased_vendor_ids),
                }

            # Cumulative spend prior to adding current vendor
            unique_canonical_vids = {
                get_vendor_by_id(vid).vendor_id
                for vid in self.purchased_vendor_ids
                if get_vendor_by_id(vid) is not None
            }
            prior_spend = sum(
                get_vendor_by_id(vid).get_cost(currency)
                for vid in unique_canonical_vids
            )

            portfolio = {
                "selected_vendor_ids": list(self.purchased_vendor_ids),
                "allocated_spend": prior_spend,
                "baseline_eal": self.baseline_eal_inr,
                "residual_eal": self.current_eal_inr,
                "risk_mitigated": max(0.0, self.baseline_eal_inr - self.current_eal_inr),
                "currency": currency,
            }
            updated = apply_virtual_vendor_purchase(vendor_id, portfolio)

            self.purchased_vendor_ids.add(canonical_id)
            if matched_id:
                self.purchased_vendor_ids.add(matched_id)
            for alias in aliases:
                self.purchased_vendor_ids.add(alias)

            if vendor.associated_control_id:
                self.funded_control_ids.add(vendor.associated_control_id)

            self.current_eal_inr = max(1000.0, float(updated.get("residual_eal", self.current_eal_inr)))
            # Posture boost proportional to mitigated risk
            posture_boost = round((updated.get("risk_mitigated", 0.0) / self.baseline_eal_inr) * 35.0, 1)
            self.current_posture = min(98.5, round(self.current_posture + posture_boost, 1))

            return {
                "vendor_id": matched_id or canonical_id,
                "canonical_vendor_id": canonical_id,
                "product_name": vendor.product_name,
                "vendor_name": vendor.vendor_name,
                "category": vendor.category,
                "allocated_spend": updated.get("allocated_spend", 0.0),
                "allocated_spend_inr": vendor.annual_cost_inr,
                "allocated_spend_usd": vendor.annual_cost_usd,
                "baseline_eal": round(self.baseline_eal_inr * rate, 2),
                "residual_eal": round(self.current_eal_inr * rate, 2),
                "risk_mitigated": updated.get("risk_mitigated", 0.0),
                "security_upgrade_pct": updated.get("security_upgrade_pct", 0.0),
                "security_factor_score": self.current_posture,
                "net_capital_saved": updated.get("net_capital_saved", 0.0),
                "security_posture_score": self.current_posture,
                "posture_score": self.current_posture,
                "risk_factor": round((self.current_eal_inr / self.baseline_eal_inr) * 4.8, 1),
                "future_shields_unlocked": len(vendor.future_threat_shields) if hasattr(vendor, "future_threat_shields") else 2,
                "portfolio_rosi": updated.get("portfolio_rosi", 0.0),
                "currency": currency.upper(),
                "status": updated.get("status", "PURCHASED"),
                "purchased_vendor_ids": list(self.purchased_vendor_ids),
            }

    def get_telemetry_pulse(self) -> Dict[str, Any]:
        """Generates continuous stochastic walk pulse every 2-3s."""
        with self._lock:
            base_eps = 14_850.0
            base_tef = 12.4
            base_alerts = 11

            if self.active_attack:
                spike_mul = self.active_attack.tef_spike_multiplier
                eps = base_eps * (1.0 + spike_mul * 0.65) + self.rng.gauss(0, 350.0)
                tef = self.active_attack.spiked_tef + self.rng.uniform(-0.5, 0.5)
                alerts = int(base_alerts + (4.0 * self.active_attack.intensity) + self.rng.choice([-1, 0, 1]))
                threat_level = "CRITICAL_ATTACK_ACTIVE"
            else:
                eps = base_eps * (1.0 + self.rng.gauss(0, 0.025))
                tef = base_tef * (1.0 + self.rng.uniform(-0.04, 0.04))
                alerts = max(5, min(20, base_alerts + self.rng.choice([-1, 0, 1])))
                threat_level = "NORMAL"

            now = datetime.now(timezone.utc)
            node_statuses = [
                {
                    "node": "BC-API-GW-01",
                    "name": "API Gateway",
                    "status": "SURGING" if any(a["target_node"] == "BC-API-GW-01" for a in self.active_attacks) else "ONLINE",
                },
                {
                    "node": "BC-FLASH-SALE-01",
                    "name": "Flash Sale Microservice",
                    "status": "DEGRADED" if any(a["target_node"] == "BC-FLASH-SALE-01" for a in self.active_attacks) else "ONLINE",
                },
                {
                    "node": "BC-PAY-GW-01",
                    "name": "Payment Gateway",
                    "status": "ATTACKED" if any(a["target_node"] == "BC-PAY-GW-01" for a in self.active_attacks) else "ONLINE",
                },
                {
                    "node": "BC-PII-VAULT-01",
                    "name": "Customer PII Vault",
                    "status": "COMPROMISED" if any(a["target_node"] == "BC-PII-VAULT-01" for a in self.active_attacks) else "ONLINE",
                },
            ]

            is_attack = self.active_attack is not None
            attack_type_str = self.active_attack.attack_type.value if self.active_attack else None
            target_node_str = self.active_attack.target_node if self.active_attack else None
            rf = round((self.current_eal_inr / self.baseline_eal_inr) * 4.8, 1)

            # Dynamic stochastic background SOC telemetry events
            if self.rng.random() < 0.4 and not self.active_attack:
                sample_events = [
                    ("INFO", "API Gateway ingress rate normalized at 14,840 req/s", "BC-API-GW-01"),
                    ("INFO", "Automated TLS certificate renewal verified for Payment Gateway", "BC-PAY-GW-01"),
                    ("INFO", "PostgreSQL connection pool healthy (12 active, 0 stalled)", "BC-PII-VAULT-01"),
                    ("WARN", "Transient latency spike (48ms) on Flash Sale service mitigated", "BC-FLASH-SALE-01"),
                    ("INFO", "WAF zero-trust rule matrix re-indexed successfully", "BC-API-GW-01"),
                    ("INFO", "IAM role session token refreshed with FIDO2 MFA confirmation", "BC-API-GW-01"),
                    ("WARN", "Single suspicious brute-force probe from external IP dropped", "BC-API-GW-01"),
                    ("INFO", "EDR memory integrity verification completed with zero IOCs", "BC-PAY-GW-01"),
                ]
                chosen = self.rng.choice(sample_events)
                self.recent_events.insert(0, {
                    "time": now.isoformat(),
                    "level": chosen[0],
                    "msg": chosen[1],
                    "node": chosen[2],
                })
                if len(self.recent_events) > 15:
                    self.recent_events.pop()

            # Dynamic VaR Calculation (EAL < VaR90 < VaR95 < VaR99)
            self.current_eal_inr = max(1000.0, self.current_eal_inr)
            var_scale = self.current_eal_inr / max(1.0, self.baseline_eal_inr)
            var_90 = round(82_000_000.0 * (1.0 + (var_scale - 1.0) * 0.85), 2)
            var_95 = round(124_000_000.0 * (1.0 + (var_scale - 1.0) * 0.88), 2)
            var_99 = round(241_000_000.0 * (1.0 + (var_scale - 1.0) * 0.92), 2)

            # Defensive mathematical invariant clamp: strictly guarantee 0 < EAL < VaR90 < VaR95 < VaR99
            var_90 = max(var_90, round(self.current_eal_inr * 1.10, 2))
            var_95 = max(var_95, round(var_90 * 1.15, 2))
            var_99 = max(var_99, round(var_95 * 1.25, 2))
            posture_drift = round(((self.current_posture - self.baseline_posture) / max(1.0, self.baseline_posture)) * 100.0, 1)

            return {
                "timestamp": now.isoformat(),
                "overall_threat_level": threat_level,
                "events_per_second": round(eps, 1),
                "eps_current": round(eps, 1),
                "threat_event_frequency": round(tef, 2),
                "tef_current": round(tef, 2),
                "active_alerts_count": alerts,
                "threat_level": threat_level,
                "current_eal_inr": round(self.current_eal_inr, 2),
                "current_posture_score": round(self.current_posture, 1),
                "posture_score": round(self.current_posture, 1),
                "security_posture_score": round(self.current_posture, 1),
                "posture_drift_pct": posture_drift,
                "risk_factor_score": rf,
                "var_90_inr": var_90,
                "var_95_inr": var_95,
                "var_99_inr": var_99,
                "has_active_attack": is_attack,
                "active_attack": is_attack,
                "attack_type": attack_type_str,
                "target_node": target_node_str,
                "active_attacks_count": len(self.active_attacks),
                "active_attacks": list(self.active_attacks),
                "total_threat_shields_active": 5 + len(self.purchased_vendor_ids) * 2,
                "purchased_vendors_count": len(self.purchased_vendor_ids),
                "recent_events": list(self.recent_events[:10]),
                "nodes": node_statuses,
                "active_attack_details": self.active_attack.model_dump() if self.active_attack else None,
            }
