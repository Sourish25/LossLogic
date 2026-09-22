"""
src/ai/actions.py - Natural Language Action Payload Interpreter & Schema.
Translates executive and technical natural language instructions into structured,
executable client-side ActionPayloads (tab navigation, slider adjustment, attack simulation).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from src.decision_support.nlq_parser import NLQParser


class ActionPayload(BaseModel):
    """
    Structured action payload for dashboard frontend consumption.
    Compatible with both survey specifications and frontend event dispatchers.
    """
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    action_type: str = Field(..., description="'switch_tab' | 'tab_switch' | 'simulate_attack' | 'inject_attack' | 'set_slider' | 'set_budget_and_optimize' | 'reset_simulation' | 'toggle_currency' | 'open_drawer'")
    action: Optional[str] = Field(default=None, description="Alias for action_type")
    target: Optional[str] = Field(default=None, description="Target element, tab, or attack type")
    target_tab: Optional[str] = Field(default=None, description="Target tab ('executive' | 'technical' | 'demo' | 'optimize')")
    target_element: Optional[str] = Field(default=None, description="DOM selector or target ID")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Execution parameters")
    explanation: str = Field(default="", description="User-facing plain-language description")

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        if self.action is None:
            self.action = self.action_type
        if self.target is None and self.target_tab is not None:
            self.target = self.target_tab


def interpret_navigation_command(command: str, currency: str = "INR") -> Dict[str, Any]:
    """
    Deterministically interprets natural language commands into ActionPayload collections.
    Returns dictionary conforming to AINavigateResponse schema.
    """
    text = command.strip().lower()
    curr = currency.upper().strip()

    actions: List[ActionPayload] = []
    intent = "UNKNOWN"
    confidence = 0.95
    target_tab: Optional[str] = None
    action_type = "switch_tab"
    parameters: Dict[str, Any] = {}
    explanation = ""

    # 1. Reset / Normalize commands (must precede attack check so "clear attack" is not intercepted)
    if any(k in text for k in ("reset", "restore", "normalize", "clear attack", "clear")):
        target_tab = "technical"
        action_type = "reset_simulation"
        explanation = "Restoring BharatCart demonstration environment to nominal baseline state."
        actions.append(
            ActionPayload(
                action_type="reset_simulation",
                target_tab="technical",
                target="technical",
                parameters={},
                explanation=explanation,
            )
        )
        intent = "RESET_SIMULATION"

    # 2. Delay simulation slider (must precede general "simulate" keyword)
    elif "delay" in text:
        m = re.search(r"(\d+)", text)
        days = int(m.group(1)) if m else 30
        target_tab = "executive"
        action_type = "set_slider"
        parameters = {"name": "delay", "value": days}
        explanation = f"Setting remediation delay parameter to {days} days."
        actions.append(
            ActionPayload(
                action_type="set_slider",
                target="slider-delay",
                target_element="#slider-delay",
                parameters=parameters,
                explanation=explanation,
            )
        )
        intent = "REMEDIATION_DELAY"

    # 3. Budget Optimization commands
    # e.g., "Optimize security portfolio for 75 Lakhs budget", "Optimize for 50 Lakh budget", "Allocate ₹1.5 crore for security"
    elif any(k in text for k in ("optimize", "budget", "allocation", "allocate", "knapsack", "spend", "invest")):
        # Extract currency amount using NLQ parser slots
        _, budget_source, budget_inr, budget_usd = NLQParser.extract_currency_and_budget(command)
        budget_val = budget_inr if curr == "INR" else budget_usd
        if not budget_val:
            budget_val = budget_source

        # Fallback regex for numbers if slot extraction didn't catch it
        if not budget_val:
            m = re.search(r"(\d+(?:\.\d+)?)\s*(?:lakh|lac|cr|crore|m|k|million)?", text)
            if m:
                num = float(m.group(1))
                if "cr" in text:
                    budget_val = num * 10_000_000.0
                elif "lakh" in text or "lac" in text:
                    budget_val = num * 100_000.0
                elif "m" in text or "million" in text:
                    budget_val = num * 1_000_000.0
                else:
                    budget_val = num * 100_000.0 if num <= 100 else num
            else:
                budget_val = 5_000_000.0 if curr == "INR" else 60_000.0

        target_tab = "optimize"
        action_type = "set_budget_and_optimize"
        parameters = {
            "budget": float(budget_val),
            "currency": curr,
            "name": "budget",
            "value": float(budget_val),
        }
        explanation = f"Adjusting capital investment budget to {budget_val:,.0f} {curr} and solving HiGHS MILP optimization."

        actions.append(
            ActionPayload(
                action_type="set_budget_and_optimize",
                target_tab="optimize",
                target="optimize",
                parameters=parameters,
                explanation=explanation,
            )
        )
        actions.append(
            ActionPayload(
                action_type="set_slider",
                target="slider-budget",
                target_element="#slider-budget",
                parameters={"name": "budget", "value": float(budget_val)},
                explanation=f"Updating budget slider to {budget_val:,.0f}",
            )
        )
        intent = "BUDGET_OPTIMIZATION"

    # 4. Attack Simulation commands
    # e.g., "Simulate a zero-day exploit against flash sale microservice", "Simulate DDoS attack", "Brute force password spray"
    elif any(k in text for k in (
        "simulate", "inject", "attack", "exploit", "surge", "outage", "leak",
        "ransomware", "ddos", "zero-day", "0-day", "stuffing", "brute", "password", "credential"
    )):
        target_tab = "technical"
        action_type = "inject_attack"

        # Determine attack vector
        if any(k in text for k in ("zero day", "zero-day", "0-day", "cve")):
            atk_type = "zero_day_cve"
            tgt_node = "BC-FLASH-SALE-01"
            name = "Zero-Day Exploit"
        elif any(k in text for k in ("ddos", "flood", "volumetric", "traffic")):
            atk_type = "ddos_surge"
            tgt_node = "BC-API-GW-01"
            name = "DDoS Ingress Surge"
        elif any(k in text for k in ("ransomware", "lockbit", "encrypt")):
            atk_type = "ransomware_outage"
            tgt_node = "BC-PAY-GW-01"
            name = "Ransomware Outage"
        elif any(k in text for k in ("sql", "pii", "database", "data leak", "exfiltration")):
            atk_type = "sql_data_leak"
            tgt_node = "BC-PII-VAULT-01"
            name = "SQL Data Leak"
        elif any(k in text for k in ("credential", "stuffing", "brute", "password")):
            atk_type = "credential_stuffing"
            tgt_node = "BC-FLASH-SALE-01"
            name = "Credential Stuffing Surge"
        elif any(k in text for k in ("iam", "cloud", "privilege", "role", "root")):
            atk_type = "cloud_iam_compromise"
            tgt_node = "BC-API-GW-01"
            name = "Cloud IAM Compromise"
        else:
            atk_type = "zero_day_cve"
            tgt_node = "BC-FLASH-SALE-01"
            name = "Simulated Threat Injection"

        # Check for explicit node overrides
        if "pay" in text or "payment" in text:
            tgt_node = "BC-PAY-GW-01"
        elif "vault" in text or "pii" in text:
            tgt_node = "BC-PII-VAULT-01"
        elif "gateway" in text or "api" in text:
            tgt_node = "BC-API-GW-01"
        elif "flash" in text or "sale" in text:
            tgt_node = "BC-FLASH-SALE-01"

        parameters = {
            "attack_type": atk_type,
            "target_node": tgt_node,
            "intensity": 5.0,
        }
        explanation = f"Injecting {name} against {tgt_node} on the BharatCart topology."

        # Switch to technical tab first
        actions.append(
            ActionPayload(
                action_type="switch_tab",
                target_tab="technical",
                target="technical",
                parameters={"tab": "technical"},
                explanation="Navigating to Technical SecOps view (BharatCart Cyber Threat Simulator)",
            )
        )
        # Trigger attack
        actions.append(
            ActionPayload(
                action_type="inject_attack",
                target_tab="technical",
                target=atk_type,
                parameters=parameters,
                explanation=explanation,
            )
        )
        intent = "SIMULATE_ATTACK"

    # 5. Currency toggling
    elif any(k in text for k in ("currency", "usd", "inr", "toggle currency")):
        req_curr = "USD" if "usd" in text else "INR"
        action_type = "toggle_currency"
        parameters = {"currency": req_curr}
        explanation = f"Toggling enterprise reporting currency to {req_curr}."
        actions.append(
            ActionPayload(
                action_type="toggle_currency",
                target="btn-currency",
                target_element="#btn-currency",
                parameters=parameters,
                explanation=explanation,
            )
        )
        intent = "TOGGLE_CURRENCY"

    # 6. Tab Navigation commands
    else:
        intent = "NAVIGATE_TAB"
        if any(k in text for k in ("technical", "secops", "cve", "backlog", "vulnerability", "cves", "findings")):
            target_tab = "technical"
            action_type = "tab_switch"
            explanation = "Navigating to Technical SecOps view (CVE findings & asset drilldowns)."
        elif any(k in text for k in ("vendor", "benchmarking", "matrix", "procurement", "cldf", "crwd", "okta", "wiz")):
            target_tab = "executive"
            action_type = "tab_switch"
            explanation = "Navigating to CEO Vendor Benchmarking Matrix on Executive view."
        elif any(k in text for k in ("blast radius", "topology", "dag", "bharatcart", "threat simulator", "attack injection", "demo")) or "jur" in text:
            target_tab = "technical"
            action_type = "tab_switch"
            explanation = "Navigating to Technical SecOps view (BharatCart service topology & blast radius)."
        elif any(k in text for k in ("compliance", "rbi", "sebi", "iso", "nist", "framework")):
            target_tab = "executive"
            action_type = "tab_switch"
            explanation = "Navigating to Regulatory Compliance Crosswalk view."
        else:
            target_tab = "executive"
            action_type = "tab_switch"
            explanation = "Navigating to Executive Board & CISO view."

        actions.append(
            ActionPayload(
                action_type=action_type,
                target_tab=target_tab,
                target=target_tab,
                parameters={"tab": target_tab},
                explanation=explanation,
            )
        )

    # Primary action alias for convenient single-action inspection
    primary_action = None
    for a in actions:
        if a.action_type in ("set_budget_and_optimize", "inject_attack", "simulate_attack", "reset_simulation", "toggle_currency"):
            primary_action = a
            break
    if primary_action is None and actions:
        primary_action = actions[0]
    elif primary_action is None:
        primary_action = ActionPayload(
            action_type="switch_tab",
            target_tab="executive",
            parameters={"tab": "executive"},
            explanation="Default to Executive View",
        )

    return {
        "interpreted_command": command,
        "intent": intent,
        "confidence": confidence,
        "actions": actions,
        "action": primary_action,
        "action_type": primary_action.action_type,
        "target_tab": target_tab or primary_action.target_tab,
        "parameters": parameters or primary_action.parameters,
        "explanation": explanation or primary_action.explanation,
        "message": explanation or primary_action.explanation,
        "model_used": "local-heuristic-fallback",
        "offline_fallback": True,
        "execution_time_ms": 1.2,
    }
