"""
src/ai/__init__.py - AI Copilot & Action Engine Package for LossLogic.
Google Gemini 3.5 Flash Lite integration with live platform grounding,
structured action interpretation, and 100% offline heuristic fallback.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.ai.actions import ActionPayload, interpret_navigation_command
from src.ai.client import GeminiAPIException, GeminiClient
from src.ai.config import (
    DEFAULT_TIMEOUT_SECONDS,
    GEMINI_MODEL,
    GeminiSettings,
    clear_api_key_cache,
    get_api_key,
    is_gemini_available,
    resolve_api_key,
)
from src.ai.fallback import (
    fallback_chat,
    fallback_executive_summary,
    fallback_navigate,
)
from src.ai.grounding import build_grounded_system_prompt, get_live_platform_metrics

logger = logging.getLogger(__name__)


class GeminiCopilot:
    """
    Unified AI Copilot service managing live Gemini 3.5 Flash Lite communication,
    live platform state grounding, structured action generation, and seamless local fallback.
    """

    def __init__(
        self,
        client: Optional[GeminiClient] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.client = client or GeminiClient(timeout=timeout)
        self.timeout = timeout

    async def chat(
        self,
        message: str,
        currency: str = "INR",
        history: Optional[List[Dict[str, str]]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Executes grounded conversational risk decision support.
        Falls back seamlessly to local heuristic engine on network/timeout/429 errors.
        """
        start_t = time.perf_counter()
        curr = currency.upper().strip()

        if is_gemini_available():
            try:
                system_prompt = build_grounded_system_prompt(currency=curr, context=context)
                response_text = await self.client.generate_content(
                    prompt=message,
                    system_instruction=system_prompt,
                    timeout=self.timeout,
                )
                elapsed_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
                metrics = get_live_platform_metrics(currency=curr)

                suggested_actions = [
                    {"label": "Run What-If Simulation", "command": "simulate what-if scenario"},
                    {"label": "Optimize Portfolio", "command": f"optimize for {metrics['recommended_spend_formatted']} budget"},
                    {"label": "View Blast Radius", "command": "take me to BharatCart blast radius"},
                ]
                suggested_followups = [
                    "What is our highest financial cyber risk?",
                    "Which vulnerabilities contribute most to expected losses?",
                    "What is the optimal security investment for 50 Lakhs budget?",
                    "What is our compliance status against RBI CSF and SEBI?",
                ]

                return {
                    "response": response_text,
                    "reply": response_text,
                    "model_used": GEMINI_MODEL,
                    "grounded_metrics": metrics,
                    "suggested_actions": suggested_actions,
                    "suggested_followups": suggested_followups,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "offline_fallback": False,
                    "execution_time_ms": elapsed_ms,
                }
            except Exception as e:
                logger.info("Routing chat query to local fallback engine (reason: %s)", e)
                elapsed_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
                return fallback_chat(
                    message=message,
                    currency=curr,
                    history=history,
                    execution_time_ms=elapsed_ms,
                )

        elapsed_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
        return fallback_chat(
            message=message,
            currency=curr,
            history=history,
            execution_time_ms=elapsed_ms,
        )

    async def navigate(
        self,
        command: str,
        currency: str = "INR",
    ) -> Dict[str, Any]:
        """
        Interprets natural language commands into structured ActionPayloads.
        Uses deterministic rule parser with Gemini fallback or enhancement.
        """
        start_t = time.perf_counter()
        curr = currency.upper().strip()

        # Deterministic rule parser is fast and precision-calibrated
        res = interpret_navigation_command(command=command, currency=curr)

        if is_gemini_available():
            try:
                # Optionally attempt Gemini JSON parsing if command is ambiguous (low confidence)
                if res.get("confidence", 1.0) < 0.8:
                    prompt = (
                        f"Analyze the navigation instruction: '{command}'. "
                        f"Target currency is {curr}. "
                        "Return JSON with keys: interpreted_command, intent, target_tab, action_type, parameters, explanation."
                    )
                    gemini_res = await self.client.generate_json(
                        prompt=prompt,
                        timeout=min(self.timeout, 2.0),
                    )
                    if isinstance(gemini_res, dict) and "target_tab" in gemini_res:
                        res.update(gemini_res)
                        res["model_used"] = GEMINI_MODEL
                        res["offline_fallback"] = False
            except Exception:
                pass  # Keep deterministic result

        elapsed_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
        res["execution_time_ms"] = elapsed_ms
        return res

    async def executive_summary(
        self,
        target_audience: str = "jury",
        currency: str = "INR",
        focus_domain: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generates 30-second jury & board elevator briefing.
        """
        start_t = time.perf_counter()
        curr = currency.upper().strip()

        if is_gemini_available():
            try:
                metrics = get_live_platform_metrics(currency=curr)
                sys_prompt = build_grounded_system_prompt(currency=curr)
                prompt = (
                    f"Provide an executive elevator pitch (30-45 seconds) for {target_audience}. "
                    f"Focus on balance-sheet monetary exposure ({metrics['current_eal_formatted']} EAL), "
                    f"VaR 95% tail risk ({metrics['var_95_formatted']}), "
                    f"and ROSI ({metrics['portfolio_rosi']}% on {metrics['recommended_spend_formatted']} budget). "
                    "Return concise, crisp text without emojis."
                )
                raw_text = await self.client.generate_content(
                    prompt=prompt,
                    system_instruction=sys_prompt,
                    timeout=self.timeout,
                )
                elapsed_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
                fb = fallback_executive_summary(target_audience=target_audience, currency=curr, focus_domain=focus_domain)
                fb["elevator_pitch_30s"] = raw_text
                fb["elevator_pitch"] = raw_text
                fb["summary_30s"] = raw_text
                fb["summary"] = raw_text
                fb["model_used"] = GEMINI_MODEL
                fb["offline_fallback"] = False
                fb["execution_time_ms"] = elapsed_ms
                return fb
            except Exception as e:
                logger.info("Routing executive summary to local fallback engine (reason: %s)", e)
                elapsed_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
                return fallback_executive_summary(
                    target_audience=target_audience,
                    currency=curr,
                    focus_domain=focus_domain,
                    execution_time_ms=elapsed_ms,
                )

        elapsed_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
        return fallback_executive_summary(
            target_audience=target_audience,
            currency=curr,
            focus_domain=focus_domain,
            execution_time_ms=elapsed_ms,
        )


_copilot_instance: Optional[GeminiCopilot] = None


def get_copilot() -> GeminiCopilot:
    """Returns singleton GeminiCopilot instance."""
    global _copilot_instance
    if _copilot_instance is None:
        _copilot_instance = GeminiCopilot()
    return _copilot_instance


__all__ = [
    "ActionPayload",
    "GeminiAPIException",
    "GeminiClient",
    "GeminiCopilot",
    "GeminiSettings",
    "build_grounded_system_prompt",
    "clear_api_key_cache",
    "fallback_chat",
    "fallback_executive_summary",
    "fallback_navigate",
    "get_api_key",
    "get_copilot",
    "get_live_platform_metrics",
    "interpret_navigation_command",
    "is_gemini_available",
    "resolve_api_key",
]
