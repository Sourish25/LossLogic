"""
src/ai/client.py - Direct Async REST Client for Google Gemini 3.5 Flash Lite API.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional
import httpx

from src.ai.config import (
    DEFAULT_TIMEOUT_SECONDS,
    GEMINI_API_BASE_URL,
    GEMINI_MODEL,
    get_api_key,
)

logger = logging.getLogger(__name__)


class GeminiAPIException(Exception):
    """Raised when Gemini API request fails, times out, or returns an error status."""

    def __init__(self, message: str, status_code: Optional[int] = None, original_error: Optional[Exception] = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.original_error = original_error


class GeminiClient:
    """
    Direct asynchronous REST client for Google Generative Language v1beta API.
    Uses httpx.AsyncClient with strict timeout enforcement and zero extra SDK dependencies.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = GEMINI_MODEL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        base_url: str = GEMINI_API_BASE_URL,
    ) -> None:
        self.api_key = api_key or get_api_key()
        self.model = model
        self.timeout = timeout
        self.base_url = base_url

    @property
    def endpoint_url(self) -> str:
        key = self.api_key or ""
        return f"{self.base_url}/{self.model}:generateContent?key={key}"

    async def generate_content(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        json_mode: bool = False,
        temperature: float = 0.2,
        max_output_tokens: int = 1024,
        timeout: Optional[float] = None,
    ) -> str:
        """
        Sends an asynchronous generateContent request to Gemini 3.5 Flash Lite.
        Returns the raw response text string.
        Raises GeminiAPIException on timeouts, network errors, or HTTP failures.
        """
        key = self.api_key or get_api_key()
        if not key:
            raise GeminiAPIException("Gemini API key is not configured or resolved.", status_code=401)

        url = f"{self.base_url}/{self.model}:generateContent?key={key}"
        effective_timeout = timeout if timeout is not None else self.timeout

        # Construct payload
        user_content = prompt
        if system_instruction:
            user_content = f"{system_instruction.strip()}\n\n---\n\nUSER REQUEST:\n{prompt.strip()}"

        payload: Dict[str, Any] = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_content}],
                }
            ],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_output_tokens,
            },
        }

        if json_mode:
            payload["generationConfig"]["responseMimeType"] = "application/json"

        try:
            async with httpx.AsyncClient(timeout=effective_timeout) as client:
                response = await client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )

            if response.status_code != 200:
                raise GeminiAPIException(
                    f"Gemini API returned HTTP {response.status_code}: {response.text[:200]}",
                    status_code=response.status_code,
                )

            data = response.json()
            candidates = data.get("candidates", [])
            if not candidates:
                raise GeminiAPIException("Gemini API response contained no candidates.")

            parts = candidates[0].get("content", {}).get("parts", [])
            if not parts:
                raise GeminiAPIException("Gemini candidate contained no content parts.")

            raw_text = parts[0].get("text", "")
            return raw_text

        except httpx.TimeoutException as e:
            logger.warning("Gemini API call timed out after %.1fs: %s", effective_timeout, e)
            raise GeminiAPIException(f"Gemini API request timed out after {effective_timeout}s.", status_code=408, original_error=e)
        except httpx.NetworkError as e:
            logger.warning("Gemini API network error: %s", e)
            raise GeminiAPIException(f"Gemini API network error: {e}", status_code=503, original_error=e)
        except GeminiAPIException:
            raise
        except Exception as e:
            logger.warning("Unexpected error during Gemini API call: %s", e)
            raise GeminiAPIException(f"Unexpected error: {e}", original_error=e)

    async def generate_json(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        temperature: float = 0.0,
        max_output_tokens: int = 1024,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Generates content and parses it as a JSON dictionary.
        Strips markdown code blocks if the model wrapped output in ```json ... ```.
        """
        raw = await self.generate_content(
            prompt=prompt,
            system_instruction=system_instruction,
            json_mode=True,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
            timeout=timeout,
        )

        cleaned = raw.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as e:
            raise GeminiAPIException(f"Failed to parse Gemini output as JSON: {e}. Raw: {cleaned[:100]}", original_error=e)

    def generate_content_sync(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        json_mode: bool = False,
        timeout: Optional[float] = None,
    ) -> str:
        """Synchronous wrapper for generate_content."""
        return asyncio.run(
            self.generate_content(
                prompt=prompt,
                system_instruction=system_instruction,
                json_mode=json_mode,
                timeout=timeout,
            )
        )
