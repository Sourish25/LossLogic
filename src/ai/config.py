"""
src/ai/config.py - Google Gemini 3.5 Flash Lite Configuration & API Key Resolver.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field

GEMINI_MODEL = "gemini-3.5-flash-lite"
DEFAULT_TIMEOUT_SECONDS = 3.0
GEMINI_API_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"

_CACHED_API_KEY: Optional[str] = None


def resolve_api_key(project_root: Optional[Path] = None) -> Optional[str]:
    """
    Resolves the Gemini API key by checking:
    1. geminiAPI.txt at the project root or current working directory.
    2. GEMINI_API_KEY environment variable.
    Returns the stripped key string, or None if unavailable.
    """
    global _CACHED_API_KEY
    if _CACHED_API_KEY:
        return _CACHED_API_KEY

    candidate_paths = []
    if project_root:
        candidate_paths.append(project_root / "geminiAPI.txt")

    # Current working directory
    candidate_paths.append(Path.cwd() / "geminiAPI.txt")

    # Path relative to this file: src/ai/config.py -> 3 levels up is project root
    this_file = Path(__file__).resolve()
    candidate_paths.append(this_file.parent.parent.parent / "geminiAPI.txt")
    candidate_paths.append(this_file.parent.parent / "geminiAPI.txt")

    for p in candidate_paths:
        try:
            if p.is_file():
                raw = p.read_text(encoding="utf-8").strip()
                if len(raw) >= 20:
                    _CACHED_API_KEY = raw
                    return _CACHED_API_KEY
        except Exception:
            continue

    env_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if len(env_key) >= 20:
        _CACHED_API_KEY = env_key
        return _CACHED_API_KEY

    return None


def get_api_key() -> Optional[str]:
    """Public helper returning the resolved Gemini API key, if available."""
    return resolve_api_key()


def is_gemini_available() -> bool:
    """Returns True if a valid Gemini API key is configured."""
    return resolve_api_key() is not None


def clear_api_key_cache() -> None:
    """Clears the cached API key (useful for test isolation)."""
    global _CACHED_API_KEY
    _CACHED_API_KEY = None


class GeminiSettings(BaseModel):
    """Configuration settings for Gemini Copilot."""
    model_name: str = Field(default=GEMINI_MODEL)
    timeout_seconds: float = Field(default=DEFAULT_TIMEOUT_SECONDS)
    base_url: str = Field(default=GEMINI_API_BASE_URL)
    api_key: Optional[str] = Field(default_factory=get_api_key)
