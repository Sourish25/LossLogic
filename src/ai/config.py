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


def _parse_and_inject_env(filepath: Path) -> None:
    """Parse key=value pairs from a .env file and inject into os.environ if not already present."""
    try:
        if not filepath.is_file():
            return
        lines = filepath.read_text(encoding="utf-8").splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            if "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip("'\"")
                if key and key not in os.environ:
                    os.environ[key] = val
    except Exception:
        pass


def resolve_api_key(project_root: Optional[Path] = None) -> Optional[str]:
    """
    Resolves the Gemini API key by checking:
    1. Direct environment variables: GEMINI_API_KEY, GOOGLE_API_KEY, GEMINI_KEY.
    2. .env files (cwd, project root, or Render secret path /etc/secrets/.env).
    3. geminiAPI.txt files (cwd, project root, or Render secret path /etc/secrets/geminiAPI.txt).
    Returns the stripped key string, or None if unavailable.
    """
    global _CACHED_API_KEY
    if _CACHED_API_KEY:
        return _CACHED_API_KEY

    # 1. Check existing environment variables first
    for env_var in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "GEMINI_KEY"):
        val = os.environ.get(env_var, "").strip().strip("'\"")
        if len(val) >= 20:
            _CACHED_API_KEY = val
            return _CACHED_API_KEY

    # 2. Check and parse potential .env files
    this_file = Path(__file__).resolve()
    repo_root = this_file.parent.parent.parent
    dotenv_candidates = [
        Path.cwd() / ".env",
        repo_root / ".env",
        Path("/etc/secrets/.env"),
    ]
    if project_root:
        dotenv_candidates.insert(0, project_root / ".env")

    for dotenv_path in dotenv_candidates:
        _parse_and_inject_env(dotenv_path)

    # Check env vars again after parsing .env
    for env_var in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "GEMINI_KEY"):
        val = os.environ.get(env_var, "").strip().strip("'\"")
        if len(val) >= 20:
            _CACHED_API_KEY = val
            return _CACHED_API_KEY

    # 3. Check raw geminiAPI.txt secret files
    secret_txt_candidates = [
        Path.cwd() / "geminiAPI.txt",
        repo_root / "geminiAPI.txt",
        this_file.parent.parent / "geminiAPI.txt",
        Path("/etc/secrets/geminiAPI.txt"),
    ]
    if project_root:
        secret_txt_candidates.insert(0, project_root / "geminiAPI.txt")

    for p in secret_txt_candidates:
        try:
            if p.is_file():
                raw = p.read_text(encoding="utf-8").strip().strip("'\"")
                if len(raw) >= 20:
                    _CACHED_API_KEY = raw
                    return _CACHED_API_KEY
        except Exception:
            continue

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
