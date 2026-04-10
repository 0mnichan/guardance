"""
API key authentication for the Guardance web API.

Keys are loaded from the ``GUARDANCE_API_KEYS`` environment variable as a
comma-separated list of raw key strings.  If the variable is unset or
empty, authentication is disabled and all requests are allowed through
(development mode).  A warning is logged in that case.

Usage::

    from src.api.auth import require_api_key

    @app.get("/some-endpoint")
    async def handler(key: str = Depends(require_api_key)):
        ...

Configuration (env vars):
    GUARDANCE_API_KEYS   Comma-separated API keys, e.g. ``"key1,key2"``.
                         If empty, auth is disabled.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

logger = logging.getLogger(__name__)

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# ---------------------------------------------------------------------------
# Key store
# ---------------------------------------------------------------------------

def _load_keys() -> set[str]:
    """Load valid API keys from environment."""
    raw = os.environ.get("GUARDANCE_API_KEYS", "")
    keys = {k.strip() for k in raw.split(",") if k.strip()}
    return keys


def get_valid_keys() -> set[str]:
    """Return the current set of valid API keys (re-read on each call)."""
    return _load_keys()


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

async def require_api_key(
    api_key: Optional[str] = Security(_API_KEY_HEADER),
) -> Optional[str]:
    """
    FastAPI dependency that enforces API key authentication.

    If ``GUARDANCE_API_KEYS`` is not set, auth is disabled and all requests
    pass through.  If it is set, the ``X-API-Key`` header must match one of
    the configured keys.

    Args:
        api_key: Value of the ``X-API-Key`` request header.

    Returns:
        The validated API key string, or ``None`` if auth is disabled.

    Raises:
        HTTPException 401: If keys are configured but header is missing.
        HTTPException 403: If the provided key is not valid.
    """
    valid_keys = get_valid_keys()

    if not valid_keys:
        # Auth disabled — development mode
        logger.debug("API key auth disabled (GUARDANCE_API_KEYS not set)")
        return None

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Key header is required",
        )

    if api_key not in valid_keys:
        logger.warning("Invalid API key attempt: %r", api_key[:8] + "...")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )

    return api_key
