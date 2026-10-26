"""Anonymous local browser sessions, scoped to the local workspace."""
from __future__ import annotations

import hashlib
import os
import secrets
from typing import Any

from fastapi import Depends, HTTPException, Request, Response

from quantumshield.api.db import get_pool

COOKIE_NAME = "quantumshield_session"
SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 30


def token_hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def get_local_session(
    request: Request,
    response: Response,
    pool: Any = Depends(get_pool),
) -> dict[str, Any]:
    """Resolve the current local session or create a fresh one.

    The browser receives an opaque random token; only its SHA-256 hash is stored.
    This is local workspace separation, not strong user authentication.
    """
    raw_token = request.cookies.get(COOKIE_NAME)
    if raw_token and len(raw_token) <= 256:
        hashed = token_hash(raw_token)
        try:
            with pool.connection() as conn:
                existing = conn.execute(
                    """SELECT session_id, display_name, created_at, last_seen_at, expires_at
                       FROM local_sessions
                       WHERE token_hash = %s AND (expires_at IS NULL OR expires_at > now())""",
                    (hashed,),
                ).fetchone()
                if existing:
                    updated = conn.execute(
                        """UPDATE local_sessions SET last_seen_at = now()
                           WHERE session_id = %s
                           RETURNING session_id, display_name, created_at, last_seen_at, expires_at""",
                        (existing["session_id"],),
                    ).fetchone()
                    return updated
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Session storage is temporarily unavailable.") from exc

    # A fresh value is generated for every new session; never accept a caller-chosen session ID.
    raw_token = secrets.token_urlsafe(32)
    hashed = token_hash(raw_token)
    try:
        with pool.connection() as conn:
            row = conn.execute(
                """INSERT INTO local_sessions (token_hash, expires_at)
                   VALUES (%s, now() + (%s * interval '1 second'))
                   RETURNING session_id, display_name, created_at, last_seen_at, expires_at""",
                (hashed, SESSION_MAX_AGE_SECONDS),
            ).fetchone()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Could not create a local session.") from exc

    response.set_cookie(
        key=COOKIE_NAME,
        value=raw_token,
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=os.getenv("QUANTUMSHIELD_COOKIE_SECURE", "false").casefold() == "true",
        samesite="strict",
        path="/",
    )
    return row
