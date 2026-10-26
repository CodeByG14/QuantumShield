"""PostgreSQL pool and request dependency helpers."""
from __future__ import annotations

import os
from typing import Any

from fastapi import HTTPException, Request


def _conninfo() -> str:
    url = os.getenv("DATABASE_URL")
    if url:
        return url

    # Values match the repository's local Compose/.env convention.
    from psycopg.conninfo import make_conninfo

    return make_conninfo(
        host=os.getenv("POSTGRES_HOST", "127.0.0.1"),
        port=os.getenv("POSTGRES_PORT", "5433"),
        dbname=os.getenv("POSTGRES_DB", "quantumshield_db"),
        user=os.getenv("POSTGRES_USER", "postgres"),
        password=os.getenv("POSTGRES_PASSWORD", ""),
        connect_timeout="5",
        application_name="quantumshield-api",
    )


def open_pool() -> Any:
    """Open and verify a bounded synchronous connection pool."""
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool

    pool = ConnectionPool(
        conninfo=_conninfo(),
        min_size=1,
        max_size=int(os.getenv("QUANTUMSHIELD_DB_POOL_MAX", "8")),
        timeout=10,
        kwargs={"row_factory": dict_row},
        open=True,
    )
    try:
        pool.wait(timeout=10)
    except Exception:
        pool.close()
        raise
    return pool


def get_pool(request: Request) -> Any:
    pool = getattr(request.app.state, "db_pool", None)
    if pool is None:
        raise HTTPException(status_code=503, detail="Database pool is not available.")
    return pool
