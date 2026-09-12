from __future__ import annotations

import os
from typing import Mapping
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware


def allowed_hosts(env: Mapping[str, str] | None = None) -> list[str]:
    source = os.environ if env is None else env
    raw = source.get("TRUSTKERNEL_ALLOWED_HOSTS", "*")
    hosts = [item.strip() for item in raw.split(",") if item.strip()]
    return hosts or ["*"]


def host_header_restricted(env: Mapping[str, str] | None = None) -> bool:
    hosts = allowed_hosts(env)
    return bool(hosts) and "*" not in hosts and all("*" not in host for host in hosts)


def allowed_cors_origins(env: Mapping[str, str] | None = None) -> list[str]:
    source = os.environ if env is None else env
    raw = source.get("TRUSTKERNEL_CORS_ORIGINS", "*")
    origins = [item.strip() for item in raw.split(",") if item.strip()]
    return origins or ["*"]


def _valid_origin(origin: str, require_https: bool) -> bool:
    if origin == "*":
        return False
    parsed = urlparse(origin)
    if parsed.scheme not in ({"https"} if require_https else {"http", "https"}):
        return False
    if not parsed.netloc or parsed.username or parsed.password:
        return False
    if parsed.path not in ("", "/") or parsed.params or parsed.query or parsed.fragment:
        return False
    return True


def cors_origin_restricted(env: Mapping[str, str] | None = None) -> bool:
    origins = allowed_cors_origins(env)
    return bool(origins) and all(_valid_origin(origin, require_https=False) for origin in origins)


def cors_origins_https(env: Mapping[str, str] | None = None) -> bool:
    origins = allowed_cors_origins(env)
    return bool(origins) and all(_valid_origin(origin, require_https=True) for origin in origins)


def configure_http_security(app: FastAPI, env: Mapping[str, str] | None = None) -> list[str]:
    hosts = allowed_hosts(env)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)
    return hosts
