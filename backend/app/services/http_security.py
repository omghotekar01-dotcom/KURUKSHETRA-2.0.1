from __future__ import annotations

import os
from typing import Mapping
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send


_TRUE = {"1", "true", "yes", "on"}
_MIN_PRODUCTION_HSTS_SECONDS = 31_536_000


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
    if not parsed.hostname or "*" in parsed.hostname:
        return False
    try:
        _ = parsed.port
    except ValueError:
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


def hsts_max_age(env: Mapping[str, str] | None = None) -> int:
    source = os.environ if env is None else env
    raw = source.get("TRUSTKERNEL_HSTS_MAX_AGE", "0").strip()
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 0
    return max(0, value)


def hsts_production_ready(env: Mapping[str, str] | None = None) -> bool:
    source = os.environ if env is None else env
    return hsts_max_age(source) >= _MIN_PRODUCTION_HSTS_SECONDS


def hsts_header_value(env: Mapping[str, str] | None = None) -> str | None:
    source = os.environ if env is None else env
    if source.get("TRUSTKERNEL_ENV", "development").strip().lower() != "production":
        return None
    max_age = hsts_max_age(source)
    if max_age <= 0:
        return None
    value = f"max-age={max_age}"
    if source.get("TRUSTKERNEL_HSTS_INCLUDE_SUBDOMAINS", "0").strip().lower() in _TRUE:
        value += "; includeSubDomains"
    # TrustKernel deliberately does not emit `preload` automatically. Preload is
    # an externally submitted, persistent browser policy and needs an explicit
    # domain/TLS ownership review outside the application runtime.
    return value


class HSTSMiddleware:
    """Emit HSTS only for explicitly configured production deployments.

    Browsers ignore HSTS received over plaintext HTTP, so emitting at the app
    layer remains compatible with TLS-terminating reverse proxies while keeping
    local/development profiles free from persistent browser HTTPS state.
    """

    def __init__(self, app: ASGIApp, env: Mapping[str, str] | None = None) -> None:
        self.app = app
        self.env = dict(env) if env is not None else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_hsts(message: Message) -> None:
            if message["type"] == "http.response.start":
                value = hsts_header_value(self.env)
                if value:
                    headers = MutableHeaders(scope=message)
                    headers["Strict-Transport-Security"] = value
            await send(message)

        await self.app(scope, receive, send_with_hsts)


def configure_http_security(app: FastAPI, env: Mapping[str, str] | None = None) -> list[str]:
    hosts = allowed_hosts(env)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)
    app.add_middleware(HSTSMiddleware, env=env)
    return hosts
