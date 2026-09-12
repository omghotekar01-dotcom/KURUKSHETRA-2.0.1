from __future__ import annotations

import os
from typing import Mapping

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


def configure_http_security(app: FastAPI, env: Mapping[str, str] | None = None) -> list[str]:
    hosts = allowed_hosts(env)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)
    return hosts
