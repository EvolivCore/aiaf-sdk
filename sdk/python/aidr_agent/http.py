"""HTTP-library adapters. Each signs a request at the moment it is sent, with a fresh nonce."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Generator
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from .agent import Agent

try:
    from requests.auth import AuthBase as _RequestsAuthBase
except ImportError:                      # requests is optional
    _RequestsAuthBase = object           # type: ignore[assignment,misc]


class RequestsAuth(_RequestsAuthBase):   # type: ignore[misc,valid-type]
    def __init__(self, agent: Agent) -> None:
        self.agent = agent

    def __call__(self, request):  # noqa: ANN001, ANN204 - requests.PreparedRequest
        request.headers.update(self.agent.sign_headers(request.method, request.url))
        return request


class HttpxAuth(httpx.Auth):
    """Sync and async. Credentials are fetched with a separate client, never the one being used,
    so a request to the registry is never itself signed for the site."""

    def __init__(self, agent: Agent) -> None:
        self.agent = agent

    def sync_auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers.update(self.agent.sign_headers(request.method, str(request.url)))
        yield request

    async def async_auth_flow(self, request: httpx.Request) -> AsyncGenerator[httpx.Request, httpx.Response]:
        request.headers.update(await self.agent.asign_headers(request.method, str(request.url)))
        yield request
