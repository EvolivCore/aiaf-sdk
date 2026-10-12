"""WSGI middleware: verify AI agents in front of Flask, classic Django, Bottle, Pyramid, …

Flask, in one line::

    from aidr_verifier.wsgi import AidrWSGIMiddleware, RelyingPartyConfig

    app.wsgi_app = AidrWSGIMiddleware(app.wsgi_app, RelyingPartyConfig(
        issuer="https://api.evolivcore.com", public_origin="https://shop.example"))

    @app.get("/products")
    def products():
        identity = request.environ["aidr"]          # always present
        if identity.is_agent:
            ...identity.organization, identity.agal, identity.org_domains...

Classic Django: ``aidr_verifier.django.AidrMiddleware`` (it uses this module).

The decisions are the ASGI middleware's own (:class:`aidr_verifier.asgi.AidrMiddleware`), not a
copy: each WSGI request is presented to it as the equivalent ASGI scope, so anonymous, verified and
refused mean exactly the same as there, and as at the Cloudflare Worker. Trust sync and the replay
store's (async) claims run on one background event loop in a daemon thread; request threads wait
on it for the decision, which takes microseconds once trust is loaded.

The signature covers the path *as sent*, so the raw request URI is used when the server provides
it (``RAW_URI`` from gunicorn, ``REQUEST_URI`` from uWSGI and Werkzeug); otherwise it is rebuilt
from ``SCRIPT_NAME`` + ``PATH_INFO``, which is exact for every path a client did not over-encode.
Set ``public_origin`` to this site's origin (or ``AIDR_PUBLIC_ORIGIN``): signatures are judged
against it, not the client's Host header (see ``origin.py``; required from 0.2.0).
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from http import HTTPStatus
from typing import Any
from urllib.parse import quote

from .asgi import AidrIdentity, AidrMiddleware, RelyingPartyConfig

logger = logging.getLogger("aidr.middleware")

#: How long a request waits for a decision before it is refused as "cannot be checked" (503).
DECISION_TIMEOUT_SECONDS = 10.0


class BackgroundGate:
    """The ASGI middleware's decision engine, driven from synchronous code."""

    def __init__(self, config: RelyingPartyConfig) -> None:
        self.engine = AidrMiddleware(app=None, config=config)
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, name="aidr-trust-sync",
                                       daemon=True)
        self.thread.start()
        started = asyncio.run_coroutine_threadsafe(self.engine.startup(), self.loop)
        try:
            # Wait for the first trust load, as an ASGI server's startup would; if the registry
            # cannot be reached, start anyway: agent requests get 503 until trust arrives.
            started.result(timeout=config.initial_sync_timeout + 5)
        except Exception as exc:  # noqa: BLE001 - agents get 503 until trust arrives
            logger.warning("AIDR: first trust load did not finish (%s); agent requests get 503 "
                           "until it does", exc)

    def decide(self, environ: dict[str, Any]) -> tuple[AidrIdentity, tuple[int, str, str] | None]:
        future = asyncio.run_coroutine_threadsafe(self.engine._authenticate(scope_from(environ)),  # noqa: SLF001
                                                  self.loop)
        try:
            return future.result(timeout=DECISION_TIMEOUT_SECONDS)
        except TimeoutError:
            future.cancel()
            return AidrIdentity("anonymous"), (503, "aidr.registry.unavailable",
                                               "agent verification timed out")

    def refusal(self, status: int, code: str, reason: str) -> tuple[str, list[tuple[str, str]], bytes]:
        body = json.dumps({"error": code, "reason": reason}).encode()
        headers = self.engine.refusal_headers(status, code)
        headers.append(("content-length", str(len(body))))
        return f"{status} {HTTPStatus(status).phrase}", headers, body

    def health(self) -> dict[str, Any]:
        return self.engine.health()

    def close(self) -> None:
        asyncio.run_coroutine_threadsafe(self.engine.shutdown(), self.loop).result(timeout=5)
        self.loop.call_soon_threadsafe(self.loop.stop)


def scope_from(environ: dict[str, Any]) -> dict[str, Any]:
    """The ASGI scope equivalent to a WSGI environ (as much of it as the decision reads)."""
    raw_uri = environ.get("RAW_URI") or environ.get("REQUEST_URI")
    if raw_uri and raw_uri.startswith("/"):
        raw_path, _, query = raw_uri.partition("?")
    else:
        # PEP 3333 hands PATH_INFO over decoded, as latin-1 code points: recover the bytes, then
        # re-encode the characters a client would have had to encode.
        script = environ.get("SCRIPT_NAME", "")
        path = environ.get("PATH_INFO", "") or "/"
        raw_path = quote((script + path).encode("latin-1"), safe="/:@!$&'()*+,;=-._~")
        query = environ.get("QUERY_STRING", "")
    headers: list[tuple[bytes, bytes]] = []
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            name = key[5:].replace("_", "-").lower()
        elif key in ("CONTENT_TYPE", "CONTENT_LENGTH") and value:
            name = key.replace("_", "-").lower()
        else:
            continue
        headers.append((name.encode("latin-1"), str(value).encode("latin-1")))
    return {
        "type": "http",
        "method": environ.get("REQUEST_METHOD", "GET"),
        "scheme": environ.get("wsgi.url_scheme", "https"),
        "path": environ.get("PATH_INFO", "/"),
        "raw_path": raw_path.encode("latin-1"),
        "query_string": query.encode("latin-1"),
        "headers": headers,
    }


class AidrWSGIMiddleware:
    """Puts an :class:`~aidr_verifier.asgi.AidrIdentity` in ``environ["aidr"]``, or refuses."""

    def __init__(self, app: Any, config: RelyingPartyConfig) -> None:
        self.app = app
        self.gate = BackgroundGate(config)

    def __call__(self, environ: dict[str, Any], start_response: Any) -> Any:
        identity, refusal = self.gate.decide(environ)
        if refusal is not None:
            status, headers, body = self.gate.refusal(*refusal)
            start_response(status, headers)
            return [body]
        environ["aidr"] = identity
        return self.app(environ, start_response)

    def health(self) -> dict[str, Any]:
        return self.gate.health()

    def close(self) -> None:
        self.gate.close()


__all__ = ["AidrWSGIMiddleware", "BackgroundGate", "RelyingPartyConfig", "scope_from"]
