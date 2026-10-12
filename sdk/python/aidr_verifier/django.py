"""Django middleware: verify AI agents in a classic (WSGI) Django project.

    # settings.py
    MIDDLEWARE = ["aidr_verifier.django.AidrMiddleware", *MIDDLEWARE]
    AIDR = {"issuer": "https://api.evolivcore.com",
            "public_origin": "https://shop.example"}      # any RelyingPartyConfig field

    # a view
    def products(request):
        if request.aidr.is_agent:
            ...request.aidr.organization, request.aidr.agal...

Put it first, so a refused request never reaches sessions, CSRF or your views. The decisions are
the ASGI middleware's (see aidr_verifier.wsgi): anonymous passes, verified passes with
``request.aidr``, a false identity is refused 401/403/503, and with ``"mode": "verified-only"``
anonymous requests to the protected paths are refused with 401. Django under ASGI can use either
this or :class:`aidr_verifier.asgi.AidrMiddleware`.
"""

from __future__ import annotations

from typing import Any

from .asgi import RelyingPartyConfig
from .wsgi import BackgroundGate


class AidrMiddleware:
    """Django's middleware protocol around :class:`aidr_verifier.wsgi.BackgroundGate`."""

    _gate: BackgroundGate | None = None

    def __init__(self, get_response: Any) -> None:
        from django.conf import settings
        from django.core.exceptions import ImproperlyConfigured

        options = getattr(settings, "AIDR", None)
        if not isinstance(options, dict) or not options.get("issuer"):
            raise ImproperlyConfigured('set AIDR = {"issuer": "https://api.evolivcore.com"} in settings')
        self.get_response = get_response
        # One gate (one trust sync, one replay store) per process, however Django instantiates us.
        if AidrMiddleware._gate is None:
            AidrMiddleware._gate = BackgroundGate(RelyingPartyConfig(**options))
        self.gate = AidrMiddleware._gate

    def __call__(self, request: Any) -> Any:
        from django.http import HttpResponse

        identity, refusal = self.gate.decide(request.META)
        if refusal is not None:
            status, headers, body = self.gate.refusal(*refusal)
            response = HttpResponse(body, status=int(status.split()[0]))
            for name, value in headers:
                if name != "content-length":
                    response[name] = value
            return response
        request.aidr = identity
        return self.get_response(request)


__all__ = ["AidrMiddleware"]
