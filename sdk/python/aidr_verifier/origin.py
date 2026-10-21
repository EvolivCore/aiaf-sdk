"""Which site a request was meant for — the authority a signature must cover.

A signature covers ``@authority``, so the verifier must judge it against THIS site's own origin.
The request's Host header is what the client sent: a request signed for another site, replayed
here with that site's Host, would verify wherever the server answers any host name (found
2026-10-10). So the site says who it is::

    RelyingPartyConfig(issuer=..., public_origin="https://shop.example")
    RelyingPartyConfig(issuer=..., public_origin=["https://shop.example", "https://www.shop.example"])
    AIDR_PUBLIC_ORIGIN=https://shop.example,https://www.shop.example      # the same, from the environment

A request whose Host matches a configured origin is judged as that origin; any other Host as the
first — so a signature made for a host that is not this site's never matches.

Without an origin, localhost (and 127.0.0.0/8, ::1) still works, for development. Any other host:
in 0.1.x a warning, once, and the Host header is used as before; from 0.2.0 an agent's request is
refused (``aidr.config.public_origin_required``) — people without agent headers are never affected.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from collections.abc import Callable, Mapping, Sequence
from urllib.parse import urlsplit

from aidr_core.errors import AidrError

logger = logging.getLogger("aidr_verifier")

PUBLIC_ORIGIN_ENV = "AIDR_PUBLIC_ORIGIN"

#: True from 0.2.0 (refuse); 0.1.x warned.
ENFORCE_PUBLIC_ORIGIN = True


class PublicOriginRequired(AidrError):
    code = "aidr.config.public_origin_required"
    http_status = 503

    def __init__(self) -> None:
        super().__init__("this site has not configured its public origin (public_origin or "
                         f"{PUBLIC_ORIGIN_ENV}), so agents cannot be verified")


def _normalise(value: str) -> str:
    parts = urlsplit(value.strip())
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(f"public_origin: not an http(s) origin: {value!r}")
    return f"{parts.scheme}://{parts.netloc.lower()}"


def configured_origins(public_origin: str | Sequence[str] | None,
                       env: Mapping[str, str] | None = None) -> list[str]:
    """The option, else the environment; [] when neither."""
    raw: str | Sequence[str] | None = public_origin
    if raw is None or raw == "":
        raw = (os.environ if env is None else env).get(PUBLIC_ORIGIN_ENV) or None
    if raw is None:
        return []
    values = raw.split(",") if isinstance(raw, str) else list(raw)
    return [_normalise(v) for v in values if v.strip()]


def is_loopback_host(host: str | None) -> bool:
    """localhost, *.localhost, 127.0.0.0/8 and ::1, with or without a port."""
    name = (host or "").strip().lower()
    if name.startswith("["):
        name = name[1:name.find("]")] if "]" in name else name
    elif name.count(":") == 1:
        name = name.split(":")[0]
    if name == "localhost" or name.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


_warned = False


def reset_origin_warning() -> None:
    """For tests: forget that the warning was given."""
    global _warned
    _warned = False


def origin_resolver(public_origin: str | Sequence[str] | None = None, *, scheme: str = "https",
                    enforce: bool | None = None, env: Mapping[str, str] | None = None,
                    warn: Callable[[str], None] | None = None) -> Callable[[str | None], str]:
    """``resolve(host_header)`` → the origin the request is judged as; raises
    :class:`PublicOriginRequired` when enforcement is on and nothing says who this site is."""
    origins = configured_origins(public_origin, env)
    enforcing = ENFORCE_PUBLIC_ORIGIN if enforce is None else enforce
    say = warn or logger.warning

    def resolve(host_header: str | None) -> str:
        global _warned
        host = (host_header or "").strip().lower()
        if origins:
            return next((o for o in origins if urlsplit(o).netloc == host), origins[0])
        if is_loopback_host(host):
            return f"{scheme}://{host}"
        if enforcing:
            raise PublicOriginRequired()
        if not _warned:
            _warned = True
            say("[aidr] public_origin is not set: requests are judged by their Host header, which "
                "the client chooses. A request signed for another site could be replayed here. Set "
                f"public_origin (or {PUBLIC_ORIGIN_ENV}) to this site's origin; from aidr-verifier "
                "0.2.0 it is required.")
        return f"{scheme}://{host}"

    return resolve
