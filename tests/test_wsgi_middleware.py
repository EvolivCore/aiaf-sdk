"""The WSGI middleware (Flask, classic Django): the same decisions as ASGI, the Worker and Node.

Every shared vector case goes through it; Flask and Django are exercised for real where they are
installed (the Python release workflow installs both).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

import pytest

from aidr_verifier import build_trust_store
from aidr_verifier.wsgi import AidrWSGIMiddleware, RelyingPartyConfig, scope_from

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads(Path(os.environ.get("AIDR_VECTORS") or ROOT / "sdk" / "testdata" / "vectors.json")
                     .read_text(encoding="utf-8"))   # AIDR_VECTORS: the conformance gate (docs/13)
EVALUATE_AT = datetime.fromtimestamp(VECTORS["evaluate_at"], tz=timezone.utc)
SUITE = VECTORS["suites"][0]
ALLOW = next(c for c in SUITE["cases"] if c["expect"] == "allow"
             and not c.get("expected_audience") and not c.get("min_assurance"))


def trust_for(suite: dict, delta: str = "delta_before_revocation"):
    with patch("aidr_crypto.jws.utcnow", lambda: EVALUATE_AT):
        return build_trust_store(suite["jwks"], expected_issuer=suite["issuer"],
                                 delta_token=suite["revocation"][delta])


def config(suite: dict = SUITE, public_origin: str = "https://shop.example", **overrides) -> RelyingPartyConfig:
    return RelyingPartyConfig(issuer=suite["issuer"], public_origin=public_origin,
                              trust=trust_for(suite), sync=False, clock=lambda: EVALUATE_AT,
                              **overrides)


def environ_for(method: str, url: str, headers: dict[str, str], *, raw_uri: bool = True) -> dict:
    parts = urlsplit(url)
    environ = {"REQUEST_METHOD": method, "wsgi.url_scheme": parts.scheme, "HTTP_HOST": parts.netloc,
               "PATH_INFO": parts.path, "QUERY_STRING": parts.query, "SCRIPT_NAME": ""}
    if raw_uri:
        environ["REQUEST_URI"] = parts.path + (f"?{parts.query}" if parts.query else "")
    for name, value in headers.items():
        environ["HTTP_" + name.upper().replace("-", "_")] = value
    return environ


def call(middleware: AidrWSGIMiddleware, method: str = "GET", url: str = "https://shop.example/api/products",
         headers: dict[str, str] | None = None, **kwargs):
    seen: dict = {}

    def app(environ, start_response):
        seen["aidr"] = environ["aidr"]
        start_response("200 OK", [("content-type", "text/plain")])
        return [b"ok"]

    middleware.app = app
    response: dict = {}

    def start_response(status, response_headers):
        response["status"] = int(status.split()[0])
        response["headers"] = dict(response_headers)

    body = b"".join(middleware(environ_for(method, url, headers or {}, **kwargs), start_response))
    return response["status"], response["headers"], body, seen.get("aidr")


class TestDecisions:
    def test_anonymous_passes_marked_anonymous(self):
        status, _, _, identity = call(AidrWSGIMiddleware(None, config()))
        assert status == 200 and identity.status == "anonymous" and not identity.is_agent

    def test_a_valid_agent_passes_with_its_identity(self):
        status, _, _, identity = call(AidrWSGIMiddleware(None, config()), ALLOW["method"], ALLOW["url"],
                                      ALLOW["headers"])
        assert status == 200 and identity.is_agent and identity.aid == SUITE["aid"]

    def test_a_garbage_credential_is_refused_not_anonymous(self):
        status, _, body, identity = call(AidrWSGIMiddleware(None, config()),
                                         headers={"Agent-Credential": "garbage"})
        assert status == 401 and identity is None
        assert json.loads(body)["error"] == "aidr.crypto.malformed_token"

    def test_a_replay_is_refused(self):
        middleware = AidrWSGIMiddleware(None, config())
        assert call(middleware, ALLOW["method"], ALLOW["url"], ALLOW["headers"])[0] == 200
        status, _, body, _ = call(middleware, ALLOW["method"], ALLOW["url"], ALLOW["headers"])
        assert status == 401 and json.loads(body)["error"] == "aidr.verify.replay_detected"

    def test_without_the_raw_uri_the_path_is_rebuilt(self):
        status, _, _, identity = call(AidrWSGIMiddleware(None, config()), ALLOW["method"], ALLOW["url"],
                                      ALLOW["headers"], raw_uri=False)
        assert status == 200 and identity.is_agent

    def test_the_scope_carries_what_the_signature_covers(self):
        scope = scope_from(environ_for("POST", "https://shop.example/a%20b?x=1", {"Signature": "s"}))
        assert (scope["method"], scope["raw_path"], scope["query_string"]) == ("POST", b"/a%20b", b"x=1")
        assert (b"signature", b"s") in scope["headers"] and (b"host", b"shop.example") in scope["headers"]


@pytest.mark.parametrize(("suite", "case"), [
    pytest.param(s, c, id=f"{s['algorithm']}: {c['name']}") for s in VECTORS["suites"] for c in s["cases"]])
def test_every_vector_case(suite, case):
    parts = urlsplit(case["url"])
    middleware = AidrWSGIMiddleware(None, config(
        suite, public_origin=f"{parts.scheme}://{parts.netloc}",
        expected_audience=case.get("expected_audience"), min_agal=case.get("min_assurance", 0)))
    status, _, body, _ = call(middleware, case["method"], case["url"], case["headers"])
    assert (status == 200) == (case["expect"] == "allow"), body
    if case["expect"] == "deny" and case.get("expect_code"):
        assert json.loads(body)["error"] == case["expect_code"]


class TestVerifiedOnly:
    def test_anonymous_is_refused_and_pointed_at_the_registry(self):
        status, headers, body, _ = call(AidrWSGIMiddleware(None, config(mode="verified-only")))
        assert status == 401 and json.loads(body)["error"] == "aidr.edge.agent_required"
        assert headers["link"] == f'<{SUITE["issuer"]}/.well-known/aiaf-registry>; rel="aiaf-registry"'

    def test_scoped_paths_people_keep_the_rest_and_ambiguity_is_protected(self):
        middleware = AidrWSGIMiddleware(None, config(mode="verified-only", verified_only_paths=[r"/api/.*"]))
        assert call(middleware, url="https://shop.example/catalogue")[0] == 200
        assert call(middleware, url="https://shop.example/api/products")[0] == 401
        assert call(middleware, url="https://shop.example/docs/%252e%252e/api/x")[0] == 401

    def test_a_mistyped_mode_is_an_error_not_an_open_site(self):
        with pytest.raises(ValueError):
            AidrWSGIMiddleware(None, config(mode="verified_only"))
        with pytest.raises(ValueError):
            AidrWSGIMiddleware(None, config(verified_only_paths=[r"/api/.*"]))


class TestFlask:
    def test_one_line_in_a_real_flask_app(self):
        flask = pytest.importorskip("flask")
        app = flask.Flask(__name__)

        @app.get("/api/products")
        def products():
            identity = flask.request.environ["aidr"]
            return {"status": identity.status, "aid": identity.aid}

        app.wsgi_app = AidrWSGIMiddleware(app.wsgi_app, config())
        client = app.test_client()
        assert client.get("/api/products", base_url="https://shop.example").json == {
            "status": "anonymous", "aid": None}
        verified = client.get("/api/products", base_url="https://shop.example", headers=ALLOW["headers"])
        assert verified.status_code == 200 and verified.json["aid"] == SUITE["aid"]
        refused = client.get("/api/products", base_url="https://shop.example",
                             headers={"Agent-Credential": "garbage"})
        assert refused.status_code == 401


class TestDjango:
    def test_classic_django_middleware(self):
        pytest.importorskip("django")
        from django.conf import settings

        if not settings.configured:
            settings.configure(ALLOWED_HOSTS=["shop.example"], DEFAULT_CHARSET="utf-8")
        import django

        django.setup()
        from django.http import JsonResponse
        from django.test import RequestFactory, override_settings

        from aidr_verifier.django import AidrMiddleware

        def view(request):
            return JsonResponse({"status": request.aidr.status, "aid": request.aidr.aid})

        AidrMiddleware._gate = None
        options = {"issuer": SUITE["issuer"], "public_origin": "https://shop.example",
                   "trust": trust_for(SUITE), "sync": False, "clock": lambda: EVALUATE_AT}
        with override_settings(AIDR=options):
            middleware = AidrMiddleware(view)
        factory = RequestFactory()
        anonymous = middleware(factory.get("/api/products", HTTP_HOST="shop.example", secure=True))
        assert json.loads(anonymous.content) == {"status": "anonymous", "aid": None}
        meta = {f"HTTP_{k.upper().replace('-', '_')}": v for k, v in ALLOW["headers"].items()}
        verified = middleware(factory.get("/api/products", HTTP_HOST="shop.example", secure=True, **meta))
        assert verified.status_code == 200 and json.loads(verified.content)["aid"] == SUITE["aid"]
        refused = middleware(factory.get("/api/products", HTTP_HOST="shop.example", secure=True,
                                         HTTP_AGENT_CREDENTIAL="garbage"))
        assert refused.status_code == 401 and refused["cache-control"] == "no-store"
        AidrMiddleware._gate = None
