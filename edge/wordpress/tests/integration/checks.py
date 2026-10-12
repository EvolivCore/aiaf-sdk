"""Live checks against WordPress with the plugin active. Run by run.sh, one step at a time.

Every agent request is signed by the CLI mock agent (scripts/staging_agent.py) and carries a
credential freshly issued by the local registry.

    python checks.py <step>
"""

from __future__ import annotations

import concurrent.futures
import subprocess
import sys
from pathlib import Path

import httpx

SITE = "http://wordpress"
REGISTRY = "https://registry:8443"
KEY = "/shared/agent-key.json"
AID = Path("/shared/aid.txt").read_text(encoding="utf-8").strip()
CA = "/shared/registry-ca.pem"
WHOAMI = "/wp-json/aidr/v1/whoami"

failures = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global failures
    failures += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}".rstrip())


def signed(path: str, method: str = "GET") -> dict[str, str]:
    out = "/tmp/sig.txt"
    subprocess.run([sys.executable, "/repo/scripts/staging_agent.py", "sign", KEY, AID, method,
                    f"{SITE}{path}", out], check=True)
    lines = Path(out).read_text(encoding="utf-8").strip().splitlines()
    return dict(line.split(": ", 1) for line in lines)


def credential() -> str:
    return httpx.post(f"{REGISTRY}/test/credential", verify=CA).json()["credential"]


def agent(path: str = WHOAMI) -> dict[str, str]:
    return {**signed(path), "Agent-Credential": credential()}


def get(path: str, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.get(f"{SITE}{path}", headers=headers or {}, follow_redirects=False, timeout=30)


def error_of(response: httpx.Response) -> str:
    try:
        return str(response.json().get("error"))
    except ValueError:
        return f"(non-JSON HTTP {response.status_code})"


def step_outcomes() -> None:
    home = get("/")
    check("anonymous page is served normally", home.status_code == 200, str(home.status_code))
    check("every response varies on the agent headers",
          "agent-credential" in home.headers.get("vary", "").lower(), home.headers.get("vary", ""))

    anonymous = get(WHOAMI)
    check("anonymous caller is anonymous", anonymous.json().get("status") == "anonymous", anonymous.text)

    headers = agent()
    verified = get(WHOAMI, headers)
    body = verified.json()
    check("verified agent is identified", verified.status_code == 200 and body.get("aid") == AID,
          f"{verified.status_code} {body.get('aid')} AgAL{body.get('agal')} OAL{body.get('oal')} KAL{body.get('kal')}")
    cache = verified.headers.get("cache-control", "")
    check("an agent's response is private and never stored", "no-store" in cache and "private" in cache, cache)

    replay = get(WHOAMI, headers)
    check("replayed request is refused (database nonce store)",
          replay.status_code == 401 and error_of(replay) == "aidr.verify.replay_detected",
          f"{replay.status_code} {error_of(replay)}")
    check("a refusal is never stored", "no-store" in replay.headers.get("cache-control", ""),
          replay.headers.get("cache-control", ""))

    lone = get(WHOAMI, {"Agent-Credential": credential()})
    check("credential without a signature is refused, not treated as anonymous",
          lone.status_code == 401 and error_of(lone) == "aidr.crypto.malformed_token",
          f"{lone.status_code} {error_of(lone)}")

    genuine = agent()
    forged = {**genuine, "Signature": genuine["Signature"][:-6] + "AAAAA:"}
    first = get(WHOAMI, forged)
    second = get(WHOAMI, genuine)
    check("a forged request does not consume the genuine nonce",
          first.status_code == 401 and second.status_code == 200, f"{first.status_code} then {second.status_code}")

    bypassed = get("/robots.txt", {"Signature": "sig1=:AAAA:"})
    check("bypassed path is never verified", bypassed.status_code == 200, str(bypassed.status_code))
    # %2e%2e rather than ..%2f: Apache refuses encoded slashes itself, before PHP ever runs.
    not_bypassed = get("/robots.txt/%2e%2e/wp-json", {"Signature": "sig1=:AAAA:"})
    check("an encoded dot segment does not ride a bypass rule", not_bypassed.status_code == 401,
          str(not_bypassed.status_code))

    racing = agent()
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        statuses = list(pool.map(lambda _: get(WHOAMI, racing).status_code, range(10)))
    check("ten concurrent copies of one request: exactly one is served",
          statuses.count(200) == 1 and statuses.count(401) == 9, str(sorted(statuses)))


def step_expect(code: str) -> None:
    response = get(WHOAMI, agent())
    check(f"agent refused 403 {code}", response.status_code == 403 and error_of(response) == code,
          f"{response.status_code} {response.json().get('reason') if response.status_code != 200 else ''}")


PRE_REVOCATION = Path("/tmp/pre-revocation-credential")


def step_revoke() -> None:
    # The registry will not issue a credential to a revoked agent, so the threat revocation sync
    # exists for is a credential issued just BEFORE revocation, still inside its 15-minute life.
    PRE_REVOCATION.write_text(credential(), encoding="utf-8")
    httpx.post(f"{REGISTRY}/test/revoke", verify=CA).raise_for_status()
    print("credential issued, then the agent revoked at the registry")


def step_revoked() -> None:
    headers = {**signed(WHOAMI), "Agent-Credential": PRE_REVOCATION.read_text(encoding="utf-8")}
    response = get(WHOAMI, headers)
    check("a still-unexpired credential of a revoked agent is refused 403",
          response.status_code == 403 and error_of(response) == "aidr.verify.agent_revoked",
          f"{response.status_code} {error_of(response)}")


def step_verified() -> None:
    response = get(WHOAMI, agent())
    check("agent verified", response.status_code == 200, str(response.status_code))


if __name__ == "__main__":
    step = sys.argv[1]
    if step == "outcomes":
        step_outcomes()
    elif step == "expect":
        step_expect(sys.argv[2])
    elif step == "revoke":
        step_revoke()
    elif step == "revoked":
        step_revoked()
    elif step == "verified":
        step_verified()
    sys.exit(1 if failures else 0)
