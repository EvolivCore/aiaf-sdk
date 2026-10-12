"""``python -m aidr_agent`` — enroll an agent, or show who it is.

    python -m aidr_agent enroll --name research-01 [--audience https://shop.example] [--print-identity]
    python -m aidr_agent whoami --name research-01

``enroll`` reads the token from AIDR_ENROLLMENT_TOKEN (never from the command line, where it would
land in shell history and process listings). ``--print-identity`` prints the whole identity,
private key included, as one line for AIDR_AGENT_IDENTITY in a container's secret store — and
saves nothing to disk.
"""

from __future__ import annotations

import argparse
import os
import sys

from .agent import REGISTRY_ENV, TOKEN_ENV
from .identity import DEFAULT_REGISTRY, IdentityError, normalize_origin
from .keystore import IDENTITY_ENV, EnvKeyStore, FileKeyStore
from .registry import RegistryError, enroll, token_id


def main(argv: list[str] | None = None) -> int:
    # Named as it was run: the `aidr-agent` command, or `python -m aidr_agent`.
    invoked = os.path.basename(sys.argv[0]).lower()
    prog = "aidr-agent" if invoked.startswith("aidr-agent") else "python -m aidr_agent"
    parser = argparse.ArgumentParser(prog=prog, description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    enroll_cmd = commands.add_parser("enroll", help="enroll a new agent with an enrollment token")
    enroll_cmd.add_argument("--name", required=True)
    enroll_cmd.add_argument("--audience", action="append", default=None,
                            help="an origin the agent may identify to (repeatable)")
    enroll_cmd.add_argument("--description", default="")
    enroll_cmd.add_argument("--registry", default=os.environ.get(REGISTRY_ENV) or DEFAULT_REGISTRY)
    enroll_cmd.add_argument("--print-identity", action="store_true",
                            help=f"print the identity for {IDENTITY_ENV} instead of saving it")
    whoami = commands.add_parser("whoami", help="show the saved identity (never the key)")
    whoami.add_argument("--name", required=True)
    args = parser.parse_args(argv)

    try:
        if args.command == "whoami":
            identity = EnvKeyStore().load(args.name) or FileKeyStore().load(args.name)
            if identity is None:
                print(f"agent {args.name!r} is not enrolled here", file=sys.stderr)
                return 1
            print(f"aid:       {identity.aid}\nregistry:  {identity.registry}\n"
                  f"audiences: {', '.join(identity.audiences) or '(unrestricted)'}")
            return 0

        token = os.environ.get(TOKEN_ENV)
        if not token:
            print(f"set {TOKEN_ENV} to the token from the AIDR console", file=sys.stderr)
            return 2
        store = FileKeyStore()
        if not args.print_identity and store.load(args.name) is not None:
            print(f"agent {args.name!r} is already enrolled here ({store.path(args.name)})", file=sys.stderr)
            return 1
        audiences = [normalize_origin(a) for a in args.audience] if args.audience else None
        print(f"enrolling {args.name} at {args.registry} with token {token_id(token)}…", file=sys.stderr)
        identity = enroll(token, name=args.name, registry=args.registry, audiences=audiences,
                          description=args.description)
        if args.print_identity:
            print(f"enrolled {identity.aid}. Store this line as the secret {IDENTITY_ENV} "
                  "(it contains the private key):", file=sys.stderr)
            print(identity.to_portable())
        else:
            store.save(identity)
            print(f"enrolled {identity.aid}; saved to {store.path(args.name)}", file=sys.stderr)
        return 0
    except (RegistryError, IdentityError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
