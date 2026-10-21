"""AIDR agent SDK — give an AI agent a verifiable identity from its first run.

    from aidr_agent import Agent

    agent = Agent.load_or_enroll("research-01", audiences=["https://shop.example"])
    session = agent.session()                     # requests; or agent.httpx_auth() for httpx
    session.get("https://shop.example/products")  # signed (RFC 9421) with a short-lived credential

The first run enrolls with the token in AIDR_ENROLLMENT_TOKEN (issued in the AIDR console) and
keeps the new identity; later runs load it. The private key is generated here and never sent.
LangChain: ``aidr_agent.langchain``. LlamaIndex: ``aidr_agent.llamaindex``. Command line: ``python -m aidr_agent --help``.
"""

from .agent import Agent, NotAllowed
from .identity import AgentIdentity, IdentityError
from .keystore import EnvKeyStore, FileKeyStore, KeyStore
from .registry import RegistryError

__version__ = "0.2.0"

__all__ = ["Agent", "AgentIdentity", "EnvKeyStore", "FileKeyStore", "IdentityError", "KeyStore",
           "NotAllowed", "RegistryError"]
