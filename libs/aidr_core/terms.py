"""The API terms of use an organisation accepts before it registers agents (docs/11, step 3).

``CURRENT_TERMS_VERSION`` names the text published at https://<domain>/api-terms. Changing the text
in any way that matters means changing the version: every organisation must then accept again
before it registers another agent or issues another enrollment token. The console carries the same
value (web/dashboard/src/lib/terms.ts); a test keeps the two equal.

The current text is INTERIM wording (the owner's decisions in docs/20), pending legal review.
"""

from __future__ import annotations

CURRENT_TERMS_VERSION = "2026-10-20-interim"
TERMS_PATH = "/api-terms"
