# Security

EvolivCore runs the AIDR registry for AI agent identities. If you have found a weakness in it, in
the SDKs or in the desktop app, please tell us privately first.

## How to report

Email **security@evolivcore.com**. The same contact is published at
`https://evolivcore.com/.well-known/security.txt` (RFC 9116).

Please include:

- what is affected (host and path, SDK and version, or desktop app version and OS);
- steps to reproduce, and what an attacker could do with it;
- your name or handle, if you would like to be credited.

Write in English or Hebrew. Please do not put the details in a public issue, a pull request or a
post until we have fixed the problem or agreed a date with you.

## What happens next

EvolivCore is a small team, so these are aims, not a contract:

- we confirm we have your report within **3 working days**;
- we tell you what we found within **10 working days**, and keep you updated until it is fixed;
- we agree a disclosure date with you, normally no later than **90 days** after your report, and
  credit you in the fix's release notes if you wish.

There is no paid bug bounty.

## Scope

In scope:

- `evolivcore.com` and its subdomains: `api.` (the registry and verification gateway),
  `console.` (the customer console), `login.` (sign-in), `aidr.` (the product site);
- the SDKs and edge plugins in this repository: the Python, Node and Go verifiers, the agent SDKs,
  the Cloudflare Worker and the WordPress plugin;
- the AIDR desktop app;
- the AIAF specification itself, where following it as written leads to an insecure result.

Out of scope:

- `admin.evolivcore.com` beyond what anyone can reach without signing in (it is for staff only);
- denial of service, load or volume testing, and automated scanning that sends large amounts of
  traffic;
- social engineering of staff or customers, and physical attacks;
- reports about our providers' own services (AWS, Cloudflare, Stripe, GitHub); report those to them;
- missing headers or settings with no demonstrated way to exploit them.

## Testing in good faith

Use your own account (the Developer plan is free) and your own agents. Do not read, change or
delete other people's data; if you reach some by accident, stop, keep no copy, and tell us what you
saw. Do not keep access open longer than needed to show the problem.

We will not take action against research that follows this page and stays within the law, and we
will work with you to understand and fix what you found.

## Supported versions

Security fixes go into the latest release of each SDK and of the desktop app. The hosted service
is always the current version.
