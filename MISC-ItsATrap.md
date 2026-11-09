# It's a Trap!

## Challenge description

**Points:** 2

```
Hi Senior Researcher,

we've received a report about an unregistered web service operating somewhere in the 10.100.26.0/24 network. There is one problem: the subnet has become unusually noisy. Every address and every port seems eager to talk, driving our AI-driven automated scanner completely mad.

Your task is to find the web service.

Stay curious!
```


## Summary

An unregistered web service hides in `10.100.26.0/24`, but the subnet is a
**LaBrea tarpit**: it answers SYN/ACK for **every port on every host**, so SYN- and
connect-scans report ~254×65535 "open" ports and any port-scanner is useless. The
catch is that the tarpit **accepts connections but never sends application data**.
So the honest discriminator is *"does this socket actually reply?"* — probe with a
real request and a **short read timeout**: the tarpit costs one timeout, a real
service answers within a round-trip. That instantly reveals the three genuine hosts
(real **SSH** banners on `.1`, `.10`, `.66`); a full-port data-scan of those three
finds a Python `http.server` on **`10.100.26.66:2025`** serving the flag.

## Solution

### Step 1: Recognise the tarpit

`nmap -sS`/`-sT` show every port open; `nmap -sV` returns no banners (66 s, all `?`).
Careful connect+GET on port 80 across all 254 hosts: 254/254 connect, **0 data**.
Conclusion: a tarpit that SYN/ACKs everything and stays silent — ignore "open/closed"
and look only for a real reply.

### Step 2: Scan for *data*, not for open ports

An async sweep (short read timeout) over the /24 pulls real banners out of the noise.
Three hosts return a genuine **SSH-2.0-OpenSSH** banner — the real machines in the
tarpit (`.1`, `.10`, `.66`; they also RST random high ports instead of spoofing them
open). A full-port data-scan of just those three surfaces the hidden web service.

### Step 3: Find the service and read the flag

```python
#!/usr/bin/env python3
"""Solve: It's a Trap! — find the one real web service in a LaBrea-tarpitted /24 by
scanning for actual replies (the tarpit accepts every port but never sends data)."""
import asyncio, re, urllib.request

SUBNET = "10.100.26."
REQ = b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n"

async def probe(ip, port, connto=1.5, recvto=0.6, sem=None):
    async with sem:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), connto)
        except Exception:
            return None
        try:
            w.write(REQ); await w.drain()
            data = await asyncio.wait_for(r.read(2048), recvto)   # tarpit -> b'' ; real -> bytes
        except Exception:
            data = b""
        try: w.close()
        except Exception: pass
        return (ip, port, data) if data else None

async def sweep(pairs, conc):
    sem = asyncio.Semaphore(conc)
    out = []
    for i in range(0, len(pairs), 40000):
        for res in await asyncio.gather(*(probe(ip, p, sem=sem) for ip, p in pairs[i:i+40000])):
            if res: out.append(res)
    return out

async def main():
    hosts = [SUBNET + str(i) for i in range(1, 255)]
    # Phase 1: ports 1-1024 across the /24 -> real hosts leak real banners (SSH on 22)
    phase1 = await sweep([(ip, p) for p in range(1, 1025) for ip in hosts], conc=1500)
    real = sorted({ip for ip, p, d in phase1}, key=lambda x: int(x.split(".")[-1]))
    print("[*] real hosts (returned data):", real)
    # Phase 2: full-port data-scan of the real hosts -> the hidden HTTP service
    phase2 = await sweep([(ip, p) for p in range(1, 65536) for ip in real], conc=900)
    for ip, port, data in phase2:
        if data.startswith(b"HTTP/"):
            print(f"[+] web service: http://{ip}:{port}/")
            body = urllib.request.urlopen(f"http://{ip}:{port}/", timeout=15).read().decode("utf-8","replace")
            print("[+] FLAG:", re.search(r"FLAG\{[^}]+\}", body).group())

asyncio.run(main())
```

Output:

```
[*] real hosts (returned data): ['10.100.26.1', '10.100.26.10', '10.100.26.66']
[+] web service: http://10.100.26.66:2025/
[+] FLAG: FLAG{O2pS-yj4k-Qd8U-v9ft}
```

The page at `http://10.100.26.66:2025/` is an **in-memoriam for Pavel Vachek**, a
CESNET founder of **CESNET-CERTS** who brought **LaBrea** (the tarpit used here) to
CESNET — a fitting theme for the challenge.

## Flag

```
FLAG{O2pS-yj4k-Qd8U-v9ft}
```

## Notes

- Defeat a SYN/ACK-spoofing tarpit by scanning for an **application-layer reply**,
  not for open/closed ports — SYN and connect scans are both fooled; only "does it
  send data?" is honest. A **short read timeout** turns the tarpit's silence into a
  cheap uniform timeout and keeps the async sweep fast.
- Real hosts also give themselves away by **RST-ing** random high ports (a real TCP
  stack) instead of spoofing them open — an independent way to shortlist `.1/.10/.66`.
- Service port `2025` was arbitrary/high, which is why port-guessing fails and a
  content-based sweep is required.
- Artifacts saved next to this file: `itsATrap_service_page.html` (the memorial page
  with the flag) and `itsATrap_pavel-vachek.png` (the photograph it serves).
```
