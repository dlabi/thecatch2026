# CRMS — Cat Reverse Mail Service

## Challenge description

**Points:** 1

```
Hi Associate Researcher,

cats are valued members of the NREN-TCC community. Their curiosity, intelligence, and dedication help advance science, research, and education. Always eager to assist, these furry colleagues work tirelessly to support everyone—one paw, one discovery, and one helpful message at a time.

"Need help? Just ask the NREN cat team. For example, they have recently created a new service called CRMS", says the Head of the Department of Feline Research.

Stay curious!

Access the service at http://crms.nren.tcc/
```

## Summary

A Flask/gunicorn web app ("Cat **Reverse** Mail Service") does not *receive* mail — it
**connects back to the client's source IP on TCP/2525 (SMTP) to deliver** an email
containing the flag. Standing up a listener on that port and triggering `POST /send`
yields the flag.

## Solution

### Step 1: Recon → the only action is `POST /send`

The site (`http://crms.nren.tcc/`) has a single form posting to `/send`. All other paths
return `404`; `/send` is `405` on GET. Hitting `POST /send` sets a signed Flask `session`
cookie and redirects to `/`. The cookie payload (leading `.` = zlib-compressed, then
base64url) carries the result message — and on the first try it leaked the mechanism:

```
IP address: 10.200.0.36   Port: TCP/2525   Error: [Errno 111] Connection refused
Title: Tiger cat could not deliver the message
```

The server tries to open an **SMTP connection back to our source IP** (our VPN address,
`10.200.0.36`) on **TCP/2525** to deliver the "surprise". "Connection refused" (not a
timeout) confirmed packets from the server reach our host through the VPN — only a
listener was missing. "Reverse" in the name is the whole trick.

### Step 2: Catch the mail

Run a minimal SMTP sink bound to the VPN IP, then trigger delivery. The server connects
from `10.99.26.12` (crms.nren.tcc) and hands over the email with the flag.

```python
#!/usr/bin/env python3
# solve.py — dependency-free SMTP sink + trigger. Run with Windows/any Python 3.
# Usage: python solve.py
import socket, threading, urllib.request, time

VPN_IP = "10.200.0.36"      # our source IP as seen by the server (VPN address)
PORT   = 2525               # SMTP port the service dials back to
TARGET = "http://crms.nren.tcc/send"
captured = []

def smtp_sink():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((VPN_IP, PORT)); s.listen(1)
    conn, _ = s.accept()
    f = conn.makefile("rwb", buffering=0)
    f.write(b"220 sink ready\r\n")
    in_data, body = False, []
    while True:
        raw = f.readline()
        if not raw: break
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if in_data:
            if line == ".":
                captured.append("\n".join(body)); f.write(b"250 OK\r\n"); in_data = False
            else:
                body.append(line)
            continue
        up = line.upper()
        if up.startswith("DATA"):
            f.write(b"354 go\r\n"); in_data = True
        elif up.startswith("QUIT"):
            f.write(b"221 bye\r\n"); break
        else:                      # EHLO/HELO/MAIL/RCPT/... — stay plaintext, no STARTTLS
            f.write(b"250 OK\r\n")
    conn.close()

t = threading.Thread(target=smtp_sink, daemon=True); t.start()
time.sleep(0.5)
# IMPORTANT: force the request over IPv4 so our source IP is the routed VPN address.
urllib.request.urlopen(TARGET, data=b"", timeout=25).read()
t.join(timeout=10)
print(captured[0] if captured else "no mail received")
```

Captured message:

```
Subject: Message from Tiger (not a tiger)
From: Tiger the Cat <tigercat@dfr.nren.tcc>
To: my favorite player

Hello hooman,
I'm sending you a secret code, to make you happy.

FLAG{eEA9-WUne-CloQ-Ofaz}

Do not share it with dogs!
```


## Flag

```
FLAG{eEA9-WUne-CloQ-Ofaz}
```
