# Document Scan

## Challenge description

**Points:** 2

```
Hi Senior Researcher,

an awkward incident occurred at the NREN headquarters: an important document was scanned and immediately shredded for security reasons. However, the digital copy has since disappeared, and no trace can be found on the file servers.

Fortunately, a network capture of the scanner’s communication was recorded at the time of the incident. Your task is to reconstruct the missing document from the PCAP.

Stay curious!

Download the evidence. (SHA256 fingerpring 09982464cc16f288be66d33874de8bb1db6a414503e99666d15087dc5e1f3269)
```

## Summary

A document was scanned and shredded; only a PCAP of the scanner's traffic remains.
The scanner is a **Canon multi-function device** talking **MFNP** (Canon
Multi-Function Network Protocol) on TCP **8610**, streaming the page as **raw 8-bit
grayscale raster** (no image file to carve). A provided reference pair
(`reference_scan.pcapng` + its known `reference_scan.png`) acts as a Rosetta Stone:
the PNG is **4960×7015, 1-bit = A4 @ 600 DPI**, and the ~35 MB transfer equals
`4960×7015×1` bytes of grayscale. Reassembling the scanner→PC MFNP frames, keeping
the large `0x82 0x20` data blocks and stripping their 8-byte block headers,
reconstructs the page exactly. The rebuilt document is an "NREN-TCC Annual Ball"
invitation whose **QR code** encodes the flag.

## Solution

### Step 1: Identify the scanner protocol

`tshark -z conv,tcp` shows one dominant flow, `10.100... PC ↔ 10.10.1.9:canon-mfnp`
(~37 MB scanner→PC). Every message starts with ASCII `MFNP`: a 16-byte header
(`"MFNP"`, type, cmd, seq, 4-byte length) + payload. Control frames are `0x82 0x21`
(4-byte values) and small `0x82 0x20` acks (`0606…`); the raster rides in 144 large
`0x82 0x20` blocks.

### Step 2: Prove the raster format with the reference pair

`reference_scan.png` is 4960×7015 1-bit (A4 @ 600 DPI). The scanner sends 8-bit
grayscale, so the page is `4960×7015 = 34,794,400` bytes. The 144 big blocks total
`34,795,552`; subtracting a per-block 8-byte header (`144×8 = 1,152`) gives exactly
`34,794,400`. Rebuilding the reference this way and thresholding reproduces
`reference_scan.png` at **100 % pixel agreement** — format confirmed.

### Step 3: Reconstruct the document and decode the QR

Apply the identical decode to `document_scan.pcapng`, reshape to 4960×7015 grayscale,
and decode the QR in the rendered page:

```python
#!/usr/bin/env python3
"""Solve: Document Scan — rebuild a Canon MFNP raster scan from a PCAP and read the QR flag."""
import subprocess, re, numpy as np
from PIL import Image
from pyzbar.pyzbar import decode as qrdecode

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
PCAP   = r"D:\ALES\ctf\catch2026\documents\document_scan.pcapng"
W      = 4960                      # A4 @ 600 DPI width; height derives from byte count

# 1) locate the Canon MFNP scanner stream (TCP 8610) and reassemble scanner->PC bytes
stream = subprocess.run([TSHARK,"-r",PCAP,"-Y","tcp.port==8610","-T","fields",
                         "-e","tcp.stream"],capture_output=True,text=True).stdout.split()[0]
follow = subprocess.run([TSHARK,"-r",PCAP,"-q","-z",f"follow,tcp,raw,{stream}"],
                        capture_output=True,text=True).stdout
# tab-indented lines are the server(scanner)->client(PC) direction
data = b"".join(bytes.fromhex(ln.strip()) for ln in follow.splitlines() if ln.startswith("\t"))

# 2) parse MFNP frames; keep big 0x20 data blocks, strip each block's 8-byte header
off, big = 0, []
while off + 16 <= len(data):
    if data[off:off+4] != b"MFNP":
        off = data.find(b"MFNP", off+1)
        if off == -1: break
        continue
    cmd    = data[off+5]
    length = int.from_bytes(data[off+12:off+16], "big")
    payload = data[off+16:off+16+length]
    if cmd == 0x20 and length > 1000:
        big.append(payload[8:])          # drop 8-byte block header -> raw raster slice
    off += 16 + length

raster = b"".join(big)
H = len(raster) // W
arr = np.frombuffer(raster[:W*H], np.uint8).reshape(H, W)
Image.fromarray(arr, "L").save(r"D:\ALES\ctf\catch2026\documentScan_reconstructed.png")

# 3) decode the QR code on the reconstructed page
for sym in qrdecode(Image.fromarray(arr)):
    print("[+] FLAG:", sym.data.decode())
```

Output:

```
[+] FLAG: FLAG{GOTO-NREN-BALL-BABY}
```

## Flag

```
FLAG{GOTO-NREN-BALL-BABY}
```

## Notes

- `canon-mfnp` on TCP **8610** carries raw raster, not a wrapped JPEG/PDF — nothing
  to "export object"; you must reassemble the stream and carve the pixels.
- The reference scan + its PNG pinned down image geometry (A4 / 600 dpi), pixel
  format (8-bit gray) and the per-block framing (8-byte header). The byte identity
  `big_total − 144×8 = 4960×7015` fixed the header size without fully reversing MFNP.
- Reconstructed page is an "NREN-TCC Annual Ball" invitation signed *Ivanhoe
  Turtleboy*; the flag is only in the QR code (lower-left).
- Artifacts saved next to this file: `documentScan_reconstructed.png` (full A4 page)
  and `documentScan_qr.png` (cropped QR).
```
