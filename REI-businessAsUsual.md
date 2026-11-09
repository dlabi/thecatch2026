# Business as Usual

## Challenge description

**Points:** 1

```
Hi Associate Researcher,

an anonymous source has shared a PDF document originating from the Department of Hidden Messages. At first glance, it appears to be nothing more than another copy of one of the department's routine public paper. However, the department has been distributing documents with nearly identical contents for quite some time, and the reason for doing so remains unclear. Your task is to analyze the document.

Stay curious!

Download the [PDF document](https://owncloud.cesnet.cz/index.php/s/VeHUHAxE9DeNVCW/download). (SHA256 fingerprint `95845f56dc4c0fa9c0dee4a1ee6c87991ea78cf76457b2404b6f6e5d83abb422`)
```

## Summary

Tiny cat drawings embedded in an otherwise ordinary PDF point at characters in the surrounding text. Reading the characters on page 2 reveals `hiddenpaws6.tcc`; the PNG served by that website hides the flag in its alpha channel.


## Solution

### Step 1: Follow the cats' gaze directions

The PDF contains three pages of a paper titled *The Early Origins of Steganography*. Text extraction returns the historical article, and there are no embedded file attachments or obvious flag strings in the text or metadata.

The useful clue is visual: tiny cats are scattered through the first two pages. Internally, these drawings are vector **Form XObjects**, rather than ordinary raster image objects. In the analyzed file, objects 84 through 94 hold eleven distinct drawings, reused in 28 placements. Their page transformations shrink them to roughly one percent of their original dimensions.

Enlarge the PDF substantially, or extract and render the Form XObjects. The cats have different poses and gaze directions. Each points toward a nearby character; read the selected characters in page order. The fifteen cats on page 2 give:

```text
h i d d e n p a w s 6 . t c c
```

This spells the challenge hostname:

```text
hiddenpaws6.tcc
```

The following crops show the page-2 cats in order, with the visually decoded character labeled above each crop:

![Page-2 cat clues spelling hiddenpaws6.tcc](assets/pdf-domain-clue.png)

### Step 2: Extract the website image's alpha channel

Opening [http://hiddenpaws6.tcc/](http://hiddenpaws6.tcc/) returns a page titled **Department of Hidden Messages**, labeled **Message No. 6**. Its HTML references:

```html
<img src="image.png" alt="A relaxing cat">
```

The image at [http://hiddenpaws6.tcc/image.png](http://hiddenpaws6.tcc/image.png) is a 1064 x 739 pixel RGBA PNG. Ordinary viewing shows a reclining cat. Inspecting the **alpha channel separately as a grayscale image** reveals text inside its body. Looking only at the RGB channels misses this message.

![Hidden message recovered from the alpha channel](assets/flag-detail.png)

The recovered text is:

```text
Want the VIP parking spot?
Enter this code at the gate:
FLAG{THIS-ISMY-SPOT-OKAY}
```

The script below matches [solve_business_as_usual.py](solve_business_as_usual.py). The letter selection in Step 1 is manual; this script reproduces the PNG retrieval and channel extraction after recovering the hostname. It can use the included [saved image](assets/message6.png), so that extraction remains reproducible without access to the challenge network. If Tesseract is available on PATH, it also attempts to print the flag using OCR; otherwise, read the saved alpha image directly.

```python
"""Extract the hidden message from the PNG reached through the PDF clue."""

import argparse
from io import BytesIO
from pathlib import Path
import re
import shutil
import subprocess
from urllib.request import urlopen

from PIL import Image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, help="Use a saved PNG instead of HTTP")
    parser.add_argument("--output", type=Path, default=Path("flag-alpha.png"))
    args = parser.parse_args()

    # This hostname was read manually from the cats' gaze directions in the PDF.
    url = "http://hiddenpaws6.tcc/image.png"
    if args.image:
        data = args.image.read_bytes()
    else:
        with urlopen(url, timeout=30) as response:
            data = response.read()

    with Image.open(BytesIO(data)) as image:
        if "A" not in image.getbands():
            raise ValueError("The image has no alpha channel")
        alpha = image.getchannel("A")
        alpha.save(args.output)
    print(f"Alpha channel saved to: {args.output.resolve()}")

    # OCR is optional; the original solve read the extracted image visually.
    tesseract = shutil.which("tesseract")
    if tesseract:
        result = subprocess.run(
            [tesseract, str(args.output), "stdout", "--psm", "11"],
            capture_output=True, text=True, check=True,
        )
        match = re.search(r"FLAG\{[^}\r\n]+\}", result.stdout)
        if match:
            print(match.group())
            return
    print("Open the saved image and read the flag in the cat's body.")


if __name__ == "__main__":
    main()
```

Install the required Python dependency:

```powershell
python -m pip install Pillow
```

To retrieve the image from the challenge website:

```powershell
python .\solve_business_as_usual.py
```

To reproduce the extraction offline from the included evidence:

```powershell
python .\solve_business_as_usual.py --image .\assets\message6.png --output .\flag-alpha.png
```

The offline extraction was verified with **Python 3.12.14** and **Pillow 12.3.0**. The resulting channel matched the saved evidence pixel for pixel, and the flag was read visually. The optional OCR path was not used or tested in this solve. PDF inspection used **pypdf 6.10.0**; the clue illustration was rendered with **pypdfium2 5.13.0**.

The preserved source PNG has SHA256:

```text
8e8c89f9ae0fc97e9c077b14352707b11a92e1212a5b865b66aa5c2955a6da9b
```

## Flag

```text
FLAG{THIS-ISMY-SPOT-OKAY}
```
