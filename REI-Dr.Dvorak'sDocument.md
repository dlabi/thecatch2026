# Dr. Dvorak's Document

## Challenge description

**Points:** 1

```
Hi Associate Researcher,

The National Research and Education Network (NREN) has many experts, such as is Dr. Simon Dvorak, Chair of the Committee for Strategic QWERTY Decommissioning, member of 17 working groups, editor of 42 draft documents, and self-proclaimed "Home Row Evangelist".

Yesterday, Dr. Dvorak briefly visited a shared workstation in the NREN office. Without looking at the keyboard, he quickly typed an important document, saved it, and left for following National QWERTY Transition Initiative meeting.

Unfortunately, the resulting document appears to be complete nonsense. Your task is to recover the correct document.

Stay curious!

Download the [typed document](https://owncloud.cesnet.cz/index.php/s/bxY0ZfocJGyLqmu/download). (SHA256 fingerpring `1b10f088e53772993ed6b628e9cb4f2846f848d203a4f94248ae90baeaa83fed`)
```

## Summary

Dr. Simon Dvorak touch-typed a document on a shared workstation, but the resulting text was unreadable. He used the familiar key positions of the **Dvorak** layout while the computer interpreted his keystrokes as **US QWERTY**. Mapping characters between the same physical keys restores the entire document, including the flag.

The difficulty is an estimate based on the solution.

## Solution

### Step 1: Identify the keyboard layout mismatch

The input is `dr_dvoraks_document.txt`. The name Dvorak, the references to decommissioning QWERTY, and typing without looking at the keyboard all point to a keyboard layout mismatch.

The file begins with:

```text
Hdao isppdaufd;w ;frrsokdo;w alh kjs;d ,js aod ;kgpp f;glu X<DOKTw
```

Map each QWERTY character to the character produced by the same key in Dvorak. For example, `H → D`, `d → e`, `a → a`, and `o → r`, turning `Hdao` into `Dear`. The entire first line then becomes readable:

```text
Dear colleagues, supporters, and those who are still using QWERTY,
```

The mapping must also cover shifted characters and punctuation, including `_ → {`, `+ → }`, and `' → -`. These characters occur in the flag.

### Step 2: Recover the document and extract the flag

The complete script below matches [solve_dr_dvorak.py](solve_dr_dvorak.py). It uses only the Python standard library and was verified with Python 3.11.8. Place the script and the input document in the same directory.

```python
"""Recover Dvorak keystrokes recorded using the US QWERTY layout."""

from pathlib import Path
import re


QWERTY = (
    "`1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./"
    '~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:"ZXCVBNM<>?'
)
DVORAK = (
    "`1234567890[]',.pyfgcrl/=\\aoeuidhtns-;qjkxbmwvz"
    '~!@#$%^&*(){}"<>PYFGCRL?+|AOEUIDHTNS_:QJKXBMWVZ'
)


def main():
    source = Path(__file__).with_name("dr_dvoraks_document.txt")
    destination = source.with_name("dr_dvoraks_document.recovered.txt")
    original = source.read_bytes()
    text = original.decode("utf-8")
    recovered = text.translate(str.maketrans(QWERTY, DVORAK))

    # Verify every byte, including punctuation, case, and line endings.
    restored = recovered.translate(str.maketrans(DVORAK, QWERTY))
    assert restored.encode("utf-8") == original
    destination.write_bytes(recovered.encode("utf-8"))
    print(recovered)
    print("Recovered flag:", re.search(r"FLAG\{[^}]+\}", recovered).group())
    print("Saved:", destination)
    print("Round-trip verification: passed")


if __name__ == "__main__":
    main()
```

Run:

```powershell
python .\solve_dr_dvorak.py
```

The script saves the [recovered document](dr_dvoraks_document.recovered.txt), prints it, and extracts the flag. Converting the result back from Dvorak to QWERTY verifies that it matches the original file byte for byte. The coherent English text confirms the correct mapping direction.

Relevant excerpt from the recovered document:

```text
Stay strong, think about FLAG{BCjM-6SpO-HVpI-N13B}. Every great change begins with a remapping file.
```

Verified script output, abbreviated:

```text
Recovered flag: FLAG{BCjM-6SpO-HVpI-N13B}
Round-trip verification: passed
```

## Flag

```text
FLAG{BCjM-6SpO-HVpI-N13B}
```
