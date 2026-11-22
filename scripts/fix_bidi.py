"""Replaces hidden bidirectional control characters in source files with visible escapes.

Why: a literal direction-control character inside code is invisible in most editors,
which is the "Trojan Source" trick. The escape text (a backslash followed by u and four
hex digits) means the same thing to Python but is visible to a human reader.

Run from the project root:  python scripts/fix_bidi.py
"""

from pathlib import Path

# Built from code points so this file itself contains no hidden characters.
BIDI_CODE_POINTS = [0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069]
FOLDERS = ("triage", "tests", "scripts")


def fix_text(text):
    for code in BIDI_CODE_POINTS:
        text = text.replace(chr(code), "\\u%04x" % code)
    return text


def main(root=Path(".")):
    paths = [p for folder in FOLDERS for p in (root / folder).glob("*.py")]
    if (root / "app.py").exists():
        paths.append(root / "app.py")
    changed = 0
    for path in paths:
        with path.open(encoding="utf-8", newline="") as handle:  # newline="" keeps CRLF as it is
            original = handle.read()
        fixed = fix_text(original)
        if fixed != original:
            with path.open("w", encoding="utf-8", newline="") as handle:
                handle.write(fixed)
            print(f"Fixed {path}")
            changed += 1
    print(f"Done. {changed} file(s) changed.")


if __name__ == "__main__":
    main()
    