#!/usr/bin/env python3
"""Prepare text for pasting into the provider's noVNC console while the console keymap is de/mac.

noVNC sends each pasted character as the US key that produces it; the console then reads that
key with the German layout ('yz-#/' arrives as 'zyß§-', test 2026-10-12). This tool does the
reverse: for every wanted character it picks the US character on the key that yields it in
de/mac, and puts the result on the macOS clipboard. Nothing is printed unless --show is given.

Table: 'ckbcomp -layout de -variant mac' and 'ckbcomp us' on silo, keycodes 2-53, 2026-10-12.
Not reachable: dead keys (´ ` ^), AltGr/Option characters (@ € { } [ ] | \\ ~), and < > (ISO key
without a US counterpart).

Usage:
  vnc-paste.py            ask for the text hidden (password), copy result to clipboard
  vnc-paste.py --show     read the text visibly and also print the result (no secrets)
"""
import getpass
import subprocess
import sys

# keycode: (de plain, de shift, us plain, us shift)
KEYS = {
    2: ("1", "!", "1", "!"), 3: ("2", '"', "2", "@"), 4: ("3", "§", "3", "#"),
    5: ("4", "$", "4", "$"), 6: ("5", "%", "5", "%"), 7: ("6", "&", "6", "^"),
    8: ("7", "/", "7", "&"), 9: ("8", "(", "8", "*"), 10: ("9", ")", "9", "("),
    11: ("0", "=", "0", ")"), 12: ("ß", "?", "-", "_"),
    16: ("q", "Q", "q", "Q"), 17: ("w", "W", "w", "W"), 18: ("e", "E", "e", "E"),
    19: ("r", "R", "r", "R"), 20: ("t", "T", "t", "T"), 21: ("z", "Z", "y", "Y"),
    22: ("u", "U", "u", "U"), 23: ("i", "I", "i", "I"), 24: ("o", "O", "o", "O"),
    25: ("p", "P", "p", "P"), 26: ("ü", "Ü", "[", "{"), 27: ("+", "*", "]", "}"),
    30: ("a", "A", "a", "A"), 31: ("s", "S", "s", "S"), 32: ("d", "D", "d", "D"),
    33: ("f", "F", "f", "F"), 34: ("g", "G", "g", "G"), 35: ("h", "H", "h", "H"),
    36: ("j", "J", "j", "J"), 37: ("k", "K", "k", "K"), 38: ("l", "L", "l", "L"),
    39: ("ö", "Ö", ";", ":"), 40: ("ä", "Ä", "'", '"'), 41: (None, "°", "`", "~"),
    43: ("#", "'", "\\", "|"), 44: ("y", "Y", "z", "Z"), 45: ("x", "X", "x", "X"),
    46: ("c", "C", "c", "C"), 47: ("v", "V", "v", "V"), 48: ("b", "B", "b", "B"),
    49: ("n", "N", "n", "N"), 50: ("m", "M", "m", "M"), 51: (",", ";", ",", "<"),
    52: (".", ":", ".", ">"), 53: ("-", "_", "/", "?"),
}

MAP = {" ": " "}
for de_p, de_s, us_p, us_s in KEYS.values():
    if de_p:
        MAP[de_p] = us_p
    MAP[de_s] = us_s


def convert(text):
    bad = sorted({c for c in text if c not in MAP})
    if bad:
        sys.exit("nicht über Einfügen erreichbar: " + " ".join(bad) + " (von Hand tippen)")
    return "".join(MAP[c] for c in text)


def main():
    show = "--show" in sys.argv[1:]
    text = input("Text: ") if show else getpass.getpass("Passwort (unsichtbar): ")
    out = convert(text)
    subprocess.run(["pbcopy"], input=out.encode(), check=True)
    if show:
        print("Einfügen:", out)
    print(f"{len(out)} Zeichen in der Zwischenablage; nach dem Einfügen Zwischenablage leeren: pbcopy </dev/null")


if __name__ == "__main__":
    main()
