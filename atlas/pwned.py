"""Has this password been leaked? Checked against Have I Been Pwned's Pwned Passwords list.

The password never leaves the PC: Atlas hashes it (SHA-1) and sends only the first 5 characters
of the hash. The service answers with every leaked hash starting with those 5 characters
(hundreds of them, padded with fakes), and Atlas looks for the rest of the hash in that list here.
Nothing is saved. Free, no key needed.
"""

from __future__ import annotations

import hashlib

import requests

RANGE_URL = "https://api.pwnedpasswords.com/range/"


def times_leaked(password: str, get=requests.get) -> int:
    """How many times this password appears in known leaks (0 = not found)."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, rest = digest[:5], digest[5:]
    resp = get(RANGE_URL + prefix, headers={"Add-Padding": "true", "User-Agent": "Project-Atlas"}, timeout=20)
    resp.raise_for_status()
    for line in resp.text.splitlines():
        suffix, _, count = line.strip().partition(":")
        if suffix == rest:
            return int(count or 0)
    return 0


def verdict(count: int) -> str:
    if count == 0:
        return ("Not found in any known leak. That doesn't make it strong: use a long, unique password for each "
                "account, ideally from a password manager.")
    return (f"This password has appeared in data leaks {count:,} time(s). Criminals try leaked passwords first, so "
            "stop using it everywhere you do, starting with email and banking. Turn on two-step sign-in too.")
