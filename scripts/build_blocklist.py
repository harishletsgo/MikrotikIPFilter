#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import sys
import urllib.request

URLS = [
    "https://www.spamhaus.org/drop/drop.txt",
    "https://www.spamhaus.org/drop/edrop.txt",
    "https://lists.blocklist.de/lists/all.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
]


def fetch_text(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as resp:
        data = resp.read()
    return data.decode("utf-8", errors="ignore")


def normalize_token(line: str) -> str | None:
    # Remove inline comments and trim.
    for sep in ("#", ";"):
        if sep in line:
            line = line.split(sep, 1)[0]
    line = line.strip()
    if not line:
        return None

    # Use first token only.
    token = line.split()[0]
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None
    return str(net)


def main() -> int:
    seen: set[str] = set()
    total_lines = 0
    total_valid = 0

    for url in URLS:
        text = fetch_text(url)
        for line in text.splitlines():
            total_lines += 1
            token = normalize_token(line)
            if not token:
                continue
            if token not in seen:
                seen.add(token)
                total_valid += 1

    def sort_key(s: str):
        net = ipaddress.ip_network(s, strict=False)
        return (net.version, int(net.network_address), net.prefixlen)

    entries = sorted(seen, key=sort_key)

    with open("blocklist.txt", "w", encoding="ascii") as f:
        for entry in entries:
            f.write(entry)
            f.write("\n")

    print(f"lines={total_lines} entries={len(entries)} new={total_valid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
