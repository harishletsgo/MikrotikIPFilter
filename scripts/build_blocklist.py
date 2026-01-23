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
    seen_v4: set[ipaddress._BaseNetwork] = set()
    seen_v6: set[ipaddress._BaseNetwork] = set()
    total_lines = 0
    total_valid = 0

    for url in URLS:
        text = fetch_text(url)
        for line in text.splitlines():
            total_lines += 1
            token = normalize_token(line)
            if not token:
                continue
            net = ipaddress.ip_network(token, strict=False)
            target = seen_v4 if net.version == 4 else seen_v6
            if net not in target:
                target.add(net)
                total_valid += 1

    collapsed_v4 = list(ipaddress.collapse_addresses(seen_v4))
    collapsed_v6 = list(ipaddress.collapse_addresses(seen_v6))
    entries = sorted(
        collapsed_v4 + collapsed_v6,
        key=lambda n: (n.version, int(n.network_address), n.prefixlen),
    )

    with open("blocklist.txt", "w", encoding="ascii") as f:
        for entry in entries:
            f.write(str(entry))
            f.write("\n")

    with open("blocklist.rsc", "w", encoding="ascii") as f:
        for entry in entries:
            if entry.version == 6:
                f.write("/ipv6 firewall address-list add ")
            else:
                f.write("/ip firewall address-list add ")
            f.write("list=BlockIPs address=")
            f.write(str(entry))
            f.write(' comment="Auto-blocked IPs" timeout=1d\n')

    print(
        f"lines={total_lines} entries={len(entries)} "
        f"new={total_valid} "
        f"collapsed_v4={len(collapsed_v4)} collapsed_v6={len(collapsed_v6)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
