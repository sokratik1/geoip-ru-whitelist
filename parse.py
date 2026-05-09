#!/usr/bin/env python3
"""
Downloads geoip-ru-only.dat and extracts RU-WHITELIST IP CIDRs into a plain text file.
"""
import socket
import urllib.request
import sys
import os

SOURCE_URL = "https://raw.githubusercontent.com/runetfreedom/russia-blocked-geoip/release/geoip-ru-only.dat"
OUTPUT_FILE = "ru-whitelist.txt"
CATEGORY    = "RU-WHITELIST"

# ── Minimal protobuf parser ───────────────────────────────────────────────────

def _varint(data, pos):
    result, shift = 0, 0
    while True:
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos

def _ld(data, pos):
    n, pos = _varint(data, pos)
    return data[pos:pos + n], pos + n

def _parse_cidr(data):
    pos, ip, pfx = 0, None, None
    while pos < len(data):
        tag, pos = _varint(data, pos)
        f = tag >> 3
        if   f == 1: ip,  pos = _ld(data, pos)
        elif f == 2: pfx, pos = _varint(data, pos)
        else:
            if (tag & 7) == 2: _, pos = _ld(data, pos)
            else: break
    return ip, pfx

def _parse_entry(data):
    pos, code, cidrs = 0, None, []
    while pos < len(data):
        tag, pos = _varint(data, pos)
        f = tag >> 3
        if f == 1:
            raw, pos = _ld(data, pos)
            code = raw.decode()
        elif f == 2:
            raw, pos = _ld(data, pos)
            cidrs.append(_parse_cidr(raw))
        else:
            if (tag & 7) == 2: _, pos = _ld(data, pos)
            else: break
    return code, cidrs

def parse_geoip(data):
    """Returns dict: {CATEGORY: [(ip_bytes, prefix), ...]}"""
    pos, result = 0, {}
    while pos < len(data):
        tag, pos = _varint(data, pos)
        if (tag >> 3) == 1:
            raw, pos = _ld(data, pos)
            code, cidrs = _parse_entry(raw)
            if code:
                result[code] = cidrs
        else:
            break
    return result

def to_cidr(ip_b, pfx):
    if not ip_b or pfx is None:
        return None
    if len(ip_b) == 4:
        return f"{socket.inet_ntoa(ip_b)}/{pfx}"
    if len(ip_b) == 16:
        return f"{socket.inet_ntop(socket.AF_INET6, ip_b)}/{pfx}"
    return None

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print(f"Downloading {SOURCE_URL} ...", flush=True)
    req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
    print(f"Downloaded {len(data) // 1024} KB", flush=True)

    entries = parse_geoip(data)

    if CATEGORY not in entries:
        available = ", ".join(sorted(entries.keys()))
        print(f"ERROR: category '{CATEGORY}' not found. Available: {available}", file=sys.stderr)
        sys.exit(1)

    cidrs = [to_cidr(ip, pfx) for ip, pfx in entries[CATEGORY]]
    cidrs = sorted(c for c in cidrs if c)

    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(cidrs) + "\n")

    print(f"Written {len(cidrs)} CIDRs to {OUTPUT_FILE}", flush=True)

if __name__ == "__main__":
    main()
