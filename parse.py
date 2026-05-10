#!/usr/bin/env python3
"""
Downloads geoip-ru-only.dat and generates two lists:
  ru-whitelist.txt  — IP-диапазоны российских сетей (RU-WHITELIST)
  not-ru.txt        — всё IPv4 пространство КРОМЕ российских IP
                      (используется в Подкопе для режима «весь трафик через прокси»)
"""
import socket, ipaddress, urllib.request, sys

SOURCE_URL    = "https://raw.githubusercontent.com/runetfreedom/russia-blocked-geoip/release/geoip-ru-only.dat"
CATEGORY      = "RU-WHITELIST"
OUT_WHITELIST = "ru-whitelist.txt"
OUT_NOT_RU    = "not-ru.txt"

def _varint(data, pos):
    result, shift = 0, 0
    while True:
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80): break
        shift += 7
    return result, pos

def _ld(data, pos):
    n, pos = _varint(data, pos)
    return data[pos:pos+n], pos+n

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
        if f == 1: raw, pos = _ld(data, pos); code = raw.decode()
        elif f == 2: raw, pos = _ld(data, pos); cidrs.append(_parse_cidr(raw))
        else:
            if (tag & 7) == 2: _, pos = _ld(data, pos)
            else: break
    return code, cidrs

def parse_geoip(data):
    pos, result = 0, {}
    while pos < len(data):
        tag, pos = _varint(data, pos)
        if (tag >> 3) == 1:
            raw, pos = _ld(data, pos)
            code, cidrs = _parse_entry(raw)
            if code: result[code] = cidrs
        else: break
    return result

def to_net(ip_b, pfx):
    if not ip_b or pfx is None or len(ip_b) != 4: return None
    return ipaddress.IPv4Network(f"{socket.inet_ntoa(ip_b)}/{pfx}", strict=False)

def merge_ranges(ranges):
    merged = []
    for s, e in sorted(ranges):
        if merged and s <= merged[-1][1] + 1: merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else: merged.append([s, e])
    return merged

def invert_ranges(ranges, lo=0, hi=0xFFFFFFFF):
    result, cur = [], lo
    for s, e in ranges:
        if cur < s: result.append((cur, s - 1))
        cur = e + 1
    if cur <= hi: result.append((cur, hi))
    return result

def ranges_to_cidrs(ranges):
    cidrs = []
    for s, e in ranges:
        cidrs.extend(ipaddress.summarize_address_range(
            ipaddress.IPv4Address(s), ipaddress.IPv4Address(e)))
    return cidrs

def main():
    print(f"Downloading {SOURCE_URL} ...", flush=True)
    req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
    print(f"Downloaded {len(data)//1024} KB", flush=True)

    entries = parse_geoip(data)
    if CATEGORY not in entries:
        print(f"ERROR: '{CATEGORY}' not found. Available: {', '.join(sorted(entries))}", file=sys.stderr)
        sys.exit(1)

    ru_nets = sorted(
        filter(None, (to_net(ip_b, pfx) for ip_b, pfx in entries[CATEGORY])),
        key=lambda n: n.network_address)

    # 1. ru-whitelist.txt — РФ напрямую
    with open(OUT_WHITELIST, "w") as f:
        f.write("\n".join(str(n) for n in ru_nets) + "\n")
    print(f"[1] {OUT_WHITELIST}: {len(ru_nets)} CIDRs", flush=True)

    # 2. not-ru.txt — весь мир кроме РФ (для режима «всё через прокси»)
    ranges  = [(int(n.network_address), int(n.broadcast_address)) for n in ru_nets]
    not_ru  = ranges_to_cidrs(invert_ranges(merge_ranges(ranges)))
    with open(OUT_NOT_RU, "w") as f:
        f.write("\n".join(str(n) for n in not_ru) + "\n")
    print(f"[2] {OUT_NOT_RU}: {len(not_ru)} CIDRs (весь мир кроме РФ)", flush=True)

if __name__ == "__main__":
    main()
