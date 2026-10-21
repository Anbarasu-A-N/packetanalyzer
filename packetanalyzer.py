#!/usr/bin/env python3
"""
Fathom -- a portable packet capture inspector, single-file edition (v2).

Opens as a desktop GUI app (Tkinter -- part of Python's standard library on
most installations, so usually zero pip installs needed for file analysis).
Live capture needs `pip install scapy` plus root/sudo. Decoding QUIC Initial
packets (to show SNI / ALPN like Wireshark) uses the optional `cryptography`
package:  pip install cryptography

Usage:
    python3 fathom.py                       # opens empty; use the Open button (Ctrl+O)
    python3 fathom.py capture.pcap          # opens straight into a file (.pcap/.pcapng/.gz)
    python3 fathom.py capture.pcap --text   # no GUI: print a Wireshark-style packet list
    python3 fathom.py capture.pcap --text -v          # ...plus the full decoded tree of every packet
    python3 fathom.py capture.pcap --text -Y "stun or rtp"   # ...with a display filter
    python3 fathom.py capture.pcap --json out.json    # no GUI: dump every decoded field to JSON
    python3 fathom.py capture.pcap --expert           # no GUI: print Expert Information
    python3 fathom.py capture.pcap --stats            # no GUI: protocol hierarchy, TCP/DNS/HTTP/TLS/STUN/RTP statistics
    python3 fathom.py capture.pcap --stats-html r.html   # no GUI: HTML report with SVG charts
    sudo python3 fathom.py --live en0       # opens straight into a live capture
    python3 fathom.py --list-interfaces     # prints interface names, no GUI

pcapng extras shown like Wireshark: interface name/id, section, packet flags (Inbound/Outbound), packet
comments, nanosecond timestamps, dropped-packet counters, name-resolution and embedded-secret blocks.

Decoded: Ethernet/802.3/LLC/STP/LLDP/VLAN/MPLS, ARP, IPv4 (+options, fragments),
IPv6 (+ext headers), ICMP/ICMPv6 (incl. neighbor discovery), IGMP, TCP (options,
relative seq/ack, retransmission / dup-ACK / lost-segment / keep-alive / zero-window
analysis, stream index), UDP, DNS/mDNS/LLMNR, DHCP, NTP, SSDP, STUN/TURN, RTP, RTCP,
QUIC (Initial decryption -> SNI/ALPN), TLS (multi-record, JA3, certificates),
DTLS, HTTP, SIP/SDP, SSH, FTP/SMTP/POP/IMAP/Telnet banners.
"""
import argparse
import collections
import csv
import gzip
import hashlib
import hmac
import html
import json
import os
import queue
import re
import struct
import sys
import threading
import time
import zlib
from datetime import datetime, timezone

FATHOM_VERSION = '3.9.2 (2026-10-01: readable dropdowns in dark theme, compact UDP table, aligned table headers, compact histogram labels, UDP statistics tab, empty-tab messages; sample/demo capture removed; Wireshark-style layout, Apple process + Darwin metadata, --pcapng-info, TURN/SRTCP/ICMP-quoted dissection)'


# ============================================================================
# PART 1 -- pcap / pcapng container reader + writer (stdlib only)
# ============================================================================

class RawPacket:
    __slots__ = ('number', 'ts_sec', 'ts_usec', 'cap_len', 'orig_len', 'data', 'link_type',
                 'iface_id', 'flags', 'comments', 'section', 'ts_nsec', 'drops', 'opts')

    def __init__(self, number, ts_sec, ts_usec, cap_len, orig_len, data, link_type,
                 iface_id=0, flags=None, comments=None, section=1, ts_nsec=None, drops=None, opts=None):
        self.number = number
        self.ts_sec = ts_sec
        self.ts_usec = ts_usec
        self.cap_len = cap_len
        self.orig_len = orig_len
        self.data = data
        self.link_type = link_type
        self.iface_id = iface_id
        self.flags = flags              # pcapng epb_flags (bits 0-1 = direction), or None
        self.comments = comments or []  # pcapng packet comments
        self.section = section
        self.ts_nsec = ts_usec * 1000 if ts_nsec is None else ts_nsec   # nanoseconds within the second
        self.drops = drops              # pcapng epb_dropcount
        self.opts = opts                # other EPB options: [(code, raw_bytes, u32_or_None)] (Apple process / service-class / flow data)


LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_SLL = 113
LINKTYPE_SLL2 = 276
LAST_PARSE_WARNINGS = []
# Capture-file metadata gathered while parsing (pcapng sections / interfaces / statistics / comments / secrets)
CAPTURE_META = {}


def _reset_meta(fmt):
    CAPTURE_META.clear()
    CAPTURE_META.update({'format': fmt, 'sections': [], 'interfaces': [], 'if_stats': [], 'name_resolution': [],
                         'secrets': [], 'comments': [], 'file_comment': None, 'processes': [], 'epb_options': {},
                         'unknown_blocks': {}, 'big_endian': False})


def interface_info(section, iface_id):
    for it in CAPTURE_META.get('interfaces', []):
        if it['section'] == section and it['id'] == iface_id:
            return it
    return None


def parse_capture_bytes(buf: bytes):
    """Returns (link_type, [RawPacket, ...]). Raises ValueError on unrecognized formats.
    Non-fatal problems (truncated file, etc.) are appended to LAST_PARSE_WARNINGS; file-level
    metadata (interfaces, comments, statistics...) is left in CAPTURE_META."""
    del LAST_PARSE_WARNINGS[:]
    _reset_meta('unknown')
    if buf[:2] == b'\x1f\x8b':
        try:
            buf = gzip.decompress(buf)
        except Exception as e:
            raise ValueError(f"Could not decompress gzip capture: {e}")
    if len(buf) < 4:
        raise ValueError("File is too small to be a capture file.")
    magic = struct.unpack_from('>I', buf, 0)[0]
    if magic == 0x0a0d0d0a:
        _reset_meta('pcapng')
        return _parse_pcapng(buf)
    classic = {
        0xa1b2c3d4: (False, False),
        0xd4c3b2a1: (True, False),
        0xa1b23c4d: (False, True),
        0x4d3cb2a1: (True, True),
    }
    if magic in classic:
        le, nano = classic[magic]
        _reset_meta('pcap (nanosecond)' if nano else 'pcap')
        return _parse_pcap_classic(buf, le, nano)
    raise ValueError("Unrecognized file format \u2014 expected a .pcap or .pcapng capture.")


def _parse_pcap_classic(buf, le, nano):
    endian = '<' if le else '>'
    if len(buf) < 24:
        raise ValueError("Truncated pcap global header.")
    snaplen = struct.unpack_from(endian + 'I', buf, 16)[0]
    link_type = struct.unpack_from(endian + 'I', buf, 20)[0] & 0x0fffffff
    CAPTURE_META['interfaces'].append({'section': 1, 'id': 0, 'name': None, 'description': None, 'link_type': link_type,
                                       'snaplen': snaplen, 'speed': None, 'tsresol': '1 ns' if nano else '1 \u00b5s',
                                       'filter': None, 'os': None, 'hardware': None, 'fcslen': None, 'tsoffset': 0})
    packets, off, n, num = [], 24, len(buf), 1
    while off + 16 <= n:
        ts_sec, ts_frac, cap_len, orig_len = struct.unpack_from(endian + 'IIII', buf, off)
        off += 16
        if cap_len > n - off:
            LAST_PARSE_WARNINGS.append(f"File is cut short in the middle of packet {num}; the remainder was ignored.")
            break
        data = buf[off:off + cap_len]
        off += cap_len
        if nano:
            ns = min(ts_frac, 999999999)
            packets.append(RawPacket(num, ts_sec, ns // 1000, cap_len, orig_len, data, link_type, ts_nsec=ns))
        else:
            packets.append(RawPacket(num, ts_sec, ts_frac, cap_len, orig_len, data, link_type))
        num += 1
    return link_type, packets


def _read_options(buf, off, end, endian):
    opts = []
    while off + 4 <= end:
        code, ln = struct.unpack_from(endian + 'HH', buf, off)
        off += 4
        if code == 0:
            break
        opts.append((code, bytes(buf[off:off + ln])))
        off += ln + ((4 - ln % 4) % 4)
    return opts


def _txt(v):
    return v.decode('utf-8', errors='replace').rstrip('\x00')


def _parse_pcapng(buf):
    n = len(buf)
    off, num, le, section = 0, 1, True, 0
    packets = []
    iface_link_types, iface_units = [], []     # per current section
    meta = CAPTURE_META

    def ts_split(iface_id, ticks_hi, ticks_lo):
        """Exact (sec, nsec) from pcapng ticks using integer maths (floats lose nanoseconds at today's epoch)."""
        ticks = (ticks_hi << 32) | ticks_lo
        unit = iface_units[iface_id] if 0 <= iface_id < len(iface_units) else (False, 6, 0)
        pow2, exp, offset = unit
        if pow2:
            total = ticks * (2.0 ** -exp)
            sec = int(total)
            ns = int(round((total - sec) * 1e9))
        elif exp <= 9:
            sec, rem = divmod(ticks, 10 ** exp)
            ns = rem * 10 ** (9 - exp)
        else:
            sec, rem = divmod(ticks, 10 ** exp)
            ns = rem // 10 ** (exp - 9)
        if ns >= 1000000000:
            sec, ns = sec + 1, ns - 1000000000
        return sec + offset, ns

    def mk(iface_id, sec, ns, cap_len, orig_len, data, flags, comments, drops, opts=None):
        lt = iface_link_types[iface_id] if 0 <= iface_id < len(iface_link_types) else LINKTYPE_ETHERNET
        return RawPacket(num, sec, ns // 1000, cap_len, orig_len, data, lt, iface_id, flags, comments, section,
                         ts_nsec=ns, drops=drops, opts=opts)

    while off + 12 <= n:
        is_shb = buf[off:off + 4] == b'\x0a\x0d\x0d\x0a'
        if is_shb:
            block_type = 0x0a0d0d0a
            le = (buf[off + 8:off + 12] == b'\x4d\x3c\x2b\x1a')
            meta['big_endian'] = not le
            iface_link_types, iface_units = [], []
            section += 1
        endian = '<' if le else '>'
        if not is_shb:
            block_type = struct.unpack_from(endian + 'I', buf, off)[0]
        total_len = struct.unpack_from(endian + 'I', buf, off + 4)[0]
        if not total_len or total_len < 12 or off + total_len > n:
            LAST_PARSE_WARNINGS.append("pcapng file is cut short or contains a damaged block; the rest was ignored.")
            break
        block_end = off + total_len
        body = off + 8
        try:
            if block_type == 0x0a0d0d0a:
                sec_info = {'index': section, 'hardware': None, 'os': None, 'application': None, 'comment': None}
                for code, val in _read_options(buf, body + 16, block_end - 4, endian):
                    key = {1: 'comment', 2: 'hardware', 3: 'os', 4: 'application'}.get(code)
                    if key:
                        sec_info[key] = _txt(val)
                meta['sections'].append(sec_info)
                if sec_info['comment'] and not meta['file_comment']:
                    meta['file_comment'] = sec_info['comment']
            elif block_type == 1:  # Interface Description Block
                link_type, _res, snaplen = struct.unpack_from(endian + 'HHI', buf, body)
                it = {'section': section, 'id': len(iface_link_types), 'name': None, 'description': None,
                      'link_type': link_type, 'snaplen': snaplen, 'speed': None, 'tsresol': '1 \u00b5s', 'filter': None,
                      'os': None, 'hardware': None, 'fcslen': None, 'tsoffset': 0, 'mac': None, 'ipv4': [], 'ipv6': []}
                exp, pow2 = 6, False
                for code, val in _read_options(buf, body + 8, block_end - 4, endian):
                    if code == 2:
                        it['name'] = _txt(val)
                    elif code == 3:
                        it['description'] = _txt(val)
                    elif code == 4 and len(val) >= 4:
                        it['ipv4'].append('.'.join(str(x) for x in val[:4]))
                    elif code == 5 and len(val) >= 16:
                        it['ipv6'].append(val[:16].hex())
                    elif code == 6 and len(val) == 6:
                        it['mac'] = ':'.join('%02x' % x for x in val)
                    elif code == 8 and len(val) == 8:
                        it['speed'] = struct.unpack(endian + 'Q', val)[0]
                    elif code == 9 and val:
                        pow2, exp = bool(val[0] & 0x80), val[0] & 0x7f
                        it['tsresol'] = f'2^-{exp} s' if pow2 else f'1e-{exp} s'
                    elif code == 11 and len(val) > 1:
                        it['filter'] = _txt(val[1:])
                    elif code == 12:
                        it['os'] = _txt(val)
                    elif code == 13 and val:
                        it['fcslen'] = val[0]
                    elif code == 14 and len(val) == 8:
                        it['tsoffset'] = struct.unpack(endian + 'q', val)[0]
                    elif code == 15:
                        it['hardware'] = _txt(val)
                iface_link_types.append(link_type)
                iface_units.append((pow2, exp, it['tsoffset']))
                meta['interfaces'].append(it)
            elif block_type == 6:  # Enhanced Packet Block
                iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack_from(endian + 'IIIII', buf, body)
                data_off = body + 20
                if cap_len <= n - data_off:
                    data = buf[data_off:data_off + cap_len]
                    opt_off = data_off + cap_len + ((4 - cap_len % 4) % 4)
                    flags, comments, drops, extra = None, [], None, []
                    for code, val in _read_options(buf, opt_off, block_end - 4, endian):
                        if code == 1:
                            comments.append(_txt(val))
                        elif code == 2 and len(val) == 4:
                            flags = struct.unpack(endian + 'I', val)[0]
                        elif code == 4 and len(val) == 8:
                            drops = struct.unpack(endian + 'Q', val)[0]
                        else:
                            u = struct.unpack(endian + 'I', val)[0] if len(val) == 4 else None
                            extra.append((code, val, u))
                            st_ = meta['epb_options'].setdefault(code, {'count': 0, 'lengths': set(), 'samples': []})
                            st_['count'] += 1
                            st_['lengths'].add(len(val))
                            if len(st_['samples']) < 4 and val.hex() not in st_['samples']:
                                st_['samples'].append(val.hex())
                    sec, ns = ts_split(iface_id, ts_high, ts_low)
                    packets.append(mk(iface_id, sec, ns, cap_len, orig_len, data, flags, comments, drops, extra or None))
                    num += 1
            elif block_type == 3:  # Simple Packet Block
                orig_len = struct.unpack_from(endian + 'I', buf, body)[0]
                cap_len = min(orig_len, total_len - 16)
                data_off = body + 4
                if cap_len <= n - data_off:
                    packets.append(mk(0, 0, 0, cap_len, orig_len, buf[data_off:data_off + cap_len], None, [], None))
                    num += 1
            elif block_type == 2:  # legacy Packet Block
                iface_id, _drops, ts_high, ts_low, cap_len, orig_len = struct.unpack_from(endian + 'HHIIII', buf, body)
                data_off = body + 16
                if cap_len <= n - data_off:
                    sec, ns = ts_split(iface_id, ts_high, ts_low)
                    packets.append(mk(iface_id, sec, ns, cap_len, orig_len, buf[data_off:data_off + cap_len], None, [], _drops))
                    num += 1
            elif block_type == 5:  # Interface Statistics Block
                iface_id, ts_high, ts_low = struct.unpack_from(endian + 'III', buf, body)
                st = {'section': section, 'iface': iface_id, 'comment': None, 'start': None, 'end': None, 'recv': None,
                      'drop': None, 'filter_accept': None, 'os_drop': None, 'delivered': None}
                for code, val in _read_options(buf, body + 12, block_end - 4, endian):
                    if code == 1:
                        st['comment'] = _txt(val)
                    elif code in (2, 3) and len(val) == 8:
                        hi, lo = struct.unpack(endian + 'II', val)
                        st['start' if code == 2 else 'end'] = ts_split(iface_id, hi, lo)[0]
                    elif len(val) == 8:
                        key = {4: 'recv', 5: 'drop', 6: 'filter_accept', 7: 'os_drop', 8: 'delivered'}.get(code)
                        if key:
                            st[key] = struct.unpack(endian + 'Q', val)[0]
                meta['if_stats'].append(st)
                if st['drop']:
                    LAST_PARSE_WARNINGS.append(f"Capture interface {iface_id} reports {st['drop']:,} packets dropped by the capturing system.")
            elif block_type == 4:  # Name Resolution Block
                p = body
                while p + 4 <= block_end - 4:
                    rtype, rlen = struct.unpack_from(endian + 'HH', buf, p)
                    p += 4
                    if rtype == 0:
                        break
                    val = bytes(buf[p:p + rlen])
                    if rtype == 1 and len(val) > 4:
                        ip = '.'.join(str(x) for x in val[:4])
                        for nm in val[4:].split(b'\x00'):
                            if nm:
                                meta['name_resolution'].append((ip, nm.decode('utf-8', 'replace')))
                    p += rlen + ((4 - rlen % 4) % 4)
            elif block_type == 0x80000001:  # Apple Darwin Process Event Block: pid + process name / UUID
                pid = struct.unpack_from(endian + 'I', buf, body)[0]
                pname = puuid = None
                for code, val in _read_options(buf, body + 4, block_end - 4, endian):
                    if code == 2:
                        pname = _txt(val)
                    elif code == 4 and len(val) == 16:
                        puuid = val.hex()
                idx = sum(1 for p_ in meta['processes'] if p_['section'] == section)
                meta['processes'].append({'section': section, 'index': idx, 'pid': pid, 'name': pname, 'uuid': puuid})
            elif block_type == 0x0a:  # Decryption Secrets Block
                stype, slen = struct.unpack_from(endian + 'II', buf, body)
                meta['secrets'].append({'type': {0x544c534b: 'TLS key log'}.get(stype, f'0x{stype:08x}'), 'bytes': slen})
            elif block_type not in (0x0a0d0d0a, 1, 2, 3, 4, 5, 6):
                meta['unknown_blocks'][block_type] = meta['unknown_blocks'].get(block_type, 0) + 1
        except (struct.error, IndexError):
            LAST_PARSE_WARNINGS.append(f"Damaged pcapng block of type {block_type} ignored.")
        off += total_len
    return (iface_link_types[0] if iface_link_types else LINKTYPE_ETHERNET), packets


def write_pcap(path, frames, link_type=LINKTYPE_ETHERNET):
    """frames: iterable of (ts_sec, ts_usec, data: bytes). Writes classic little-endian pcap."""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, link_type))
        for ts_sec, ts_usec, data in frames:
            f.write(struct.pack('<IIII', int(ts_sec), int(ts_usec), len(data), len(data)))
            f.write(data)


def now_ts():
    t = time.time()
    return int(t), int((t - int(t)) * 1e6)


# ============================================================================
# PART 2 -- shared decoder helpers
# ============================================================================

IP_PROTOS = {1: 'ICMP', 2: 'IGMP', 4: 'IPIP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 47: 'GRE',
             50: 'ESP', 51: 'AH', 58: 'ICMPv6', 89: 'OSPF', 103: 'PIM', 112: 'VRRP', 132: 'SCTP'}
ETHERTYPES = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x8100: 'VLAN', 0x88a8: 'QinQ',
              0x8847: 'MPLS unicast', 0x8848: 'MPLS multicast', 0x88cc: 'LLDP', 0x888e: 'EAPOL',
              0x8863: 'PPPoE Discovery', 0x8864: 'PPPoE Session', 0x0842: 'Wake-on-LAN',
              0x88f7: 'PTP', 0x8906: 'FCoE', 0x88e5: 'MACsec', 0x22f0: 'AVTP'}
IPV6_EXT_HEADERS = {0, 43, 44, 60, 51}  # Hop-by-Hop, Routing, Fragment, DstOpts, AH

OUI_VENDORS = {
    '00:1A:11': 'Google', 'DA:A1:19': 'Google', 'F4:F5:D8': 'Google', '3C:5A:B4': 'Google',
    '00:1C:B3': 'Apple', 'AC:DE:48': 'Apple', 'F0:18:98': 'Apple', 'A4:83:E7': 'Apple',
    '00:1B:63': 'Apple', '3C:15:C2': 'Apple', 'BC:92:6B': 'Apple', '00:03:93': 'Apple', '00:0D:93': 'Apple',
    'B8:27:EB': 'Raspberry Pi Foundation', 'DC:A6:32': 'Raspberry Pi Foundation', 'D8:3A:DD': 'Raspberry Pi Foundation',
    'E4:5F:01': 'Raspberry Pi Trading',
    '00:50:56': 'VMware', '00:0C:29': 'VMware', '00:1C:14': 'VMware', '00:05:69': 'VMware',
    '08:00:27': 'VirtualBox', '52:54:00': 'QEMU/KVM', '00:15:5D': 'Microsoft Hyper-V', '00:16:3E': 'Xen',
    '00:E0:4C': 'Realtek', 'F8:1E:DF': 'Netgear', '00:14:6C': 'Netgear', '00:1F:33': 'Netgear',
    '00:26:F2': 'Cisco', '00:1B:54': 'Cisco', '00:23:04': 'Cisco',
    'FC:EC:DA': 'Ubiquiti', '24:A4:3C': 'Ubiquiti', '78:8A:20': 'Ubiquiti',
    'B4:FB:E4': 'TP-Link', '50:C7:BF': 'TP-Link', 'EC:08:6B': 'TP-Link',
    '3C:D9:2B': 'Hewlett Packard', '9C:8E:99': 'Hewlett Packard',
    'D4:BE:D9': 'Dell', 'B0:83:FE': 'Dell', '00:14:22': 'Dell',
    '01:00:5E': 'IPv4mcast', '33:33:00': 'IPv6mcast', '01:80:C2': 'Spanning-tree/LLDP',
    'FF:FF:FF': 'Broadcast', '01:00:0C': 'Cisco-mcast',
}


def u8(b, o):
    return b[o]


def u16(b, o):
    return (b[o] << 8) | b[o + 1]


def u32(b, o):
    return (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]


def mac_to_str(b, off):
    return ':'.join('%02x' % x for x in b[off:off + 6])


def oui_vendor(mac_str):
    return OUI_VENDORS.get(mac_str.upper()[0:8])


def ipv4_to_str(b, off):
    return '%d.%d.%d.%d' % (b[off], b[off + 1], b[off + 2], b[off + 3])


def ipv6_to_str(b, off):
    parts = [((b[off + i * 2] << 8) | b[off + i * 2 + 1]) for i in range(8)]
    hexparts = ['%x' % p for p in parts]
    best_start, best_len, cur_start, cur_len = -1, 0, -1, 0
    for i, p in enumerate(parts):
        if p == 0:
            if cur_start == -1:
                cur_start = i
            cur_len += 1
            if cur_len > best_len:
                best_len, best_start = cur_len, cur_start
        else:
            cur_start, cur_len = -1, 0
    if best_len > 1:
        return f"{':'.join(hexparts[:best_start])}::{':'.join(hexparts[best_start + best_len:])}"
    return ':'.join(hexparts)


def addr_str(raw):
    return ipv4_to_str(raw, 0) if len(raw) == 4 else ipv6_to_str(raw, 0)


def printable_ascii(b, start, end):
    return ''.join(chr(c) if 32 <= c <= 126 else '.' for c in b[start:end])


def hexs(raw, limit=32):
    raw = bytes(raw)
    s = raw[:limit].hex()
    return s + ('\u2026' if len(raw) > limit else '')


def try_decode_text(b, start, end, max_len=300):
    sl = bytes(b[start:min(end, start + max_len)])
    if not sl:
        return None
    printable = sum(1 for c in sl if 32 <= c <= 126 or c in (9, 10, 13))
    if printable / len(sl) < 0.85:
        return None
    return sl.decode('utf-8', errors='replace')


def format_time(ts_sec, ts_usec):
    try:
        d = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return f'{ts_sec}.{ts_usec:06d}'
    return f"{d.strftime('%Y-%m-%d %H:%M:%S')}.{ts_usec:06d} UTC"


def yesno(v):
    return 'Set' if v else 'Not set'


def bitline(value, total_bits, shift, width):
    """Wireshark-style bit diagram of one field inside a larger value, e.g. '.... ...1 .... '."""
    chars = []
    for bit in range(total_bits - 1, -1, -1):
        chars.append(('1' if (value >> bit) & 1 else '0') if shift <= bit < shift + width else '.')
    return ' '.join(''.join(chars[i:i + 4]) for i in range(0, total_bits, 4))


def checksum_status(valid):
    return 'Unverified' if valid is None else ('Good' if valid else 'Bad')


DSCP_NAMES = {0: 'Default', 8: 'CS1', 10: 'AF11', 12: 'AF12', 14: 'AF13', 16: 'CS2', 18: 'AF21', 20: 'AF22', 22: 'AF23',
              24: 'CS3', 26: 'AF31', 28: 'AF32', 30: 'AF33', 32: 'CS4', 34: 'AF41', 36: 'AF42', 38: 'AF43', 40: 'CS5',
              46: 'EF', 48: 'CS6', 56: 'CS7'}
ECN_NAMES = {0: 'Not ECN-Capable Transport', 1: 'ECN-Capable Transport (1)', 2: 'ECN-Capable Transport (0)',
             3: 'Congestion Experienced'}


def format_local_time(ts_sec, ns):
    try:
        d = datetime.fromtimestamp(ts_sec).astimezone()
    except (OverflowError, OSError, ValueError):
        return f'{ts_sec}.{ns:09d}'
    return f"{d.strftime('%b %d, %Y %H:%M:%S')}.{ns:09d} {d.tzname() or ''}".strip()


def format_utc_time(ts_sec, ns):
    try:
        d = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return f'{ts_sec}.{ns:09d}'
    return f"{d.strftime('%b %d, %Y %H:%M:%S')}.{ns:09d} UTC"


def fmt_ns(delta_ns, digits=9):
    """Format an integer nanosecond delta as seconds with `digits` decimals (no float rounding)."""
    sign = '-' if delta_ns < 0 else ''
    delta_ns = abs(delta_ns)
    sec, ns = divmod(delta_ns, 1000000000)
    return f'{sign}{sec}.{ns:09d}'[:len(sign) + len(str(sec)) + 1 + digits]


def packet_direction(rp):
    """'inbound' / 'outbound' / None, from pcapng epb_flags or the Linux cooked-capture packet type."""
    if rp.flags is not None:
        d = rp.flags & 3
        return {1: 'inbound', 2: 'outbound'}.get(d)
    data = rp.data
    if rp.link_type == 113 and len(data) >= 2:
        t = (data[0] << 8) | data[1]
    elif rp.link_type == 276 and len(data) >= 11:
        t = data[10]
    else:
        return None
    return 'outbound' if t == 4 else ('inbound' if t in (0, 1, 2) else None)


def packet_flags_children(flags):
    names = {0: 'Not specified', 1: 'Unicast', 2: 'Multicast', 3: 'Broadcast', 4: 'Promiscuous'}
    d = flags & 3
    kids = [(f'{bitline(flags, 32, 0, 2)} = Direction', f'{ {0: "Not available", 1: "Inbound", 2: "Outbound"}.get(d, d) } (0x{d:x})'),
            (f'{bitline(flags, 32, 2, 3)} = Reception type', f'{names.get((flags >> 2) & 7, "Reserved")} ({(flags >> 2) & 7})'),
            (f'{bitline(flags, 32, 5, 4)} = FCS length', str((flags >> 5) & 0xf)),
            (f'{bitline(flags, 32, 9, 7)} = Reserved', str((flags >> 9) & 0x7f))]
    for bit, label in ((16, 'CRC error'), (17, 'Packet too long error'), (18, 'Packet too short error'),
                       (19, 'Wrong interframe gap error'), (20, 'Unaligned frame error'),
                       (21, 'Start frame delimiter error'), (22, 'Preamble error'), (23, 'Symbol error')):
        kids.append((f'{bitline(flags, 32, bit, 1)} = {label}', yesno((flags >> bit) & 1)))
    return kids


# ---- Internet checksum (RFC 1071) ------------------------------------------

def checksum16(data):
    if len(data) % 2:
        data = bytes(data) + b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return total & 0xffff


def checksum_is_valid(data):
    return checksum16(data) == 0xffff


def compute_correct_checksum(data_zeroed):
    return (~checksum16(data_zeroed)) & 0xffff


def checksum_field_text(stored, valid, correct):
    base = f'0x{stored:04x}'
    if valid is None:
        return f'{base} [unverified \u2014 not all segment data was captured]'
    if valid:
        return f'{base} [correct]'
    if stored == 0 and correct is not None:
        return f'{base} [not computed \u2014 likely checksum offload]'
    return f'{base} [incorrect, should be 0x{correct:04x}]' if correct is not None else f'{base} [incorrect]'


def ipv4_checksum_check(b, off, ihl):
    header = bytes(b[off:off + ihl])
    stored = struct.unpack_from('>H', header, 10)[0]
    valid = checksum_is_valid(header)
    correct = None
    if not valid:
        z = bytearray(header)
        z[10] = z[11] = 0
        correct = compute_correct_checksum(bytes(z))
    return stored, valid, correct


def _transport_check(pseudo, b, seg_off, seg_len, checksum_field_off, have_full_segment):
    stored = struct.unpack_from('>H', b, checksum_field_off)[0]
    if not have_full_segment:
        return stored, None, None
    segment = bytearray(b[seg_off:seg_off + seg_len])
    valid = checksum_is_valid(pseudo + bytes(segment))
    correct = None
    if not valid:
        rel = checksum_field_off - seg_off
        segment[rel] = segment[rel + 1] = 0
        correct = compute_correct_checksum(pseudo + bytes(segment))
    return stored, valid, correct


def transport_checksum_check_v4(b, ip_off, proto_num, seg_off, seg_len, checksum_field_off, have_full_segment):
    pseudo = bytes(b[ip_off + 12:ip_off + 20]) + b'\x00' + bytes([proto_num]) + struct.pack('>H', seg_len)
    return _transport_check(pseudo, b, seg_off, seg_len, checksum_field_off, have_full_segment)


def transport_checksum_check_v6(b, ip_off, proto_num, seg_off, seg_len, checksum_field_off, have_full_segment):
    pseudo = bytes(b[ip_off + 8:ip_off + 40]) + struct.pack('>I', seg_len) + b'\x00\x00\x00' + bytes([proto_num])
    return _transport_check(pseudo, b, seg_off, seg_len, checksum_field_off, have_full_segment)


# ---- decoded-packet containers ----------------------------------------------

class Flat:
    """Per-packet facts gathered while decoding: used for the packet list,
    the display-filter language, the TCP analyzer and the Expert Info window."""

    def __init__(self):
        self.chain = ['eth']            # protocols in frame, outermost first
        self.protocols = {'eth'}
        self.highest_proto = 'eth'
        self.eth_src = self.eth_dst = None
        self.ip_src = self.ip_dst = None
        self.ip_proto = None
        self.ip_ttl = None
        self.ip_version = None
        self.tcp_sport = self.tcp_dport = None
        self.tcp_flags = []
        self.udp_sport = self.udp_dport = None
        self.icmp_type = self.icmp_code = None
        self.dns_name = None
        self.tls_sni = None
        self.info = ''
        self.app_info = None            # application-layer info for TCP packets (None = show TCP line)
        self.summary_src = self.summary_dst = None
        self.f = {}                     # extra filter fields, e.g. f['stun.type'] = 0x0001
        self.expert = []                # [(severity, group, message)]
        self.payload = (0, 0)           # transport payload byte range
        self.trailer = None
        self.l4 = None
        self.stream = None
        self.tcp = None                 # dict consumed by the TCP analyzer
        self.tcp_layer = None
        self.rtp_candidate = None       # (flow_key, seq) for the post-pass RTP detector
        self.data_layer = None
        self.icmp_echo = None           # (ident, seq, is_request) for request/reply matching
        self.direction = None           # 'inbound' / 'outbound' / None
        self.t_rel = 0.0                # seconds since the first frame (filled by Analysis)
        self.stun_txid = None

    def add(self, name):
        name = name.lower()
        if name not in self.protocols:
            self.protocols.add(name)
        self.chain.append(name)
        self.highest_proto = name

    def warn(self, severity, group, message):
        self.expert.append((severity, group, message))


class DecodedPacket:
    __slots__ = ('number', 'ts_sec', 'ts_usec', 'length', 'layers', 'raw', 'flat', 'summary', 'rawinfo')

    def __init__(self, number, ts_sec, ts_usec, length, layers, raw, flat, summary, rawinfo=None):
        self.number = number
        self.ts_sec = ts_sec
        self.ts_usec = ts_usec
        self.length = length
        self.layers = layers   # list of dict(name, fields=[(label,value[,children])], range=(start,end))
        self.raw = raw
        self.flat = flat
        self.summary = summary
        self.rawinfo = rawinfo   # the RawPacket (interface, direction flags, comments, ns timestamp)


def field_text(label, value):
    """How a detail-tree line is written. Wireshark puts the value of bracketed (derived) fields inside the brackets."""
    if value == '' or value is None:
        return label
    if label.startswith('[') and label.endswith(']'):
        return f'{label[:-1]}: {value}]'
    return f'{label}: {value}'


def sub(label, value, children=None):
    """Build a (possibly nested) detail-tree field."""
    return (label, value, children) if children else (label, value)


def checksum_expert(flat, layer, stored, valid):
    if valid is False and stored != 0:
        if flat.direction == 'outbound':
            flat.warn('chat', 'Checksum', f'{layer}: checksum not yet filled in \u2014 expected for outbound packets captured before the NIC computes it (checksum offload)')
        else:
            flat.warn('warning', 'Checksum', f'{layer}: bad checksum (corruption, or checksum offload if captured on the sending host)')


# ---- TCP options -------------------------------------------------------------

TCP_OPTION_NAMES = {0: 'End of Option List', 1: 'No-Operation', 2: 'Maximum Segment Size',
                    3: 'Window Scale', 4: 'SACK Permitted', 5: 'SACK', 8: 'Timestamps',
                    19: 'MD5 Signature', 28: 'User Timeout', 29: 'TCP-AO', 30: 'Multipath TCP',
                    34: 'TCP Fast Open Cookie'}


def parse_tcp_options(b, start, end):
    """Returns (child_fields, info_tokens) -- tokens look like Wireshark's 'MSS=1460 SACK_PERM WS=128'."""
    fields, tokens = [], []
    p, guard = start, 0
    while p < end and guard < 40:
        guard += 1
        kind = b[p]
        if kind == 0:
            fields.append(('Option', 'End of Option List (EOL)'))
            break
        if kind == 1:
            fields.append(('Option', 'No-Operation (NOP)'))
            p += 1
            continue
        if p + 1 >= end:
            fields.append(('Option', f'Kind {kind} (truncated)'))
            break
        opt_len = b[p + 1]
        if opt_len < 2 or p + opt_len > end:
            fields.append(('Option', f'Kind {kind}, length {opt_len} (malformed)'))
            break
        name = TCP_OPTION_NAMES.get(kind, f'Unknown ({kind})')
        try:
            if kind == 2 and opt_len == 4:
                mss = u16(b, p + 2)
                fields.append(('Maximum Segment Size', f'{mss} bytes'))
                tokens.append(f'MSS={mss}')
            elif kind == 3 and opt_len == 3:
                shift = b[p + 2]
                fields.append(('Window Scale', f'{shift} (multiply by {1 << shift})'))
                tokens.append(f'WS={1 << shift}')
            elif kind == 4 and opt_len == 2:
                fields.append(('SACK Permitted', 'Yes'))
                tokens.append('SACK_PERM')
            elif kind == 5:
                n_edges = (opt_len - 2) // 4
                edges = struct.unpack_from(f'>{n_edges}I', b, p + 2)
                pairs = [f'[{edges[i]}-{edges[i + 1]}]' for i in range(0, len(edges) - 1, 2)]
                fields.append(('SACK', ', '.join(pairs) or '(empty)'))
                for i in range(0, len(edges) - 1, 2):
                    tokens.append(f'SLE={edges[i]} SRE={edges[i + 1]}')
            elif kind == 8 and opt_len == 10:
                tsval, tsecr = struct.unpack_from('>II', b, p + 2)
                fields.append(('Timestamps', f'TSval {tsval}, TSecr {tsecr}'))
                tokens.append(f'TSval={tsval} TSecr={tsecr}')
            else:
                fields.append((name, f'{opt_len} bytes'))
        except Exception:
            fields.append((name, f'{opt_len} bytes (parse error)'))
        p += opt_len
    return fields, tokens


IPV4_OPTION_NAMES = {0: 'End of Option List', 1: 'No Operation', 7: 'Record Route', 68: 'Timestamp',
                     130: 'Security', 131: 'Loose Source Route', 137: 'Strict Source Route', 148: 'Router Alert'}


def parse_ipv4_options(b, start, end):
    fields, p, guard = [], start, 0
    while p < end and guard < 20:
        guard += 1
        kind = b[p]
        if kind == 0:
            fields.append(('Option', 'End of Option List'))
            break
        if kind == 1:
            fields.append(('Option', 'No Operation'))
            p += 1
            continue
        if p + 1 >= end:
            break
        opt_len = b[p + 1]
        if opt_len < 2 or p + opt_len > end:
            break
        fields.append((IPV4_OPTION_NAMES.get(kind, f'Unknown (type {kind})'), f'{opt_len} bytes'))
        p += opt_len
    return fields


# ============================================================================
# PART 3 -- application dissectors, group 1: DNS, text protocols, TLS/DTLS
# ============================================================================

# Cross-packet knowledge (cleared whenever a new capture is loaded).
MEDIA_HINTS = set()         # (ip, port) endpoints known to carry media (learned from STUN / DTLS / SDP)
TURN_ENDPOINTS = set()      # (ip, port) endpoints that have spoken TURN (Allocate / ChannelBind / Send / Data ...)
QUIC_STATE = {}


def reset_dissector_state():
    MEDIA_HINTS.clear()
    TURN_ENDPOINTS.clear()
    QUIC_STATE.clear()
    QUIC_STATE.update({'scid_to_odcid': {}, 'cids': set(), 'crypto': {}, 'sni': {}})


reset_dissector_state()


# ---- DNS / mDNS / LLMNR -------------------------------------------------------

DNS_QTYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 13: 'HINFO', 15: 'MX', 16: 'TXT',
              24: 'SIG', 25: 'KEY', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 39: 'DNAME', 41: 'OPT', 43: 'DS',
              44: 'SSHFP', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 50: 'NSEC3', 52: 'TLSA', 64: 'SVCB',
              65: 'HTTPS', 99: 'SPF', 251: 'IXFR', 252: 'AXFR', 255: 'ANY', 257: 'CAA'}
DNS_CLASSES = {1: 'IN', 3: 'CH', 4: 'HS', 254: 'NONE', 255: 'ANY'}
DNS_RCODES = {0: 'No error', 1: 'Format error', 2: 'Server failure', 3: 'Name error (NXDOMAIN)',
              4: 'Not implemented', 5: 'Refused', 6: 'YXDomain', 7: 'YXRRSet', 8: 'NXRRSet',
              9: 'Not authorized', 10: 'Not in zone'}
DNS_RCODE_SHORT = {1: 'Format error', 2: 'Server failure', 3: 'No such name', 4: 'Not implemented', 5: 'Refused'}
DNS_OPCODES = {0: 'Standard query', 1: 'Inverse query', 2: 'Server status request', 4: 'Notify', 5: 'Dynamic update'}


def parse_dns_name(b, offset, _depth=0):
    """Returns (name, next_offset_after_name). Follows compression pointers safely."""
    if _depth > 10 or offset >= len(b):
        return '', offset + 1
    labels, p, guard = [], offset, 0
    while p < len(b) and guard < 128:
        guard += 1
        length = b[p]
        if length == 0:
            p += 1
            break
        if length & 0xc0 == 0xc0:
            if p + 1 >= len(b):
                break
            pointer = ((length & 0x3f) << 8) | b[p + 1]
            suffix, _ = parse_dns_name(b, pointer, _depth + 1)
            labels.append(suffix)
            return '.'.join(x for x in labels if x), p + 2
        p += 1
        labels.append(printable_ascii(b, p, p + length))
        p += length
    return '.'.join(labels), p


def _parse_dns_rr(b, offset):
    try:
        name, p = parse_dns_name(b, offset)
        if p + 10 > len(b):
            return None, offset + 1
        rtype, rclass, ttl, rdlength = struct.unpack_from('>HHIH', b, p)
        p += 10
        rdata_start, rdata_end = p, p + rdlength
        if rdata_end > len(b):
            return None, offset + 1
        type_name = DNS_QTYPES.get(rtype, f'TYPE{rtype}')
        value = _decode_dns_rdata(b, rtype, rdata_start, rdata_end, rclass)
        cache_flush = bool(rclass & 0x8000) and rtype != 41
        return {'name': name or '<Root>', 'type': type_name, 'class': DNS_CLASSES.get(rclass & 0x7fff, str(rclass & 0x7fff)),
                'ttl': ttl, 'value': value, 'cache_flush': cache_flush}, rdata_end
    except Exception:
        return None, offset + 1


def _decode_dns_rdata(b, rtype, start, end, rclass=0):
    try:
        if rtype == 1 and end - start == 4:
            return ipv4_to_str(b, start)
        if rtype == 28 and end - start == 16:
            return ipv6_to_str(b, start)
        if rtype in (2, 5, 12, 39):
            return parse_dns_name(b, start)[0]
        if rtype == 15 and end - start >= 3:
            return f'{u16(b, start)} {parse_dns_name(b, start + 2)[0]}'
        if rtype in (16, 99):
            parts, p = [], start
            while p < end:
                ln = b[p]
                parts.append(printable_ascii(b, p + 1, min(end, p + 1 + ln)))
                p += 1 + ln
            return ' '.join(parts)
        if rtype == 6:
            mname, p = parse_dns_name(b, start)
            rname, p = parse_dns_name(b, p)
            serial, refresh, retry, expire, minimum = struct.unpack_from('>IIIII', b, p)
            return (f'{mname} {rname} serial={serial} refresh={refresh} retry={retry} '
                    f'expire={expire} minimum={minimum}')
        if rtype == 33 and end - start >= 6:
            prio, weight, port = struct.unpack_from('>HHH', b, start)
            return f'{prio} {weight} {port} {parse_dns_name(b, start + 6)[0]}'
        if rtype in (64, 65) and end - start >= 3:
            prio = u16(b, start)
            target, p = parse_dns_name(b, start + 2)
            return f'{prio} {target or "."}'
        if rtype == 41:
            return f'UDP payload size {rclass}'
        if rtype == 257 and end - start >= 2:
            tag_len = b[start + 1]
            return f'{b[start]} {printable_ascii(b, start + 2, start + 2 + tag_len)} ' \
                   f'{printable_ascii(b, start + 2 + tag_len, end)}'
        return f'{end - start} bytes'
    except Exception:
        return f'{end - start} bytes (parse error)'


def decode_dns(b, mdns=False):
    if len(b) < 12:
        return None
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack_from('>HHHHHH', b, 0)
    if qdcount > 64 or ancount > 512 or nscount > 512 or arcount > 512:
        return None
    off = 12
    questions = []
    for _ in range(qdcount):
        qname, off = parse_dns_name(b, off)
        if off + 4 > len(b):
            break
        qtype, qclass = struct.unpack_from('>HH', b, off)
        off += 4
        questions.append({'name': qname or '<Root>', 'type': DNS_QTYPES.get(qtype, f'TYPE{qtype}'),
                          'class': DNS_CLASSES.get(qclass & 0x7fff, str(qclass & 0x7fff)),
                          'qu': bool(qclass & 0x8000)})
    answers, authorities, additionals = [], [], []
    for lst, count in ((answers, ancount), (authorities, nscount), (additionals, arcount)):
        for _ in range(min(count, 100)):
            if off >= len(b):
                break
            rr, off = _parse_dns_rr(b, off)
            if rr:
                lst.append(rr)
    return {'id': txid, 'flags': flags, 'qr': (flags >> 15) & 1, 'opcode': (flags >> 11) & 0xf,
            'aa': (flags >> 10) & 1, 'tc': (flags >> 9) & 1, 'rd': (flags >> 8) & 1, 'ra': (flags >> 7) & 1,
            'ad': (flags >> 5) & 1, 'cd': (flags >> 4) & 1, 'rcode': flags & 0xf,
            'qdcount': qdcount, 'ancount': ancount, 'nscount': nscount, 'arcount': arcount,
            'questions': questions, 'qname': questions[0]['name'] if questions else '',
            'qtype_name': questions[0]['type'] if questions else '?',
            'answers': answers, 'authorities': authorities, 'additionals': additionals}


def dns_info_line(dns, mdns=False):
    opname = DNS_OPCODES.get(dns['opcode'], f'Opcode {dns["opcode"]}')
    parts = [f'{opname} response 0x{dns["id"]:04x}' if dns['qr'] else f'{opname} 0x{dns["id"]:04x}']
    if dns['qr'] and dns['rcode']:
        parts.append(DNS_RCODE_SHORT.get(dns['rcode'], f'Rcode {dns["rcode"]}'))
    for q in dns['questions']:
        text = f'{q["type"]} {q["name"]}'
        if mdns and not dns['qr']:
            text += f', "{"QU" if q["qu"] else "QM"}" question'
        parts.append(text)
    if dns['qr'] or mdns:
        for rr in dns['answers'] + dns['authorities']:
            parts.append(f'{rr["type"]} {rr["value"]}' if rr['type'] != 'OPT' else 'OPT')
        for rr in dns['additionals']:
            if rr['type'] == 'OPT':
                parts.append('OPT')
    return ' '.join(parts)


def dns_layer(dns, start, end, name='Domain Name System', flat=None, mdns=False):
    kind = 'response' if dns['qr'] else 'query'
    flag_children = [
        ('Response', 'Message is a response' if dns['qr'] else 'Message is a query'),
        ('Opcode', f'{DNS_OPCODES.get(dns["opcode"], dns["opcode"])} ({dns["opcode"]})'),
        ('Authoritative', yesno(dns['aa'])), ('Truncated', yesno(dns['tc'])),
        ('Recursion desired', yesno(dns['rd'])), ('Recursion available', yesno(dns['ra'])),
        ('Authenticated data', yesno(dns['ad'])), ('Checking disabled', yesno(dns['cd'])),
        ('Reply code', f'{DNS_RCODES.get(dns["rcode"], dns["rcode"])} ({dns["rcode"]})'),
    ]
    fields = [('Transaction ID', f'0x{dns["id"]:04x}'),
              sub('Flags', f'0x{dns["flags"]:04x} ({"Standard " if dns["opcode"] == 0 else ""}{kind}'
                            f'{", " + str(DNS_RCODES.get(dns["rcode"], dns["rcode"])) if dns["qr"] and dns["rcode"] else ""})', flag_children),
              ('Questions', str(dns['qdcount'])), ('Answer RRs', str(dns['ancount'])),
              ('Authority RRs', str(dns['nscount'])), ('Additional RRs', str(dns['arcount']))]
    if dns['questions']:
        fields.append(sub('Queries', f'{len(dns["questions"])} question(s)', [
            (f'{q["name"]}', f'type {q["type"]}, class {q["class"]}' + (f', "{"QU" if q["qu"] else "QM"}" question' if mdns else ''))
            for q in dns['questions']]))
    for label, rrs in (('Answers', dns['answers']), ('Authoritative nameservers', dns['authorities']),
                       ('Additional records', dns['additionals'])):
        if rrs:
            fields.append(sub(label, f'{len(rrs)} record(s)', [
                (f'{rr["name"]}: type {rr["type"]}, class {rr["class"]}{", cache flush" if rr["cache_flush"] else ""}',
                 f'{rr["value"]}  (TTL {rr["ttl"]}s)') for rr in rrs]))
    if flat is not None:
        flat.f.update({'dns.id': dns['id'], 'dns.flags.response': bool(dns['qr']),
                       'dns.flags.rcode': dns['rcode'], 'dns.qry.name': dns['qname'],
                       'dns.qry.type': dns['qtype_name'], 'dns.count.answers': dns['ancount'],
                       'dns.resp.name': [a['name'] for a in dns['answers']] or None,
                       'dns.a': [a['value'] for a in dns['answers'] if a['type'] in ('A', 'AAAA')] or None,
                       'dns.flags.truncated': bool(dns['tc'])})
        if dns['qr'] and dns['rcode'] == 3:
            flat.warn('note', 'Response code', 'DNS response: no such name (NXDOMAIN)')
        elif dns['qr'] and dns['rcode'] in (2, 5):
            flat.warn('warning', 'Response code', f'DNS response: {DNS_RCODES[dns["rcode"]]}')
        elif dns['qr'] and dns['rcode']:
            flat.warn('note', 'Response code', f'DNS response: {DNS_RCODES.get(dns["rcode"], dns["rcode"])}')
        if dns['tc']:
            flat.warn('warning', 'Response', 'DNS: message truncated (TC bit set) \u2014 client should retry over TCP')
    return {'name': name, 'fields': fields, 'range': (start, end), 'summary': f' ({kind})'}


def dissect_dns(b, start, end, flat, kind='dns', prefix=0):
    """kind: 'dns' | 'mdns' | 'llmnr'.  prefix: bytes of TCP length framing to skip."""
    dns = decode_dns(bytes(b[start + prefix:end]), mdns=(kind == 'mdns'))
    if not dns:
        return None
    if kind == 'dns' and dns['qdcount'] == 0 and dns['ancount'] == 0:
        return None
    flat.dns_name = dns['qname']
    layer = dns_layer(dns, start, end, {'dns': 'Domain Name System', 'mdns': 'Multicast Domain Name System',
                                         'llmnr': 'Link-local Multicast Name Resolution'}[kind], flat, kind == 'mdns')
    return kind.upper(), dns_info_line(dns, kind == 'mdns'), [layer]


# ---- HTTP / SIP / SDP / SSDP ---------------------------------------------------

HTTP_REQ_RE = re.compile(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|REPORT) (\S+) (HTTP/\d\.\d)')
HTTP_RESP_RE = re.compile(r'^(HTTP/\d\.\d) (\d{3})\s*(.*)')
SIP_REQ_RE = re.compile(r'^(INVITE|ACK|BYE|CANCEL|REGISTER|OPTIONS|SUBSCRIBE|NOTIFY|REFER|MESSAGE|INFO|PRACK|UPDATE|PUBLISH) (\S+) SIP/2\.0')
SIP_RESP_RE = re.compile(r'^SIP/2\.0 (\d{3})\s*(.*)')
SSDP_RE = re.compile(r'^(M-SEARCH|NOTIFY|SUBSCRIBE|UNSUBSCRIBE) (\S+) HTTP/1\.[01]')


def _split_message(text):
    for sep in ('\r\n\r\n', '\n\n'):
        idx = text.find(sep)
        if idx >= 0:
            return text[:idx], text[idx + len(sep):]
    return text, ''


def _parse_headers(head):
    lines = head.replace('\r\n', '\n').split('\n')
    hdrs = []
    for line in lines[1:]:
        if ':' in line and not line.startswith((' ', '\t')):
            k, _, v = line.partition(':')
            hdrs.append((k.strip(), v.strip()))
        elif hdrs and line.startswith((' ', '\t')):
            hdrs[-1] = (hdrs[-1][0], hdrs[-1][1] + ' ' + line.strip())
    return lines[0].rstrip('\r'), hdrs


def _parse_sdp(body, flat, src_ip):
    """Returns detail fields and registers media endpoints as RTP/RTCP hints."""
    fields, conn_ip, media = [], src_ip, []
    for line in body.replace('\r\n', '\n').split('\n'):
        line = line.strip()
        if len(line) < 3 or line[1] != '=':
            continue
        key, val = line[0], line[2:]
        names = {'v': 'Session Description Protocol Version (v)', 'o': 'Owner/Creator, Session Id (o)',
                 's': 'Session Name (s)', 'c': 'Connection Information (c)', 't': 'Time Description (t)',
                 'm': 'Media Description (m)', 'a': 'Media Attribute (a)', 'b': 'Bandwidth (b)'}
        fields.append((names.get(key, key), val))
        if key == 'c':
            parts = val.split()
            if len(parts) >= 3:
                conn_ip = parts[2].split('/')[0]
        elif key == 'm':
            parts = val.split()
            if len(parts) >= 2 and parts[1].split('/')[0].isdigit():
                media.append((conn_ip, int(parts[1].split('/')[0])))
    for ip, port in media:
        MEDIA_HINTS.add((ip, port))
        MEDIA_HINTS.add((ip, port + 1))
    if media:
        flat.f['sdp.media_port'] = [m[1] for m in media]
    return fields


def dissect_text_app(b, start, end, flat, sport, dport, transport):
    """HTTP / SIP / SSDP / SSH banner.  Returns (proto, info, layers) or None."""
    text = try_decode_text(b, start, end, 8000)
    if not text:
        return None
    head, body = _split_message(text)
    first = head.replace('\r\n', '\n').split('\n')[0].rstrip('\r')
    body_off = start + len(head.encode('utf-8', errors='replace')) + (4 if '\r\n\r\n' in text else 2)

    m = HTTP_REQ_RE.match(first)
    if m and transport in ('tcp', 'udp'):
        _, hdrs = _parse_headers(head)
        hd = {k.lower(): v for k, v in hdrs}
        flat.f.update({'http.request': True, 'http.request.method': m.group(1), 'http.request.uri': m.group(2),
                       'http.request.version': m.group(3), 'http.host': hd.get('host'),
                       'http.user_agent': hd.get('user-agent'), 'http.cookie': hd.get('cookie'),
                       'http.content_type': hd.get('content-type')})
        fields = [sub(first + '\\r\\n', '', [('Request Method', m.group(1)), ('Request URI', m.group(2)),
                                                ('Request Version', m.group(3))])]
        fields += [(k, v) for k, v in hdrs]
        if hd.get('host'):
            fields.append(('Full request URI', f'http://{hd["host"]}{m.group(2)}'))
        if m.group(1) in ('POST', 'PUT') and 'authorization' in hd:
            flat.warn('note', 'Security', 'HTTP: request carries an Authorization header in clear text')
        if body:
            fields.append(('File Data', f'{len(body)} bytes'))
        return 'HTTP', first, [{'name': 'Hypertext Transfer Protocol', 'fields': fields, 'range': (start, end)}]

    m = HTTP_RESP_RE.match(first)
    if m:
        _, hdrs = _parse_headers(head)
        hd = {k.lower(): v for k, v in hdrs}
        code = int(m.group(2))
        flat.f.update({'http.response': True, 'http.response.code': code, 'http.response.phrase': m.group(3),
                       'http.content_type': hd.get('content-type'), 'http.server': hd.get('server')})
        fields = [sub(first + '\\r\\n', '', [('Response Version', m.group(1)), ('Status Code', str(code)),
                                                ('Response Phrase', m.group(3))])]
        fields += [(k, v) for k, v in hdrs]
        if body:
            fields.append(('File Data', f'{len(body)} bytes'))
        if code >= 500:
            flat.warn('warning', 'Response code', f'HTTP: server error {code} {m.group(3)}')
        elif code >= 400:
            flat.warn('note', 'Response code', f'HTTP: client error {code} {m.group(3)}')
        info = first + (f'  ({hd["content-type"].split(";")[0]})' if hd.get('content-type') else '')
        return 'HTTP', info, [{'name': 'Hypertext Transfer Protocol', 'fields': fields, 'range': (start, end)}]

    m = SIP_REQ_RE.match(first) or SIP_RESP_RE.match(first)
    if m:
        _, hdrs = _parse_headers(head)
        hd = {k.lower(): v for k, v in hdrs}
        is_req = bool(SIP_REQ_RE.match(first))
        layers = []
        sip_fields = [sub('Request-Line' if is_req else 'Status-Line', first,
                          [('Method', m.group(1)), ('Request-URI', m.group(2))] if is_req
                          else [('Status-Code', m.group(1)), ('Reason', m.group(2))])]
        sip_fields += [(k, v) for k, v in hdrs]
        has_sdp = 'sdp' in hd.get('content-type', '').lower() and bool(body.strip())
        sip_end = body_off if has_sdp else end
        layers.append({'name': 'Session Initiation Protocol', 'fields': sip_fields, 'range': (start, min(sip_end, end))})
        flat.f.update({'sip.method': m.group(1) if is_req else None, 'sip.call_id': hd.get('call-id'),
                       'sip.status_code': None if is_req else int(m.group(1)),
                       'sip.from': hd.get('from'), 'sip.to': hd.get('to')})
        if has_sdp:
            layers.append({'name': 'Session Description Protocol',
                           'fields': _parse_sdp(body, flat, flat.ip_src), 'range': (body_off, end)})
        info = (f'Request: {m.group(1)} {m.group(2)}' if is_req else f'Status: {m.group(1)} {m.group(2)}')
        if has_sdp:
            info += ', with session description'
        return 'SIP', info + ' |', layers

    m = SSDP_RE.match(first)
    if m and (sport == 1900 or dport == 1900 or transport == 'udp'):
        _, hdrs = _parse_headers(head)
        flat.f['ssdp.method'] = m.group(1)
        return 'SSDP', first, [{'name': 'Simple Service Discovery Protocol',
                                'fields': [(first, '')] + [(k, v) for k, v in hdrs], 'range': (start, end)}]
    if first.startswith('SSH-') and transport == 'tcp':
        return 'SSH', first, [{'name': 'SSH Protocol', 'fields': [('Protocol banner', first)], 'range': (start, end)}]
    return None


LINE_PROTOS = {21: 'FTP', 25: 'SMTP', 587: 'SMTP', 110: 'POP', 143: 'IMAP', 23: 'TELNET', 119: 'NNTP'}


def dissect_line_proto(b, start, end, flat, sport, dport):
    name = LINE_PROTOS.get(sport) or LINE_PROTOS.get(dport)
    if not name:
        return None
    text = try_decode_text(b, start, end, 400)
    if not text:
        return None
    first = text.replace('\r\n', '\n').split('\n')[0].strip()
    if not first:
        return None
    from_server = sport in LINE_PROTOS
    prefix = {'FTP': ('Response: ', 'Request: '), 'IMAP': ('Response: ', 'Request: '),
              'SMTP': ('S: ', 'C: '), 'POP': ('S: ', 'C: '), 'NNTP': ('S: ', 'C: '),
              'TELNET': ('Telnet Data ...', 'Telnet Data ...')}[name][0 if from_server else 1]
    info = prefix if name == 'TELNET' else prefix + first
    if re.match(r'^(USER|PASS|LOGIN|AUTH)\b', first, re.I) and not from_server:
        flat.warn('warning', 'Security', f'{name}: credentials or login command sent in clear text')
    return name, info, [{'name': name, 'fields': [('Line', first)], 'range': (start, end)}]


# ---- TLS / DTLS --------------------------------------------------------------

TLS_RECORD_TYPES = {20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data', 24: 'Heartbeat'}
TLS_HANDSHAKE_TYPES = {0: 'Hello Request', 1: 'Client Hello', 2: 'Server Hello', 3: 'Hello Verify Request',
                       4: 'New Session Ticket', 5: 'End of Early Data', 8: 'Encrypted Extensions', 11: 'Certificate',
                       12: 'Server Key Exchange', 13: 'Certificate Request', 14: 'Server Hello Done',
                       15: 'Certificate Verify', 16: 'Client Key Exchange', 20: 'Finished',
                       22: 'Certificate Status', 24: 'Key Update', 254: 'Message Hash'}
TLS_VERSIONS = {0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3',
                0xfeff: 'DTLS 1.0', 0xfefd: 'DTLS 1.2', 0xfefc: 'DTLS 1.3'}
TLS_ALERTS = {0: 'Close Notify', 10: 'Unexpected Message', 20: 'Bad Record MAC', 40: 'Handshake Failure',
              42: 'Bad Certificate', 43: 'Unsupported Certificate', 44: 'Certificate Revoked',
              45: 'Certificate Expired', 46: 'Certificate Unknown', 47: 'Illegal Parameter', 48: 'Unknown CA',
              50: 'Decode Error', 51: 'Decrypt Error', 70: 'Protocol Version', 71: 'Insufficient Security',
              80: 'Internal Error', 86: 'Inappropriate Fallback', 90: 'User Canceled', 109: 'Missing Extension',
              112: 'Unrecognized Name', 116: 'Certificate Required', 120: 'No Application Protocol'}
TLS_CIPHER_SUITES = {
    0x1301: 'TLS_AES_128_GCM_SHA256', 0x1302: 'TLS_AES_256_GCM_SHA384', 0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
    0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    0xc013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 0xc014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    0xc009: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 0xc00a: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
    0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256', 0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
    0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA', 0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
    0x000a: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 0x00ff: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
    0x0005: 'TLS_RSA_WITH_RC4_128_SHA', 0x0004: 'TLS_RSA_WITH_RC4_128_MD5',
    0xc027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 0xc028: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    0x009e: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 0x009f: 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
}
TLS_EXTENSIONS = {0: 'server_name', 1: 'max_fragment_length', 5: 'status_request', 10: 'supported_groups',
                  11: 'ec_point_formats', 13: 'signature_algorithms', 14: 'use_srtp', 15: 'heartbeat',
                  16: 'application_layer_protocol_negotiation', 18: 'signed_certificate_timestamp', 21: 'padding',
                  23: 'extended_master_secret', 27: 'compress_certificate', 28: 'record_size_limit',
                  35: 'session_ticket', 41: 'pre_shared_key', 42: 'early_data', 43: 'supported_versions',
                  44: 'cookie', 45: 'psk_key_exchange_modes', 47: 'certificate_authorities',
                  50: 'signature_algorithms_cert', 51: 'key_share', 0x0017: 'extended_master_secret',
                  0x3374: 'next_protocol_negotiation', 0x4469: 'application_settings', 0xfe0d: 'encrypted_client_hello',
                  0xff01: 'renegotiation_info'}
TLS_GROUPS = {23: 'secp256r1', 24: 'secp384r1', 25: 'secp521r1', 29: 'x25519', 30: 'x448', 256: 'ffdhe2048',
              257: 'ffdhe3072', 4588: 'X25519MLKEM768', 25497: 'X25519Kyber768Draft00'}
SRTP_PROFILES = {1: 'SRTP_AES128_CM_HMAC_SHA1_80', 2: 'SRTP_AES128_CM_HMAC_SHA1_32', 5: 'SRTP_NULL_HMAC_SHA1_80',
                 6: 'SRTP_NULL_HMAC_SHA1_32', 7: 'SRTP_AEAD_AES_128_GCM', 8: 'SRTP_AEAD_AES_256_GCM'}


def is_grease(v):
    return (v & 0x0f0f) == 0x0a0a and (v >> 8) == (v & 0xff)


def cipher_name(c):
    return 'GREASE' if is_grease(c) else TLS_CIPHER_SUITES.get(c, f'0x{c:04x}')


def _der_common_names(der):
    """Very small DER scan: returns every commonName (OID 2.5.4.3) string in order (issuer first, then subject)."""
    out, i = [], 0
    der = bytes(der)
    while True:
        i = der.find(b'\x06\x03\x55\x04\x03', i)
        if i < 0 or i + 7 > len(der):
            break
        tag, ln = der[i + 5], der[i + 6]
        if tag in (0x0c, 0x13, 0x16, 0x1e) and i + 7 + ln <= len(der):
            out.append(der[i + 7:i + 7 + ln].decode('utf-8', errors='replace'))
        i += 5
    return out


def _parse_hello_extensions(b, p, end, is_client):
    """Returns (ext_fields, details) for the extension block starting at p (after the 2-byte total length)."""
    fields, det = [], {'ext_ids': [], 'groups': [], 'ec_formats': []}
    while p + 4 <= end:
        et, el = u16(b, p), u16(b, p + 2)
        p += 4
        det['ext_ids'].append(et)
        nm = 'GREASE' if is_grease(et) else TLS_EXTENSIONS.get(et, f'unknown 0x{et:04x}')
        child = []
        try:
            if et == 0 and is_client and el >= 5:
                nlen = u16(b, p + 3)
                det['sni'] = bytes(b[p + 5:p + 5 + nlen]).decode('utf-8', errors='replace')
                child.append(('Server Name', det['sni']))
            elif et == 16 and el >= 2:
                q, qend, alpn = p + 2, min(end, p + el), []
                while q < qend:
                    alen = b[q]
                    alpn.append(printable_ascii(b, q + 1, q + 1 + alen))
                    q += 1 + alen
                det['alpn'] = alpn
                child.append(('ALPN', ', '.join(alpn)))
            elif et == 10 and el >= 2:
                det['groups'] = [u16(b, q) for q in range(p + 2, min(end, p + 2 + u16(b, p)), 2)]
                child.append(('Supported Groups', ', '.join('GREASE' if is_grease(g) else TLS_GROUPS.get(g, str(g))
                                                            for g in det['groups'])))
            elif et == 11 and el >= 1:
                det['ec_formats'] = list(b[p + 1:p + 1 + b[p]])
            elif et == 43:
                if is_client:
                    vers = [u16(b, q) for q in range(p + 1, min(end, p + 1 + b[p]), 2)]
                    det['supported_versions'] = vers
                    child.append(('Supported Versions', ', '.join('GREASE' if is_grease(v) else TLS_VERSIONS.get(v, hex(v))
                                                                  for v in vers)))
                else:
                    det['selected_version'] = u16(b, p)
                    child.append(('Selected Version', TLS_VERSIONS.get(u16(b, p), hex(u16(b, p)))))
            elif et == 51 and is_client and el >= 2:
                q, qend, g = p + 2, min(end, p + el), []
                while q + 4 <= qend:
                    g.append(TLS_GROUPS.get(u16(b, q), str(u16(b, q))))
                    q += 4 + u16(b, q + 2)
                child.append(('Key Share groups', ', '.join(g)))
            elif et == 51 and not is_client and el >= 2:
                child.append(('Key Share group', TLS_GROUPS.get(u16(b, p), str(u16(b, p)))))
            elif et == 14 and el >= 2:
                prof = [u16(b, q) for q in range(p + 2, min(end, p + 2 + u16(b, p)), 2)]
                det['srtp'] = [SRTP_PROFILES.get(x, str(x)) for x in prof]
                child.append(('SRTP protection profiles', ', '.join(det['srtp'])))
        except (IndexError, struct.error):
            pass
        fields.append(sub(f'Extension: {nm}', f'len={el}', child))
        p += el
    return fields, det


def _parse_hello(b, p, hs_end, is_client, dtls):
    """p = first byte of the ClientHello / ServerHello body. Returns (fields, detail dict)."""
    fields, det = [], {'ext_ids': [], 'groups': [], 'ec_formats': []}
    hs_end = min(hs_end, len(b))
    try:
        ver = u16(b, p)
        det['version'] = TLS_VERSIONS.get(ver, f'0x{ver:04x}')
        fields.append(('Version', det['version']))
        p += 2 + 32
        sl = b[p]
        p += 1 + sl
        if is_client:
            if dtls:
                p += 1 + b[p]
            cs_len = u16(b, p)
            p += 2
            suites = [u16(b, p + 2 * i) for i in range(cs_len // 2)]
            p += cs_len
            comp = b[p]
            p += 1 + comp
            det['suites'] = suites
            fields.append(sub('Cipher Suites', f'{len(suites)} suites', [(cipher_name(c), f'0x{c:04x}') for c in suites]))
        else:
            cipher = u16(b, p)
            det['cipher_suite'] = cipher_name(cipher)
            fields.append(('Cipher Suite', f'{det["cipher_suite"]} (0x{cipher:04x})'))
            p += 3
        if p + 2 <= hs_end:
            ext_len = u16(b, p)
            ext_fields, xd = _parse_hello_extensions(b, p + 2, min(hs_end, p + 2 + ext_len), is_client)
            det.update(xd)
            if ext_fields:
                fields.append(sub('Extensions', f'{len(ext_fields)} extensions', ext_fields))
        if 'selected_version' in det:
            det['version'] = TLS_VERSIONS.get(det['selected_version'], det['version'])
        elif is_client and det.get('supported_versions'):
            real = [v for v in det['supported_versions'] if not is_grease(v)]
            if real:
                det['version'] = TLS_VERSIONS.get(max(real), det['version'])
        if is_client and 'suites' in det:
            ja3 = '{},{},{},{},{}'.format(
                ver,
                '-'.join(str(c) for c in det['suites'] if not is_grease(c)),
                '-'.join(str(e) for e in det['ext_ids'] if not is_grease(e)),
                '-'.join(str(g) for g in det['groups'] if not is_grease(g)),
                '-'.join(str(x) for x in det['ec_formats']))
            det['ja3'] = ja3
            det['ja3_hash'] = hashlib.md5(ja3.encode()).hexdigest()
            fields.append(('JA3 fingerprint', det['ja3_hash']))
            fields.append(('JA3 fullstring', ja3))
    except (IndexError, struct.error):
        pass
    return fields, det


def sniff_tls(b, start, end, dtls=False):
    hdr = 13 if dtls else 5
    if end - start < hdr:
        return False
    ct = b[start]
    if ct not in TLS_RECORD_TYPES:
        return False
    if dtls:
        if b[start + 1] != 0xfe or b[start + 2] not in (0xff, 0xfd, 0xfc):
            return False
        rlen = u16(b, start + 11)
    else:
        if b[start + 1] != 3 or b[start + 2] > 4:
            return False
        rlen = u16(b, start + 3)
    return 0 < rlen <= 16384 + 2048 or (rlen == 0 and dtls)


def dissect_tls(b, start, end, flat, dtls=False):
    """Walks every TLS/DTLS record in the segment. Returns (proto, info, layers) or None."""
    if not sniff_tls(b, start, end, dtls):
        return None
    hdr = 13 if dtls else 5
    hs_hdr = 12 if dtls else 4
    p = start
    labels, layers, guard = [], [], 0
    sni = None
    first_hs_type = None
    saw_ccs = False
    while p + hdr <= end and guard < 12:
        guard += 1
        if not sniff_tls(b, p, end, dtls):
            break
        ct = b[p]
        ver = u16(b, p + 1)
        rlen = u16(b, p + 11) if dtls else u16(b, p + 3)
        rec_end = p + hdr + rlen
        avail_end = min(rec_end, end)
        rec_fields = [('Content Type', f'{TLS_RECORD_TYPES[ct]} ({ct})'),
                      ('Version', TLS_VERSIONS.get(ver, f'0x{ver:04x}')), ('Length', str(rlen))]
        if dtls:
            rec_fields.insert(2, ('Epoch', str(u16(b, p + 3))))
            rec_fields.insert(3, ('Sequence Number', str(int.from_bytes(bytes(b[p + 5:p + 11]), 'big'))))
        flat.f['tls.partial_remaining'] = max(0, rec_end - end)
        if rec_end > end:
            rec_fields.append(('Note', 'Record continues in a later segment/datagram (partial)'))
        encrypted = dtls and u16(b, p + 3) > 0
        label = TLS_RECORD_TYPES[ct]
        if ct == 22 and not encrypted and not saw_ccs:
            q, msg_labels = p + hdr, []
            while q + hs_hdr <= avail_end:
                ht = b[q]
                hl = int.from_bytes(bytes(b[q + 1:q + 4]), 'big')
                if ht not in TLS_HANDSHAKE_TYPES or (ht == 0 and rlen != hs_hdr) or (q == p + hdr and hl + hs_hdr > rlen and not dtls and rec_end <= end):
                    if q == p + hdr:
                        msg_labels.append('Encrypted Handshake Message')
                        rec_fields.append(('Handshake Protocol', 'Encrypted Handshake Message'))
                    break
                hname = TLS_HANDSHAKE_TYPES[ht]
                body = q + hs_hdr
                hs_fields = [('Handshake Type', f'{hname} ({ht})'), ('Length', str(hl))]
                frag_ok = True
                if dtls:
                    frag_off = int.from_bytes(bytes(b[q + 6:q + 9]), 'big')
                    frag_len = int.from_bytes(bytes(b[q + 9:q + 12]), 'big')
                    hs_fields.insert(1, ('Message Sequence', str(u16(b, q + 4))))
                    hs_fields.append(('Fragment Offset / Length', f'{frag_off} / {frag_len}'))
                    frag_ok = frag_off == 0 and frag_len == hl
                    body_end = body + frag_len
                else:
                    body_end = body + hl
                if first_hs_type is None:
                    first_hs_type = ht
                flat.f['tls.handshake.type'] = ht if 'tls.handshake.type' not in flat.f else flat.f['tls.handshake.type']
                if ht in (1, 2) and frag_ok:
                    f2, det = _parse_hello(b, body, min(body_end, avail_end), ht == 1, dtls)
                    hs_fields += f2
                    if ht == 1:
                        sni = det.get('sni') or sni
                        if det.get('sni'):
                            flat.tls_sni = det['sni']
                            flat.f['tls.handshake.extensions_server_name'] = det['sni']
                        if det.get('ja3_hash'):
                            flat.f['tls.handshake.ja3'] = det['ja3_hash']
                        if det.get('version'):
                            flat.f['tls.handshake.version'] = det['version']
                        if det.get('alpn'):
                            flat.f['tls.handshake.extensions_alpn'] = det['alpn']
                        for legacy in ('SSL 3.0', 'TLS 1.0', 'TLS 1.1'):
                            if det.get('supported_versions') is None and det.get('version') == legacy:
                                flat.warn('warning', 'Security', f'TLS Client Hello offers deprecated {legacy}')
                        weak = [cipher_name(c) for c in det.get('suites', []) if 'RC4' in cipher_name(c) or '3DES' in cipher_name(c)]
                        if weak:
                            flat.warn('note', 'Security', 'TLS Client Hello offers weak ciphers: ' + ', '.join(weak[:3]))
                        if det.get('srtp'):
                            flat.f['dtls.use_srtp'] = True
                    else:
                        flat.f['tls.handshake.ciphersuite'] = det.get('cipher_suite')
                        if det.get('version'):
                            flat.f['tls.handshake.version'] = det['version']
                    lbl = hname + (f' (SNI={det["sni"]})' if ht == 1 and det.get('sni') else '')
                    msg_labels.append(lbl)
                elif ht == 11 and body + 3 <= avail_end:
                    try:
                        total = int.from_bytes(bytes(b[body:body + 3]), 'big')
                        r, certs = body + 3, []
                        while r + 3 <= min(body + 3 + total, avail_end):
                            cl = int.from_bytes(bytes(b[r:r + 3]), 'big')
                            certs.append(bytes(b[r + 3:r + 3 + cl]))
                            r += 3 + cl
                        kids = []
                        for i, der in enumerate(certs[:4]):
                            cns = _der_common_names(der)
                            desc = f'{len(der)} bytes'
                            if len(cns) >= 2:
                                desc += f', subject CN={cns[1]}, issuer CN={cns[0]}'
                                if i == 0:
                                    flat.f['tls.cert.subject'] = cns[1]
                                    if cns[0] == cns[1]:
                                        flat.warn('note', 'Security', f'TLS: self-signed certificate ({cns[1]})')
                            kids.append((f'Certificate {i + 1}', desc))
                        hs_fields.append(sub('Certificates', f'{len(certs)} certificate(s)', kids))
                    except Exception:
                        pass
                    msg_labels.append(hname)
                else:
                    msg_labels.append(hname)
                rec_fields.append(sub(f'Handshake Protocol: {hname}', '', hs_fields))
                q = body_end
                if q <= body:
                    break
            label = ', '.join(msg_labels) if msg_labels else label
            labels.extend(msg_labels)
        elif ct == 22:
            labels.append('Encrypted Handshake Message')
            rec_fields.append(('Handshake Protocol', 'Encrypted Handshake Message'))
        elif ct == 21 and avail_end - (p + hdr) >= 2 and not encrypted and rlen == 2:
            lvl, desc = b[p + hdr], b[p + hdr + 1]
            dname = TLS_ALERTS.get(desc, str(desc))
            rec_fields.append(sub('Alert Message', '', [('Level', 'Fatal (2)' if lvl == 2 else 'Warning (1)'),
                                                          ('Description', f'{dname} ({desc})')]))
            labels.append(f'Alert (Level: {"Fatal" if lvl == 2 else "Warning"}, Description: {dname})')
            flat.warn('warning' if lvl == 2 else 'note', 'Alert', f'TLS alert: {dname}')
            flat.f['tls.alert_message.desc'] = desc
        else:
            if ct == 20:
                saw_ccs = True
            elif ct == 23:
                rec_fields.append(('Encrypted Application Data', f'{max(0, avail_end - p - hdr)} bytes'
                                   + ('' if rec_end <= end else ' (partial)')))
            labels.append(label)
        flat.f.setdefault('tls.record.version', TLS_VERSIONS.get(ver, 'TLS'))
        flat.f['tls.record.content_type'] = ct if 'tls.record.content_type' not in flat.f else flat.f['tls.record.content_type']
        layers.append({'name': ('Datagram Transport Layer Security' if dtls else 'Transport Layer Security') +
                               f' \u2014 {label}', 'fields': rec_fields, 'range': (p, avail_end)})
        p = rec_end
    if not layers:
        return None
    seen, uniq = set(), []
    for l in labels:
        if l not in seen or l.startswith('Alert'):
            seen.add(l)
            uniq.append(l)
    proto = 'DTLS' if dtls else 'TLS'
    return proto, ', '.join(uniq), layers


# ============================================================================
# PART 4 -- application dissectors, group 2: STUN/TURN, RTP, RTCP, QUIC, DHCP, NTP
# ============================================================================

WELL_KNOWN_PORTS = {20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain', 67: 'bootps',
                    68: 'bootpc', 80: 'http', 110: 'pop3', 123: 'ntp', 137: 'netbios-ns', 138: 'netbios-dgm',
                    139: 'netbios-ssn', 143: 'imap', 161: 'snmp', 162: 'snmp-trap', 389: 'ldap', 443: 'https',
                    445: 'microsoft-ds', 465: 'smtps', 500: 'isakmp', 514: 'syslog', 587: 'submission',
                    636: 'ldaps', 853: 'domain-s', 993: 'imaps', 995: 'pop3s', 1194: 'openvpn', 1723: 'pptp',
                    1883: 'mqtt', 1900: 'ssdp', 3306: 'mysql', 3389: 'ms-wbt-server', 3478: 'stun',
                    4500: 'ipsec-nat-t', 5060: 'sip', 5061: 'sips', 5222: 'xmpp-client', 5353: 'mdns',
                    5355: 'llmnr', 5432: 'postgresql', 8080: 'http-alt', 8443: 'https-alt', 19302: 'google-stun',
                    51820: 'wireguard'}


def _varint(b, p):
    """QUIC variable-length integer. Returns (value, new_pos)."""
    first = b[p]
    ln = 1 << (first >> 6)
    v = first & 0x3f
    for i in range(1, ln):
        v = (v << 8) | b[p + i]
    return v, p + ln


# ---- STUN / TURN ---------------------------------------------------------------

STUN_COOKIE = 0x2112A442
STUN_METHODS = {1: 'Binding', 2: 'Shared Secret', 3: 'Allocate', 4: 'Refresh', 6: 'Send', 7: 'Data',
                8: 'CreatePermission', 9: 'Channel-Bind', 10: 'Connect', 11: 'ConnectionBind', 12: 'ConnectionAttempt'}
STUN_CLASSES = ['Request', 'Indication', 'Success Response', 'Error Response']
STUN_ATTRS = {0x0001: 'MAPPED-ADDRESS', 0x0003: 'CHANGE-REQUEST', 0x0004: 'SOURCE-ADDRESS', 0x0005: 'CHANGED-ADDRESS',
              0x0006: 'USERNAME', 0x0008: 'MESSAGE-INTEGRITY', 0x0009: 'ERROR-CODE', 0x000A: 'UNKNOWN-ATTRIBUTES',
              0x000C: 'CHANNEL-NUMBER', 0x000D: 'LIFETIME', 0x0012: 'XOR-PEER-ADDRESS', 0x0013: 'DATA',
              0x0014: 'REALM', 0x0015: 'NONCE', 0x0016: 'XOR-RELAYED-ADDRESS', 0x0017: 'REQUESTED-ADDRESS-FAMILY',
              0x0018: 'EVEN-PORT', 0x0019: 'REQUESTED-TRANSPORT', 0x001A: 'DONT-FRAGMENT', 0x001C: 'MESSAGE-INTEGRITY-SHA256',
              0x001D: 'PASSWORD-ALGORITHM', 0x001E: 'USERHASH', 0x0020: 'XOR-MAPPED-ADDRESS', 0x0022: 'RESERVATION-TOKEN',
              0x0024: 'PRIORITY', 0x0025: 'USE-CANDIDATE', 0x0026: 'PADDING', 0x0027: 'RESPONSE-PORT',
              0x802A: 'ICE-CONTROLLING', 0x8029: 'ICE-CONTROLLED', 0x8022: 'SOFTWARE', 0x8023: 'ALTERNATE-SERVER',
              0x8028: 'FINGERPRINT', 0x802B: 'RESPONSE-ORIGIN', 0x802C: 'OTHER-ADDRESS', 0x8000: 'PASSWORD-ALGORITHMS',
              0x8001: 'ALTERNATE-DOMAIN', 0xC057: 'GOOG-NETWORK-INFO', 0xC001: 'GOOG-LAST-ICE-CHECK-RECEIVED',
              0xC002: 'GOOG-MISC-INFO', 0xC003: 'GOOG-OBSOLETE-1', 0xC004: 'GOOG-CONNECTION-ID'}
STUN_ERRORS = {300: 'Try Alternate', 400: 'Bad Request', 401: 'Unauthenticated', 403: 'Forbidden', 420: 'Unknown Attribute',
               437: 'Allocation Mismatch', 438: 'Stale Nonce', 440: 'Address Family not Supported', 441: 'Wrong Credentials',
               442: 'Unsupported Transport Protocol', 443: 'Peer Address Family Mismatch', 446: 'Connection Already Exists',
               447: 'Connection Timeout or Failure', 486: 'Allocation Quota Reached', 487: 'Role Conflict',
               500: 'Server Error', 508: 'Insufficient Capacity'}


def stun_type_name(t):
    cls = ((t >> 7) & 2) | ((t >> 4) & 1)
    method = (t & 0x000f) | ((t & 0x00e0) >> 1) | ((t & 0x3e00) >> 2)
    m = STUN_METHODS.get(method, f'Method 0x{method:03x}')
    return f'{m} {STUN_CLASSES[cls]}', cls, method


def sniff_stun(b, start, end):
    n = end - start
    if n < 20 or b[start] & 0xc0:
        return False
    ln = u16(b, start + 2)
    return u32(b, start + 4) == STUN_COOKIE and ln % 4 == 0 and ln + 20 <= n


def _stun_addr(b, p, ln, xor, txid):
    if ln < 8:
        return None
    fam = b[p + 1]
    port = u16(b, p + 2)
    if fam == 1:
        raw = bytes(b[p + 4:p + 8])
        if xor:
            port ^= 0x2112
            raw = bytes(x ^ y for x, y in zip(raw, struct.pack('>I', STUN_COOKIE)))
        return f'{addr_str(raw)}:{port}'
    if fam == 2 and ln >= 20:
        raw = bytes(b[p + 4:p + 20])
        if xor:
            port ^= 0x2112
            mask = struct.pack('>I', STUN_COOKIE) + bytes(txid)
            raw = bytes(x ^ y for x, y in zip(raw, mask))
        return f'[{addr_str(raw)}]:{port}'
    return None


def dissect_embedded_payload(b, s, e, flat):
    """Payload carried inside TURN (ChannelData or a DATA attribute).
    Returns (proto, info, layers, replaces) or None.  `replaces` is True for RTP/RTCP: Wireshark lets those take over the
    Protocol/Info columns.  Relayed STUN/DTLS are shown as extra detail layers only (the outer TURN message stays in the list)."""
    if e - s < 4:
        return None
    pk = rtcp_check(b, s, e)
    if pk:
        if (e - s) % 4:
            flat.add('rtp')       # claimed by the RTP heuristic first, then handed to RTCP (Wireshark lists both layers)
        info, layer = build_rtcp(b, s, e, pk, flat)
        return 'RTCP', info, [layer], True
    r = rtp_check(b, s, e)
    if r:
        info, layer = build_rtp(b, s, e, r, flat)
        return 'RTP', info, [layer], True
    scratch = Flat()          # keeps the relayed message's fields out of the outer packet's filter fields and statistics
    res = dissect_stun(b, s, e, scratch) or dissect_tls(b, s, e, scratch, dtls=True)
    if res:
        return res[0], res[1], [dict(l, name=l['name'] + ' (relayed)') for l in res[2]], False
    return None


def dissect_turn_channel(b, start, end, flat, sport, dport):
    """TURN ChannelData (RFC 5766 s11.4): 2-byte channel number 0x4000-0x7FFF + 2-byte length + payload.
    Only attempted on endpoints that have spoken TURN (or the standard TURN ports) to avoid mis-reading QUIC."""
    n = end - start
    if n < 4 or not 0x40 <= b[start] <= 0x7f:
        return None
    chan, ln = u16(b, start), u16(b, start + 2)
    if 4 + ln > n or n - 4 - ln > 3:
        return None
    known = (((flat.ip_src, sport) in TURN_ENDPOINTS and (flat.ip_dst, dport) in TURN_ENDPOINTS)
             or sport in (3478, 5349) or dport in (3478, 5349))
    if not known:
        return None
    flat.f.update({'stun.channel': chan, 'stun.length': ln, 'turn.channeldata': True})
    flat.add('stun')
    layer = {'name': 'Session Traversal Utilities for NAT (TURN ChannelData)', 'range': (start, start + 4),
             'fields': [('Channel Number', f'0x{chan:04x}'), ('Length', str(ln))]}
    inner = dissect_embedded_payload(b, start + 4, start + 4 + ln, flat)
    if inner and inner[3]:
        return inner[0], inner[1], [layer] + inner[2]
    flat.f['stun'] = True
    return 'STUN', 'ChannelData TURN Message', [layer] + (inner[2] if inner else [])


def dissect_stun(b, start, end, flat, transport='udp'):
    if not sniff_stun(b, start, end):
        return None
    mtype = u16(b, start)
    mlen = u16(b, start + 2)
    txid = bytes(b[start + 8:start + 20])
    name, cls, method = stun_type_name(mtype)
    msg_end = start + 20 + mlen
    attr_fields, info_parts = [], []
    data_attr = None
    p = start + 20
    while p + 4 <= msg_end:
        at, al = u16(b, p), u16(b, p + 2)
        vp = p + 4
        if vp + al > msg_end:
            attr_fields.append(('Attribute', f'0x{at:04x} truncated'))
            break
        an = STUN_ATTRS.get(at, f'Unknown 0x{at:04x}')
        val = f'{al} bytes'
        detail = []
        try:
            if at in (0x0001, 0x0004, 0x0005, 0x802B, 0x802C, 0x8023):
                a = _stun_addr(b, vp, al, False, txid)
                val = a or val
                if a:
                    detail.append(('Port', a.rsplit(':', 1)[1]))
                    detail.append(('IP', a.rsplit(':', 1)[0].strip('[]')))
                if at == 0x0001 and a:
                    info_parts.append(f'MAPPED-ADDRESS: {a}')
            elif at in (0x0020, 0x0012, 0x0016):
                a = _stun_addr(b, vp, al, True, txid)
                val = a or val
                if a:
                    detail.append(('Port (XOR-d)', a.rsplit(':', 1)[1]))
                    detail.append(('IP (XOR-d)', a.rsplit(':', 1)[0].strip('[]')))
                if a:
                    info_parts.append(f'{an}: {a}')
                    flat.f['stun.att.ipv4-xord'] = a
                    if at == 0x0016:
                        flat.f['stun.att.relayed'] = a
            elif at == 0x0006:
                val = bytes(b[vp:vp + al]).decode('utf-8', errors='replace')
                info_parts.append(f'user: {val}')
                flat.f['stun.att.username'] = val
            elif at == 0x0014:
                val = bytes(b[vp:vp + al]).decode('utf-8', errors='replace')
                info_parts.append(f'realm: {val}')
                flat.f['stun.att.realm'] = val
            elif at == 0x0015:
                val = bytes(b[vp:vp + al]).decode('utf-8', errors='replace')
                info_parts.append('with nonce')
                flat.f['stun.att.nonce'] = val
            elif at == 0x8022:
                val = bytes(b[vp:vp + al]).decode('utf-8', errors='replace')
                flat.f['stun.att.software'] = val
            elif at == 0x0009 and al >= 4:
                code = (b[vp + 2] & 7) * 100 + b[vp + 3]
                reason = bytes(b[vp + 4:vp + al]).decode('utf-8', errors='replace')
                std = STUN_ERRORS.get(code, 'Unknown')
                val = f'{code} {std}' + (f' \u2014 "{reason}"' if reason else '')
                detail += [('Error Class', str(code // 100)), ('Error Code', str(code % 100)),
                           ('Error Reason Phrase', reason)]
                info_parts.append(f'error-code: {code} ({std})' + (f' {reason}' if reason else ''))
                flat.f['stun.att.error'] = code
                flat.warn('note', 'STUN', f'STUN error response: {code} {std}')
            elif at == 0x0024 and al == 4:
                val = str(u32(b, vp))
            elif at in (0x802A, 0x8029) and al == 8:
                val = '0x' + bytes(b[vp:vp + 8]).hex()
                flat.f['stun.att.ice_role'] = 'controlling' if at == 0x802A else 'controlled'
            elif at == 0x0025:
                val = 'present'
                flat.f['stun.att.use_candidate'] = True
            elif at == 0x000D and al == 4:
                val = f'{u32(b, vp)} seconds'
                info_parts.append(f'LIFETIME: {u32(b, vp)}')
            elif at == 0x0019 and al == 4:
                tname = {17: 'UDP', 6: 'TCP'}.get(b[vp], str(b[vp]))
                val = f'{tname} ({b[vp]})'
                info_parts.append(tname)
                flat.f['stun.att.transport'] = tname
            elif at == 0x000C and al >= 2:
                val = f'0x{u16(b, vp):04x}'
                info_parts.append(f'ChannelNumber=0x{u16(b, vp):04x}')
            elif at == 0x0013:
                data_attr = (vp, vp + al)
                val = f'{al} bytes (relayed payload)'
            elif at == 0x0008:
                val = bytes(b[vp:vp + al]).hex()
            elif at == 0x8028 and al == 4:
                crc = zlib.crc32(bytes(b[start:p])) ^ 0x5354554e
                good = crc == u32(b, vp)
                val = f'0x{u32(b, vp):08x} [{"correct" if good else "incorrect, should be 0x%08x" % crc}]'
                if not good:
                    flat.warn('warning', 'STUN', 'STUN FINGERPRINT attribute does not match the message (bad CRC-32)')
            elif at == 0xC057 and al == 4:
                val = f'net-id {u16(b, vp)}, cost {u16(b, vp + 2)}'
        except (IndexError, struct.error):
            pass
        attr_fields.append(sub(f'Attribute: {an}', val, [('Attribute Type', f'{an} (0x{at:04x})'), ('Attribute Length', str(al))] + detail))
        flat.f.setdefault('stun.attributes', []).append(an)
        p = vp + al + ((4 - al % 4) % 4)
    info = name + (' ' + ' '.join(info_parts) if info_parts else '')
    flat.f.update({'stun': True, 'stun.type': mtype, 'stun.method': method, 'stun.class': cls,
                   'stun.length': mlen, 'stun.id': txid.hex(), 'stun.name': name})
    flat.stun_txid = txid
    if flat.l4 == 'udp' and flat.ip_src:
        MEDIA_HINTS.add((flat.ip_src, flat.udp_sport))
        MEDIA_HINTS.add((flat.ip_dst, flat.udp_dport))
        if method in (3, 4, 6, 7, 8, 9):
            TURN_ENDPOINTS.add((flat.ip_src, flat.udp_sport))
            TURN_ENDPOINTS.add((flat.ip_dst, flat.udp_dport))
    fields = [('Message Type', f'0x{mtype:04x} ({name})',) ,
              sub('Message Type details', '', [
                  (f'{bitline(mtype, 16, 7, 1)} / {bitline(mtype, 16, 4, 1)} = Message Class', f'{STUN_CLASSES[cls]} ({cls})'),
                  ('Message Method', f'{STUN_METHODS.get(method, hex(method))} (0x{method:03x})')]),
              ('Message Length', str(mlen)), ('Message Cookie', '0x2112a442'),
              ('Message Transaction ID', txid.hex()),
              sub('Attributes', f'{len(attr_fields)} attribute(s)', attr_fields)]
    stun_layer = {'name': 'Session Traversal Utilities for NAT', 'fields': fields, 'range': (start, start + 20 + mlen)}
    if data_attr and data_attr[1] - data_attr[0] >= 4 and not flat.f.get('_in_data_attr'):
        flat.f['_in_data_attr'] = True
        flat.add('stun')
        try:
            inner = dissect_embedded_payload(b, data_attr[0], data_attr[1], flat)
        finally:
            flat.f.pop('_in_data_attr', None)
        if inner and inner[3]:
            return inner[0], inner[1], [stun_layer] + inner[2]
        if inner:
            return 'STUN', info, [stun_layer] + inner[2]
    return 'STUN', info, [stun_layer]


# ---- RTP / RTCP -----------------------------------------------------------------

RTP_PT_NAMES = {0: 'ITU-T G.711 PCMU', 3: 'GSM 06.10', 4: 'ITU-T G.723', 5: 'DVI4 8000 Hz', 6: 'DVI4 16000 Hz',
                7: 'LPC', 8: 'ITU-T G.711 PCMA', 9: 'ITU-T G.722', 10: '16-bit L16 stereo', 11: '16-bit L16 mono',
                12: 'QCELP', 13: 'CN', 14: 'MPEG-1/2 audio', 15: 'G.728', 16: 'DVI4 11025 Hz', 17: 'DVI4 22050 Hz',
                18: 'ITU-T G.729', 25: 'CelB', 26: 'JPEG', 28: 'nv', 31: 'ITU-T H.261', 32: 'MPEG-1/2 video',
                33: 'MPEG-2 TS', 34: 'ITU-T H.263'}
RTP_VALID_PT = set(RTP_PT_NAMES) | set(range(96, 128))


def rtp_pt_name(pt):
    return RTP_PT_NAMES.get(pt) or (f'DynamicRTP-Type-{pt}' if pt >= 96 else f'Unassigned-{pt}')


def rtp_sane(b, start, end):
    """The structural part of Wireshark's RTP heuristic: version 2 and a header (CSRC list, extension, padding) that fits."""
    n = end - start
    if n < 12 or b[start] >> 6 != 2:
        return False
    hdr = 12 + 4 * (b[start] & 0x0f)
    if hdr > n:
        return False
    if b[start] & 0x10:
        if hdr + 4 > n:
            return False
        hdr += 4 + u16(b, start + hdr + 2) * 4
        if hdr > n:
            return False
    if b[start] & 0x20:
        pad = b[end - 1]
        if pad == 0 or pad > n - hdr:
            return False
    return True


def rtp_check(b, start, end):
    """Structural sanity check. Returns a dict describing the header, or None."""
    n = end - start
    if n < 12:
        return None
    b0, b1 = b[start], b[start + 1]
    if b0 >> 6 != 2 or 192 <= b1 <= 223:
        return None
    pt = b1 & 0x7f
    if pt not in RTP_VALID_PT or not rtp_sane(b, start, end):
        return None
    cc = b0 & 0x0f
    hdr = 12 + 4 * cc
    ext = None
    if b0 & 0x10:
        ext_len = u16(b, start + hdr + 2) * 4
        ext = (u16(b, start + hdr), ext_len)
        hdr += 4 + ext_len
    pad = b[end - 1] if b0 & 0x20 else 0
    return {'pt': pt, 'marker': bool(b1 & 0x80), 'seq': u16(b, start + 2), 'ts': u32(b, start + 4),
            'ssrc': u32(b, start + 8), 'cc': cc, 'ext': ext, 'hdr': hdr, 'pad': pad,
            'padding': bool(b0 & 0x20), 'extension': bool(b0 & 0x10)}


def build_rtp(b, start, end, r, flat):
    csrcs = [f'0x{u32(b, start + 12 + 4 * i):08x}' for i in range(r['cc'])]
    fields = [('Version', '2 (RFC 1889 Version)'), ('Padding', yesno(r['padding'])),
              ('Extension', yesno(r['extension'])), ('Contributing source identifiers count', str(r['cc'])),
              ('Marker', yesno(r['marker'])), ('Payload type', f'{rtp_pt_name(r["pt"])} ({r["pt"]})'),
              ('Sequence number', str(r['seq'])), ('Timestamp', str(r['ts'])),
              ('Synchronization Source identifier', f'0x{r["ssrc"]:08x} ({r["ssrc"]})')]
    if csrcs:
        fields.append(('Contributing source identifiers', ', '.join(csrcs)))
    if r['ext']:
        prof, ln = r['ext']
        fields.append(('Header extension', f'profile 0x{prof:04x}' + (' (one-byte header, RFC 5285)' if prof == 0xbede else '') + f', {ln} bytes'))
    plen = end - start - r['hdr'] - r['pad']
    fields.append(('Payload', f'{max(0, plen)} bytes' + (f' (+{r["pad"]} padding)' if r['pad'] else '')))
    flat.f.update({'rtp': True, 'rtp.version': 2, 'rtp.ssrc': r['ssrc'], 'rtp.p_type': r['pt'], 'rtp.seq': r['seq'],
                   'rtp.timestamp': r['ts'], 'rtp.marker': r['marker']})
    info = f'PT={rtp_pt_name(r["pt"])}, SSRC=0x{r["ssrc"]:X}, Seq={r["seq"]}, Time={r["ts"]}' + (', Mark' if r['marker'] else '')
    return info, {'name': 'Real-Time Transport Protocol', 'fields': fields, 'range': (start, end)}


RTCP_TYPES = {192: 'Full INTRA-frame Request', 193: 'Negative ACK', 195: 'Extended IJ', 200: 'Sender Report',
              201: 'Receiver Report', 202: 'Source description', 203: 'Goodbye', 204: 'Application defined',
              205: 'Generic RTP Feedback', 206: 'Payload-specific Feedback', 207: 'Extended report (RFC 3611)',
              208: 'AVB RTCP packet', 209: 'Receiver Summary Information', 210: 'Port Mapping', 211: 'IDMS Settings'}
RTPFB_FMT = {1: 'NACK', 3: 'TMMBR', 4: 'TMMBN', 5: 'SR-REQ', 15: 'Transport-wide CC'}
PSFB_FMT = {1: 'PLI', 2: 'SLI', 3: 'RPSI', 4: 'FIR', 5: 'TSTR', 6: 'TSTN', 7: 'VBCM', 15: 'AFB (e.g. REMB)'}
SDES_ITEMS = {1: 'CNAME', 2: 'NAME', 3: 'EMAIL', 4: 'PHONE', 5: 'LOC', 6: 'TOOL', 7: 'NOTE', 8: 'PRIV'}


def rtcp_check(b, start, end):
    """Validates an RTCP compound packet. SRTCP (encrypted RTCP) is accepted too: only the first 8 bytes are readable and a
    4-byte index plus an authentication tag trail the packet."""
    if end - start < 8 or b[start] >> 6 != 2:
        return None
    p, pkts = start, []
    while p + 4 <= end:
        pt = b[p + 1]
        ln = (u16(b, p + 2) + 1) * 4
        if b[p] >> 6 != 2 or not 192 <= pt <= 223 or p + ln > end:
            break
        pkts.append((p, pt, ln))
        p += ln
    rem = end - p
    if not pkts or pkts[0][1] not in (200, 201, 202, 203, 204, 205, 206, 207):
        return None
    if rem and not 4 <= rem <= 24:
        return None
    if (end - start) % 4:
        # Wireshark's RTCP heuristic wants a multiple of 4 bytes. Packets that are not (SRTCP with a 10-byte tag) only reach the
        # RTCP dissector through the RTP heuristic, which passes RTCP types 205-207 on when the RTP header would fit.
        if pkts[0][1] not in (205, 206, 207) or not rtp_sane(b, start, end):
            return None
    return pkts


def _ntp_time_str(msw, lsw):
    if msw < 2208988800:
        return f'{msw}.{lsw:010d}'
    try:
        d = datetime.fromtimestamp(msw - 2208988800, tz=timezone.utc)
        return d.strftime('%b %d, %Y %H:%M:%S') + f'.{int(lsw / 4294967296 * 1e9):09d} UTC'
    except (OverflowError, OSError, ValueError):
        return f'{msw}.{lsw}'


def build_rtcp(b, start, end, pkts, flat):
    fields, labels, ssrcs = [], [], []
    last_end = pkts[-1][0] + pkts[-1][2]
    encrypted = last_end < end            # SRTCP: index + auth tag follow the packet, the body is encrypted
    for (p, pt, ln) in pkts:
        b0 = b[p]
        rc = b0 & 0x1f
        name = RTCP_TYPES.get(pt, f'Type {pt}')
        pend = p + ln
        kids = [('Version', '2'), ('Padding', yesno(b0 & 0x20)),
                ('Reception report count' if pt in (200, 201) else 'Count / format', str(rc)),
                ('Packet type', f'{name} ({pt})'), ('Length', f'{u16(b, p + 2)} (in 32-bit words minus one)')]
        lbl = name
        if encrypted:
            # SRTCP: only the first 8 bytes are readable. Wireshark parses the encrypted body anyway: a bare PLI survives,
            # feedback with a control-information part and XR blocks run past the data and are reported as malformed.
            malformed = False
            if pt == 206 and rc == 1:
                lbl = f'{name}   {PSFB_FMT[1]}  '
            elif pt in (205, 206, 207):
                lbl = f'{name}   [Malformed Packet]'
                malformed = True
            if malformed:
                flat.warn('warning', 'Malformed', 'RTCP: the body is encrypted (SRTCP) and cannot be decoded \u2014 Wireshark reports this as "Malformed Packet"')
            if ln >= 8:
                ssrcs.append(u32(b, p + 4))
                kids.append(('Sender SSRC', f'0x{u32(b, p + 4):08x}'))
            kids.append(('Payload', f'{ln - 8} bytes, encrypted (SRTCP)'))
            labels.append(lbl)
            fields.append(sub(lbl, f'{ln} bytes', kids))
            continue
        try:
            if pt in (200, 201):
                sender = u32(b, p + 4)
                ssrcs.append(sender)
                kids.append(('Sender SSRC', f'0x{sender:08x}'))
                q = p + 8
                if pt == 200:
                    msw, lsw, rts, pc, oc = struct.unpack_from('>IIIII', b, q)
                    kids += [('NTP timestamp', _ntp_time_str(msw, lsw)), ('RTP timestamp', str(rts)),
                             ('Sender\'s packet count', str(pc)), ('Sender\'s octet count', str(oc))]
                    q += 20
                for i in range(rc):
                    if q + 24 > pend:
                        break
                    ssrc, fl = u32(b, q), b[q + 4]
                    cum = int.from_bytes(bytes(b[q + 5:q + 8]), 'big', signed=False)
                    if cum & 0x800000:
                        cum -= 0x1000000
                    ext, jit, lsr, dlsr = struct.unpack_from('>IIII', b, q + 8)
                    pct = fl * 100.0 / 256
                    kids.append(sub(f'Source {i + 1}', f'SSRC 0x{ssrc:08x}', [
                        ('Fraction lost', f'{fl}/256 ({pct:.1f}%)'), ('Cumulative packets lost', str(cum)),
                        ('Extended highest sequence number', str(ext)), ('Interarrival jitter', str(jit)),
                        ('Last SR timestamp', str(lsr)), ('Delay since last SR', str(dlsr))]))
                    if pct >= 10:
                        flat.warn('warning', 'RTCP', f'RTCP: {pct:.0f}% packet loss reported for SSRC 0x{ssrc:08x}')
                    flat.f['rtcp.fraction_lost'] = fl
                    q += 24
            elif pt == 202:
                q, chunks = p + 4, []
                for _ in range(rc):
                    if q + 4 > pend:
                        break
                    ssrc = u32(b, q)
                    ssrcs.append(ssrc)
                    q += 4
                    items = []
                    while q < pend and b[q] != 0:
                        it, il = b[q], b[q + 1]
                        items.append((SDES_ITEMS.get(it, f'Item {it}'), printable_ascii(b, q + 2, q + 2 + il)))
                        q += 2 + il
                    q += 1
                    q += (4 - ((q - p) % 4)) % 4
                    chunks.append(sub(f'Chunk SSRC 0x{ssrc:08x}', '', items))
                kids += chunks
            elif pt == 203:
                q = p + 4
                for _ in range(rc):
                    if q + 4 <= pend:
                        ssrcs.append(u32(b, q))
                        kids.append(('Identifier', f'0x{u32(b, q):08x}'))
                        q += 4
                if q < pend:
                    rl = b[q]
                    kids.append(('Reason for leaving', printable_ascii(b, q + 1, q + 1 + rl)))
            elif pt == 204:
                kids += [('SSRC/CSRC', f'0x{u32(b, p + 4):08x}'), ('Name', printable_ascii(b, p + 8, p + 12)),
                         ('Application specific data', f'{max(0, pend - p - 12)} bytes')]
            elif pt in (205, 206):
                fmt_name = (RTPFB_FMT if pt == 205 else PSFB_FMT).get(rc, f'FMT {rc}')
                lbl = f'{name}   {fmt_name}  '
                kids += [('Message type', f'{fmt_name} ({rc})'), ('Sender SSRC', f'0x{u32(b, p + 4):08x}'),
                         ('Media source SSRC', f'0x{u32(b, p + 8):08x}'),
                         ('Feedback control information', f'{max(0, pend - p - 12)} bytes')]
                if pt == 206 and rc == 15 and bytes(b[p + 12:p + 16]) == b'REMB' and p + 20 <= pend:
                    exp = b[p + 17] >> 2
                    mant = ((b[p + 17] & 3) << 16) | u16(b, p + 18)
                    kids.append(('REMB bitrate estimate', f'{(mant << exp) / 1000:.0f} kbps'))
                    lbl = f'{name}   REMB  '
                ssrcs.append(u32(b, p + 4))
            elif pt == 207:
                kids.append(('Sender SSRC', f'0x{u32(b, p + 4):08x}'))
                ssrcs.append(u32(b, p + 4))
        except (IndexError, struct.error):
            kids.append(('Note', 'packet body truncated/malformed'))
        labels.append(lbl)
        fields.append(sub(lbl, f'{ln} bytes', kids))
    if encrypted:
        fields.append(('SRTCP trailer (E-flag + index + authentication tag)', f'{end - last_end} bytes'))
        flat.f['rtcp.srtcp'] = True
    flat.f.update({'rtcp': True, 'rtcp.pt': [pt for _, pt, _ in pkts], 'rtcp.ssrc': ssrcs or None})
    return '   '.join(labels), {'name': 'Real-time Transport Control Protocol', 'fields': fields, 'range': (start, end)}


# ---- QUIC -------------------------------------------------------------------------

QUIC_SALTS = {
    'v1': bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a'),
    'v2': bytes.fromhex('0dede3def700a6db819381be6e269dcbf9bd2ed9'),
    'd29': bytes.fromhex('afbfec289993d24c9e9786f19c6111e04390a899'),
    'd23': bytes.fromhex('c3eef712c72ebb5a11a7d2432bb46365bef9f502'),
}
QUIC_LONG_TYPES_V1 = {0: 'Initial', 1: '0-RTT', 2: 'Handshake', 3: 'Retry'}
QUIC_LONG_TYPES_V2 = {1: 'Initial', 2: '0-RTT', 3: 'Handshake', 0: 'Retry'}


def quic_version_ok(v):
    return (v in (0, 1, 0x6b3343cf) or (v >> 8) == 0xff0000 or (v & 0x0f0f0f0f) == 0x0a0a0a0a
            or (v >> 8) == 0xfaceb0)


def quic_version_name(v):
    if v == 0:
        return 'Version Negotiation'
    if v == 1:
        return 'QUIC version 1'
    if v == 0x6b3343cf:
        return 'QUIC version 2'
    if (v >> 8) == 0xff0000:
        return f'draft-{v & 0xff}'
    if (v >> 8) == 0xfaceb0:
        return f'mvfst {v & 0xff}'
    if (v & 0x0f0f0f0f) == 0x0a0a0a0a:
        return 'Reserved (GREASE)'
    return f'0x{v:08x}'


def _hkdf_expand_label(secret, label, length):
    full = b'tls13 ' + label
    info = struct.pack('>H', length) + bytes([len(full)]) + full + b'\x00'
    return hmac.new(secret, info + b'\x01', hashlib.sha256).digest()[:length]


def quic_initial_keys(version, dcid, client):
    if version == 0x6b3343cf:
        salt, labels = QUIC_SALTS['v2'], (b'quicv2 key', b'quicv2 iv', b'quicv2 hp')
    else:
        labels = (b'quic key', b'quic iv', b'quic hp')
        if (version >> 8) == 0xff0000 and version < 0xff000021:
            salt = QUIC_SALTS['d29'] if version >= 0xff00001d else QUIC_SALTS['d23']
        else:
            salt = QUIC_SALTS['v1']
    initial = hmac.new(salt, bytes(dcid), hashlib.sha256).digest()
    secret = _hkdf_expand_label(initial, b'client in' if client else b'server in', 32)
    return (_hkdf_expand_label(secret, labels[0], 16), _hkdf_expand_label(secret, labels[1], 12),
            _hkdf_expand_label(secret, labels[2], 16))


def quic_crypto_available():
    try:
        import cryptography.hazmat.primitives.ciphers.aead  # noqa: F401
        return True
    except Exception:
        return False


def quic_decrypt_initial(pkt, pn_off, length, version, key_dcid, client):
    """pkt: bytes of the whole QUIC packet. Returns (plaintext, pn, pn_len) or None."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except Exception:
        return None
    try:
        key, iv, hp = quic_initial_keys(version, key_dcid, client)
        if len(pkt) < pn_off + 20:
            return None
        enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
        mask = enc.update(bytes(pkt[pn_off + 4:pn_off + 20])) + enc.finalize()
        first = pkt[0] ^ (mask[0] & 0x0f)
        pn_len = (first & 3) + 1
        pn_bytes = bytes(x ^ y for x, y in zip(pkt[pn_off:pn_off + pn_len], mask[1:1 + pn_len]))
        pn = int.from_bytes(pn_bytes, 'big')
        header = bytes([first]) + bytes(pkt[1:pn_off]) + pn_bytes
        nonce = bytes(x ^ y for x, y in zip(iv, pn.to_bytes(12, 'big')))
        plain = AESGCM(key).decrypt(nonce, bytes(pkt[pn_off + pn_len:pn_off + length]), header)
        return plain, pn, pn_len
    except Exception:
        return None


def _quic_frames(plain, state_key, direction):
    """Parse the frames of a decrypted Initial/Handshake payload.
    Returns (frame_fields, frame_names, extra) where extra carries TLS hello details."""
    fields, names, extra = [], [], {}
    p, n = 0, len(plain)
    pad = 0
    try:
        while p < n:
            t = plain[p]
            if t == 0:
                pad += 1
                p += 1
                continue
            if pad:
                fields.append(('PADDING', f'{pad} bytes'))
                if not names or names[-1] != 'PADDING':
                    names.append('PADDING')
                pad = 0
            if t == 1:
                fields.append(('PING', ''))
                names.append('PING')
                p += 1
            elif t in (2, 3):
                p += 1
                largest, p = _varint(plain, p)
                delay, p = _varint(plain, p)
                cnt, p = _varint(plain, p)
                first_rng, p = _varint(plain, p)
                for _ in range(min(cnt, 64)):
                    _g, p = _varint(plain, p)
                    _l, p = _varint(plain, p)
                if t == 3:
                    for _ in range(3):
                        _e, p = _varint(plain, p)
                fields.append(('ACK', f'Largest Acknowledged: {largest}, First ACK Range: {first_rng}'))
                names.append('ACK')
            elif t == 6:
                p += 1
                off, p = _varint(plain, p)
                ln, p = _varint(plain, p)
                data = bytes(plain[p:p + ln])
                p += ln
                kids = [('Offset', str(off)), ('Length', str(ln))]
                cstate = QUIC_STATE['crypto'].setdefault((state_key, direction), {})
                cstate[off] = data
                buf, pos = b'', 0
                while pos in cstate:
                    buf += cstate[pos]
                    pos = len(buf)
                label = 'CRYPTO'
                if len(buf) >= 4 and buf[0] in (1, 2):
                    hl = int.from_bytes(buf[1:4], 'big')
                    if len(buf) >= 4 + hl:
                        f2, det = _parse_hello(buf, 4, 4 + hl, buf[0] == 1, False)
                        kids.append(sub('TLS ' + TLS_HANDSHAKE_TYPES[buf[0]], '', f2))
                        extra.update(det)
                        extra['hello'] = TLS_HANDSHAKE_TYPES[buf[0]]
                        label = 'CRYPTO'
                    else:
                        kids.append(('Reassembly', f'have {len(buf)} of {4 + hl} handshake bytes \u2014 waiting for more CRYPTO frames'))
                fields.append(sub('CRYPTO', f'offset {off}, length {ln}', kids))
                names.append(label)
            elif t == 7:
                p += 1
                ln, p = _varint(plain, p)
                p += ln
                fields.append(('NEW_TOKEN', f'{ln} bytes'))
                names.append('NEW_TOKEN')
            elif t in (0x1c, 0x1d):
                p += 1
                code, p = _varint(plain, p)
                if t == 0x1c:
                    _ft, p = _varint(plain, p)
                rl, p = _varint(plain, p)
                reason = bytes(plain[p:p + rl]).decode('utf-8', errors='replace')
                p += rl
                fields.append(('CONNECTION_CLOSE', f'error code 0x{code:x}' + (f', reason "{reason}"' if reason else '')))
                names.append(f'CONNECTION_CLOSE (error 0x{code:x})')
                extra['close'] = code
            else:
                fields.append(('Unparsed frame', f'type 0x{t:02x}, {n - p} bytes'))
                break
        if pad:
            fields.append(('PADDING', f'{pad} bytes'))
            if not names or names[-1] != 'PADDING':
                names.append('PADDING')
    except (IndexError, struct.error):
        fields.append(('Note', 'frame parsing stopped (truncated)'))
    return fields, names, extra


def sniff_quic(b, start, end, sport, dport):
    n = end - start
    if n < 6:
        return False
    b0 = b[start]
    if b0 & 0x80:
        v = u32(b, start + 1)
        if not quic_version_ok(v):
            return False
        dl = b[start + 5]
        if dl > 20 and v != 0:
            return False
        if v != 0 and not (b0 & 0x40):
            return False
        return n >= 7 + dl
    if not (b0 & 0x40):
        return False
    cids = QUIC_STATE['cids']
    for c in cids:
        if n > 1 + len(c) and bytes(b[start + 1:start + 1 + len(c)]) == c:
            return True
    return (443 in (sport, dport)) and n >= 22


def dissect_quic(b, start, end, flat, sport, dport):
    if not sniff_quic(b, start, end, sport, dport):
        return None
    st = QUIC_STATE
    p = start
    layers, infos, guard = [], [], 0
    sni = None
    while p < end and guard < 6:
        guard += 1
        b0 = b[p]
        if b0 & 0x80:
            if end - p < 7:
                break
            ver = u32(b, p + 1)
            if not quic_version_ok(ver):
                break
            q = p + 5
            dl = b[q]
            dcid = bytes(b[q + 1:q + 1 + dl])
            q += 1 + dl
            sl = b[q]
            scid = bytes(b[q + 1:q + 1 + sl])
            q += 1 + sl
            fields = [('Header Form', 'Long Header (1)'), ('Version', f'0x{ver:08x} ({quic_version_name(ver)})'),
                      ('Destination Connection ID', f'{dcid.hex()} (len {dl})'),
                      ('Source Connection ID', f'{scid.hex()} (len {sl})')]
            st['cids'].add(dcid)
            st['cids'].add(scid)
            flat.f.update({'quic': True, 'quic.version': ver, 'quic.dcid': dcid.hex(), 'quic.scid': scid.hex(),
                           'quic.header_form': 1})
            if ver == 0:
                vers = [f'0x{u32(b, r):08x}' for r in range(q, end - 3, 4)]
                fields.append(('Supported Versions', ', '.join(vers)))
                infos.append(f'Version Negotiation, DCID={dcid.hex()}, SCID={scid.hex()}')
                layers.append({'name': 'QUIC IETF \u2014 Version Negotiation', 'fields': fields, 'range': (p, end)})
                p = end
                break
            ptypes = QUIC_LONG_TYPES_V2 if ver == 0x6b3343cf else QUIC_LONG_TYPES_V1
            ptype = ptypes.get((b0 >> 4) & 3, '?')
            flat.f['quic.long.packet_type'] = (b0 >> 4) & 3
            fields.insert(1, ('Packet Type', f'{ptype} ({(b0 >> 4) & 3})'))
            head = f'{ptype}, DCID={dcid.hex()}, SCID={scid.hex()}'
            if ptype == 'Retry':
                fields.append(('Retry Token + Integrity Tag', f'{end - q} bytes'))
                infos.append(head)
                layers.append({'name': 'QUIC IETF \u2014 Retry', 'fields': fields, 'range': (p, end)})
                p = end
                break
            try:
                if ptype == 'Initial':
                    tl, q = _varint(b, q)
                    fields.append(('Token Length', str(tl)))
                    q += tl
                length, q = _varint(b, q)
            except (IndexError, struct.error):
                break
            pn_off = q
            pkt_end = min(end, pn_off + length)
            fields.append(('Length', str(length)))
            pktbytes = bytes(b[p:pkt_end])
            frame_names, frame_fields, dec = [], [], None
            if ptype == 'Initial' and quic_crypto_available():
                rel_pn = pn_off - p
                dec = quic_decrypt_initial(pktbytes, rel_pn, pkt_end - pn_off, ver, dcid, True)
                direction = 'c'
                odcid = dcid
                if dec is None:
                    cands = []
                    if dcid in st['scid_to_odcid']:
                        cands.append(st['scid_to_odcid'][dcid])
                    cands += [x for x in reversed(list(st['scid_to_odcid'].values())[-16:]) if x not in cands]
                    for cand in cands:
                        dec = quic_decrypt_initial(pktbytes, rel_pn, pkt_end - pn_off, ver, cand, False)
                        if dec:
                            direction, odcid = 's', cand
                            break
                else:
                    st['scid_to_odcid'][scid] = dcid
                if dec:
                    plain, pn, pn_len = dec
                    frame_fields, frame_names, extra = _quic_frames(plain, odcid.hex(), direction)
                    fields.append(('Packet Number', f'{pn} (protection removed)'))
                    fields.append(('Decryption', f'Initial secrets derived from DCID {odcid.hex()} \u2014 payload decrypted'))
                    head += f', PKN: {pn}'
                    if extra.get('sni'):
                        sni = extra['sni']
                        flat.tls_sni = sni
                        flat.f['tls.handshake.extensions_server_name'] = sni
                        flat.f['quic.sni'] = sni
                    if extra.get('ja3_hash'):
                        flat.f['tls.handshake.ja3'] = extra['ja3_hash']
                    if extra.get('alpn'):
                        flat.f['tls.handshake.extensions_alpn'] = extra['alpn']
                    if extra.get('hello') == 'Client Hello':
                        frame_names = [f'CRYPTO (Client Hello{" SNI=" + extra["sni"] if extra.get("sni") else ""})' if x == 'CRYPTO' else x for x in frame_names]
                    elif extra.get('hello') == 'Server Hello':
                        frame_names = ['CRYPTO (Server Hello)' if x == 'CRYPTO' else x for x in frame_names]
                    if extra.get('close'):
                        flat.warn('warning', 'QUIC', f'QUIC connection closed with error 0x{extra["close"]:x}')
                else:
                    fields.append(('Payload', f'{pkt_end - pn_off} bytes, could not be decrypted'
                                   + ('' if quic_crypto_available() else ' (install `cryptography` to decode Initial packets)')))
            else:
                fields.append(('Protected Payload', f'{pkt_end - pn_off} bytes'
                               + ('' if quic_crypto_available() or ptype != 'Initial' else ' (install `cryptography` to decode Initial packets)')))
            fields += frame_fields
            info = head + (', ' + ', '.join(frame_names) if frame_names else '')
            infos.append(info)
            layers.append({'name': f'QUIC IETF \u2014 {ptype}', 'fields': fields, 'range': (p, pkt_end)})
            p = pkt_end
        else:
            n = end - p
            dcid = None
            for c in sorted(st['cids'], key=len, reverse=True):
                if n > 1 + len(c) and bytes(b[p + 1:p + 1 + len(c)]) == c:
                    dcid = c
                    break
            if dcid is None:
                lens = [len(c) for c in st['cids']]
                ln = max(set(lens), key=lens.count) if lens else 8
                dcid = bytes(b[p + 1:p + 1 + ln])
            kp = (b[p] >> 2) & 1
            fields = [('Header Form', 'Short Header (0)'), ('Fixed Bit', 'Set'), ('Spin Bit', yesno(b[p] & 0x20)),
                      ('Key Phase Bit', str(kp)), ('Destination Connection ID', dcid.hex()),
                      ('Protected Payload', f'{end - p - 1 - len(dcid)} bytes (encrypted)')]
            flat.f.update({'quic': True, 'quic.dcid': dcid.hex(), 'quic.header_form': 0})
            infos.append(f'Protected Payload (KP{kp}), DCID={dcid.hex()}')
            layers.append({'name': 'QUIC IETF \u2014 Short Header', 'fields': fields, 'range': (p, end)})
            p = end
    if not layers:
        return None
    if sni:
        flat.f['_quic_tls'] = True
    return 'QUIC', ', '.join(infos), layers


# ---- DHCP / DHCPv6 ------------------------------------------------------------------

DHCP_TYPES = {1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform'}
DHCP_OPTS = {1: 'Subnet Mask', 2: 'Time Offset', 3: 'Router', 4: 'Time Server', 6: 'Domain Name Server', 12: 'Host Name',
             15: 'Domain Name', 26: 'Interface MTU', 28: 'Broadcast Address', 33: 'Static Route', 42: 'NTP Servers',
             43: 'Vendor-Specific Information', 44: 'NetBIOS Name Server', 46: 'NetBIOS Node Type', 47: 'NetBIOS Scope',
             50: 'Requested IP Address', 51: 'IP Address Lease Time', 53: 'DHCP Message Type', 54: 'DHCP Server Identifier',
             55: 'Parameter Request List', 56: 'Message', 57: 'Maximum DHCP Message Size', 58: 'Renewal Time Value',
             59: 'Rebinding Time Value', 60: 'Vendor class identifier', 61: 'Client identifier', 81: 'Client Fully Qualified Domain Name',
             82: 'Relay Agent Information', 119: 'Domain Search', 121: 'Classless Static Route', 252: 'WPAD'}
DHCPV6_TYPES = {1: 'Solicit', 2: 'Advertise', 3: 'Request', 4: 'Confirm', 5: 'Renew', 6: 'Rebind', 7: 'Reply',
                8: 'Release', 9: 'Decline', 10: 'Reconfigure', 11: 'Information-request', 12: 'Relay-forw', 13: 'Relay-repl'}


def dissect_dhcp(b, start, end, flat):
    if end - start < 240 or bytes(b[start + 236:start + 240]) != b'\x63\x82\x53\x63':
        return None
    op, htype, hlen, hops = b[start], b[start + 1], b[start + 2], b[start + 3]
    xid, secs, flg = u32(b, start + 4), u16(b, start + 8), u16(b, start + 10)
    ciaddr, yiaddr, siaddr, giaddr = (ipv4_to_str(b, start + o) for o in (12, 16, 20, 24))
    chaddr = mac_to_str(b, start + 28) if hlen == 6 else bytes(b[start + 28:start + 28 + min(hlen, 16)]).hex()
    opt_fields, mtype, p = [], None, start + 240
    guard = 0
    while p < end and guard < 80:
        guard += 1
        code = b[p]
        if code == 0:
            p += 1
            continue
        if code == 255:
            opt_fields.append(('Option: (255) End', ''))
            break
        if p + 1 >= end:
            break
        ln = b[p + 1]
        d = bytes(b[p + 2:p + 2 + ln])
        p += 2 + ln
        nm = DHCP_OPTS.get(code, f'Option {code}')
        val = d.hex()
        try:
            if code == 53:
                mtype = d[0]
                val = f'{DHCP_TYPES.get(mtype, mtype)} ({mtype})'
            elif code in (1, 3, 4, 6, 28, 42, 44, 50, 54):
                val = ', '.join(ipv4_to_str(d, i) for i in range(0, len(d) - 3, 4))
                if code == 50:
                    flat.f['dhcp.option.requested_ip_address'] = val
            elif code in (12, 15, 56, 60, 252):
                val = d.decode('utf-8', errors='replace').rstrip('\x00')
                if code == 12:
                    flat.f['dhcp.option.hostname'] = val
                if code == 60:
                    flat.f['dhcp.option.vendor_class_id'] = val
            elif code in (51, 58, 59) and len(d) == 4:
                val = f'{u32(d, 0)} seconds'
            elif code == 55:
                val = ', '.join(DHCP_OPTS.get(x, str(x)) for x in d)
            elif code == 57 and len(d) == 2:
                val = str(u16(d, 0))
            elif code == 61 and len(d) >= 2:
                val = (mac_to_str(d, 1) if len(d) == 7 else d[1:].hex())
        except (IndexError, struct.error):
            pass
        opt_fields.append((f'Option: ({code}) {nm}', val))
    mname = DHCP_TYPES.get(mtype, 'Unknown')
    fields = [('Message type', f'Boot Request ({op})' if op == 1 else f'Boot Reply ({op})'),
              ('Hardware type', f'0x{htype:02x}' + (' (Ethernet)' if htype == 1 else '')), ('Hardware address length', str(hlen)),
              ('Hops', str(hops)), ('Transaction ID', f'0x{xid:08x}'), ('Seconds elapsed', str(secs)),
              ('Bootp flags', f'0x{flg:04x} ({"Broadcast" if flg & 0x8000 else "Unicast"})'),
              ('Client IP address', ciaddr), ('Your (client) IP address', yiaddr), ('Next server IP address', siaddr),
              ('Relay agent IP address', giaddr), ('Client MAC address', chaddr),
              sub('Options', f'{len(opt_fields)} options', opt_fields)]
    flat.f.update({'dhcp': True, 'dhcp.option.dhcp': mtype, 'dhcp.id': xid, 'dhcp.ip.your': yiaddr,
                   'dhcp.hw.mac_addr': chaddr})
    if mtype == 6:
        flat.warn('warning', 'DHCP', 'DHCP server refused the request (NAK)')
    elif mtype == 4:
        flat.warn('warning', 'DHCP', 'DHCP client declined the offered address (possible address conflict)')
    return 'DHCP', f'DHCP {mname:<9}- Transaction ID 0x{xid:x}', [
        {'name': f'Dynamic Host Configuration Protocol ({mname})', 'fields': fields, 'range': (start, end)}]


def dissect_dhcpv6(b, start, end, flat):
    if end - start < 4:
        return None
    mt = b[start]
    if mt not in DHCPV6_TYPES:
        return None
    xid = int.from_bytes(bytes(b[start + 1:start + 4]), 'big')
    nm = DHCPV6_TYPES[mt]
    flat.f['dhcpv6.msgtype'] = mt
    return 'DHCPv6', f'{nm} XID: 0x{xid:x}', [{'name': 'DHCPv6', 'fields': [
        ('Message type', f'{nm} ({mt})'), ('Transaction ID', f'0x{xid:06x}'), ('Options', f'{end - start - 4} bytes')],
        'range': (start, end)}]


# ---- NTP -------------------------------------------------------------------------------

NTP_MODES = {1: 'symmetric active', 2: 'symmetric passive', 3: 'client', 4: 'server', 5: 'broadcast',
             6: 'reserved for NTP control message', 7: 'reserved for private use'}


def dissect_ntp(b, start, end, flat):
    if end - start < 48:
        return None
    b0 = b[start]
    li, vn, mode = b0 >> 6, (b0 >> 3) & 7, b0 & 7
    if not 1 <= vn <= 4 or mode == 0:
        return None
    stratum, poll, prec = b[start + 1], b[start + 2], struct.unpack_from('b', b, start + 3)[0]
    refid = bytes(b[start + 12:start + 16])
    refid_txt = ipv4_to_str(refid, 0) if stratum >= 2 else refid.rstrip(b'\x00').decode('ascii', 'replace')

    def ts(off):
        return _ntp_time_str(u32(b, start + off), u32(b, start + off + 4))
    fields = [('Leap Indicator', ['no warning', 'last minute has 61 seconds', 'last minute has 59 seconds', 'unsynchronized'][li]),
              ('Version', str(vn)), ('Mode', f'{NTP_MODES.get(mode, mode)} ({mode})'), ('Peer Clock Stratum', str(stratum)),
              ('Peer Polling Interval', f'{poll} (2^{poll} s)'), ('Peer Clock Precision', f'{2.0 ** prec:.9f} s'),
              ('Reference ID', refid_txt), ('Reference Timestamp', ts(16)), ('Origin Timestamp', ts(24)),
              ('Receive Timestamp', ts(32)), ('Transmit Timestamp', ts(40))]
    flat.f.update({'ntp': True, 'ntp.mode': mode, 'ntp.stratum': stratum})
    if li == 3 and mode == 4:
        flat.warn('note', 'NTP', 'NTP server reports it is unsynchronized')
    return 'NTP', f'NTP Version {vn}, {NTP_MODES.get(mode, mode)}', [
        {'name': 'Network Time Protocol', 'fields': fields, 'range': (start, start + 48)}]


# ============================================================================
# PART 5 -- frame decoder: Ethernet/LLC/VLAN -> ARP/IP -> TCP/UDP/ICMP/IGMP -> applications
# ============================================================================

APPLE_SERVICE_CLASSES = {0: 'BE', 100: 'BK_SYS', 200: 'BK', 300: 'RD', 400: 'OAM', 500: 'AV', 600: 'RV', 700: 'VI', 800: 'VO', 900: 'CTL'}
LINK_NAMES = {0: 'NULL/Loopback', 1: 'Ethernet', 12: 'Raw IP', 14: 'Raw IP', 101: 'Raw IP', 113: 'Linux cooked (SLL)',
              228: 'Raw IPv4', 229: 'Raw IPv6', 276: 'Linux cooked v2 (SLL2)'}


def _add_data_layer(layers, flat, b, start, end, name='Data'):
    if end <= start:
        return
    raw = bytes(b[start:end])
    layer = {'name': name, 'fields': [('Data', hexs(raw, 48)), ('Length', f'{end - start} bytes')], 'range': (start, end)}
    layers.append(layer)
    flat.data_layer = layer


def _frame_layer(pkt, flat, number):
    """Wireshark-style 'Frame N' header: interface, section, packet flags (direction), times, lengths."""
    meta = CAPTURE_META if CAPTURE_META.get('format') == 'pcapng' else {}
    iface = interface_info(pkt.section, pkt.iface_id) if meta else None
    direction = packet_direction(pkt)
    flat.direction = direction
    ifname = (iface or {}).get('name') or (str(pkt.iface_id) if iface else None)
    title = (f'Frame {number}: {pkt.orig_len} bytes on wire ({pkt.orig_len * 8} bits), '
             f'{pkt.cap_len} bytes captured ({pkt.cap_len * 8} bits)')
    fields = []
    if iface:
        title += f' on interface {ifname}, id {pkt.iface_id}' + (f' ({direction})' if direction else '')
        fields.append(('Section number', str(pkt.section)))
        kids = [('Interface name', iface['name'])] if iface.get('name') else []
        if iface.get('description'):
            kids.append(('Interface description', iface['description']))
        if iface.get('filter'):
            kids.append(('Capture filter', iface['filter']))
        if iface.get('os'):
            kids.append(('Operating system', iface['os']))
        if iface.get('hardware'):
            kids.append(('Hardware', iface['hardware']))
        if iface.get('speed'):
            kids.append(('Speed', f'{iface["speed"]:,} bit/s'))
        kids.append(('Snap length', str(iface['snaplen'])))
        fields.append(sub(f'Interface id: {pkt.iface_id} ({ifname})', '', kids))
    elif direction:
        title += f' ({direction})'
    if pkt.flags is not None:
        fields.append(sub(f'Packet flags: 0x{pkt.flags:08x}', '', packet_flags_children(pkt.flags)))
    elif direction:
        fields.append(('Direction', direction.capitalize() + ' (from link-layer header)'))
    if pkt.drops:
        fields.append(('Packets dropped before this one', str(pkt.drops)))
    proc_title = ''
    late = []         # Wireshark prints these after the frame lengths, not at the top
    if pkt.opts:
        def proc_at(i):
            return next((p_ for p_ in CAPTURE_META.get('processes', []) if p_['section'] == pkt.section and p_['index'] == i), None)
        unknown, svc, dflags, flow, proc, eproc, trace_tags = [], None, None, None, None, None, []
        for code, val, u in pkt.opts:
            if code == 0x8001 and u is not None and proc_at(u):
                proc = proc_at(u)
            elif code == 0x8003 and u is not None and proc_at(u):
                eproc = proc_at(u)
            elif code == 0x8002 and u is not None:
                svc = u
            elif code == 0x8004 and u is not None:
                dflags = u
            elif code == 0x8005 and u is not None:
                flow = u
            elif code == 0x800a and u is not None:
                trace_tags.append(u)
            else:
                unknown.append((f'Option 0x{code:04x}', val.hex() + (f'  (= {u})' if u is not None else '')))
        if eproc and proc and eproc['pid'] == proc['pid'] and eproc['name'] == proc['name']:
            eproc = None      # Wireshark only reports an effective process when it is a different one
        for label, p_, key in (('[Process Information]', proc, 'proc'), ('[Effective Process Information]', eproc, 'eproc')):
            if p_:
                kids = [('Id', str(p_['pid'])), ('Name', str(p_['name']))] + ([('UUID', p_['uuid'])] if p_.get('uuid') else [])
                late.append(sub(label, f'{p_["name"]}({p_["pid"]})', kids))
                flat.f[f'frame.{key}.id'] = p_['pid']
                flat.f[f'frame.{key}.name'] = p_['name']
        if proc:
            proc_title = f' proc: {proc["name"]}({proc["pid"]}) [{(eproc or proc)["pid"]}]'
        if svc is not None or dflags is not None or flow is not None:
            letters = ''
            kids = []
            if dflags is not None:
                names_ = [(0x20, 'W', 'Wake Packet(wk)'), (0x10, 'C', 'Nexus Channel(ch)'), (0x08, 'S', 'Socket(so)'),
                          (0x04, 'R', 'ReXmit(re)'), (0x02, 'K', 'Keep Alive(ka)'), (0x01, 'N', 'New Flow(nf)')]
                letters = ''.join(ch if dflags & bit else '.' for bit, ch, _n in names_)
                setn = [n for bit, _c, n in names_ if dflags & bit]
                kids.append(sub(f'[Flags: 0x{dflags:08x}' + (', ' + ', '.join(setn) if setn else '') + ']', '',
                                [(f'{bitline(dflags, 32, bit.bit_length() - 1, 1)} = {n}', yesno(dflags & bit)) for bit, _c, n in names_]))
                flat.f['frame.darwin.flags'] = dflags
                flat.f['frame.darwin.retransmit'] = bool(dflags & 0x04)
                flat.f['frame.darwin.keepalive'] = bool(dflags & 0x02)
            if svc is not None:
                kids.append((f'[Service Class: {APPLE_SERVICE_CLASSES.get(svc, "?")} ({svc})]', ''))
                flat.f['frame.service_class'] = svc
            if flow is not None:
                kids.append((f'[Flow Id: 0x{flow:08x}]', ''))
                flat.f['frame.darwin.flow_id'] = flow
            summary_ = '; '.join(x for x in ((f'flags={letters}' if dflags is not None else ''),
                                             (f'sc={APPLE_SERVICE_CLASSES.get(svc, svc)}' if svc is not None else ''),
                                             (f'fi={flow:08x}' if flow is not None else '')) if x)
            late.append(sub(f'[Darwin Metadata: {summary_}]', '', kids))
        if trace_tags:
            late.append(('[Trace Tag (Apple option 0x800a)]', ', '.join(f'0x{t:08x}' for t in trace_tags) +
                           '  \u2014 raw value; Wireshark 4.6 labels this field trace_tag and prints 0x00000000'))
            flat.f['frame.darwin.trace_tag'] = trace_tags[0]
        if unknown:
            late.append(sub('[Other pcapng options on this packet]', f'{len(unknown)}', unknown))
    title += proc_title
    if pkt.opts and any(0x8000 <= c <= 0x80ff for c, _v, _u in pkt.opts):
        flat.chain.insert(0, 'darwin')       # Wireshark lists a leading 'darwin' layer when Apple metadata is present
        flat.protocols.add('darwin')
    ns = pkt.ts_nsec
    fields += [('Encapsulation type', f'{LINK_NAMES.get(pkt.link_type, "Unknown")} ({pkt.link_type})'),
               ('Arrival Time', format_local_time(pkt.ts_sec, ns)),
               ('UTC Arrival Time', format_utc_time(pkt.ts_sec, ns)),
               ('Epoch Arrival Time', f'{pkt.ts_sec}.{ns:09d}'),
               ('[Time shift for this packet]', '0.000000000 seconds')]
    time_index = len(fields)       # Analysis.feed() inserts the inter-frame deltas here
    fields += [('Frame Number', str(number)), ('Frame Length', f'{pkt.orig_len} bytes ({pkt.orig_len * 8} bits)'),
               ('Capture Length', f'{pkt.cap_len} bytes ({pkt.cap_len * 8} bits)'),
               ('[Frame is marked]', 'False'), ('[Frame is ignored]', 'False')]
    if direction:
        fields.append(('Point-to-Point Direction', 'Sent (0)' if direction == 'outbound' else 'Received (1)'))
    fields += late
    if pkt.comments:
        fields.append(sub('Packet comments', '', [('Comment', c) for c in pkt.comments]))
        flat.f['frame.comment'] = ' | '.join(pkt.comments)
    flat.f.update({'frame.interface_id': pkt.iface_id, 'frame.section_number': pkt.section,
                   'frame.time_epoch': pkt.ts_sec + ns / 1e9})
    if ifname:
        flat.f['frame.interface_name'] = ifname
    if direction:
        flat.f['frame.direction'] = direction
        flat.f['frame.packet_flags_direction'] = 1 if direction == 'inbound' else 2
    return {'name': title, 'fields': fields, 'range': (0, 0), 'time_index': time_index}


def decode_frame(pkt, packet_number_override=None):
    b = pkt.data
    layers = []
    flat = Flat()
    number = packet_number_override if packet_number_override is not None else pkt.number
    fully_captured = pkt.cap_len >= pkt.orig_len

    layers.append(_frame_layer(pkt, flat, number))

    off, eth_type, lt = 0, None, pkt.link_type
    if lt == 1:
        if len(b) < 14:
            return _finish(pkt, layers, flat, b, number, 'Malformed Ethernet frame (shorter than 14 bytes)')
        dst, src = mac_to_str(b, 0), mac_to_str(b, 6)
        et_off = 12
        et = u16(b, et_off)
        vlan_fields = []
        while et in (0x8100, 0x88a8) and len(b) >= et_off + 6:
            tci = u16(b, et_off + 2)
            vlan_fields.append(sub('802.1Q Virtual LAN' if et == 0x8100 else '802.1ad Service VLAN',
                                   f'PRI: {tci >> 13}, DEI: {(tci >> 12) & 1}, ID: {tci & 0x0fff}',
                                   [('Priority', str(tci >> 13)), ('Drop eligible', str((tci >> 12) & 1)), ('ID', str(tci & 0x0fff))]))
            flat.f['vlan.id'] = tci & 0x0fff
            et_off += 4
            et = u16(b, et_off)
            flat.add('vlan')
        vd, vs = oui_vendor(dst), oui_vendor(src)

        def mac_field(label, mac, vendor, raw_off):
            v24 = (b[raw_off] << 16) | (b[raw_off + 1] << 8) | b[raw_off + 2]
            return sub(label, mac + (f' ({vendor})' if vendor else ''), [
                (f'{bitline(v24, 24, 17, 1)} = LG bit', 'Locally administered address (this is NOT the factory default)'
                 if b[raw_off] & 2 else 'Globally unique address (factory default)'),
                (f'{bitline(v24, 24, 16, 1)} = IG bit', 'Group address (multicast/broadcast)' if b[raw_off] & 1 else 'Individual address (unicast)')])
        fields = [mac_field('Destination', dst, vd, 0), mac_field('Source', src, vs, 6)]
        fields += vlan_fields
        fields.append(('Type' if et > 1500 else 'Length', f'{ETHERTYPES.get(et, "Unknown")} (0x{et:04x})' if et > 1500 else str(et)))
        layers.append({'name': 'Ethernet II' if et > 1500 else 'IEEE 802.3 Ethernet', 'fields': fields, 'range': (0, et_off + 2),
                       'summary': f', Src: {src}, Dst: {dst}'})
        flat.eth_src, flat.eth_dst = src, dst
        flat.f['eth.type'] = et
        off = et_off + 2
        if et <= 1500:
            return _decode_llc(pkt, b, off, et, layers, flat, number)
        eth_type = et
    elif lt in (12, 14, 101, 228, 229, 0):
        off = 4 if lt == 0 else 0
        if len(b) <= off:
            return _finish(pkt, layers, flat, b, number, 'Malformed packet (empty)')
        eth_type = 0x86dd if (b[off] >> 4) == 6 else 0x0800
        if lt == 0:
            layers.append({'name': 'Null/Loopback', 'fields': [('Family', 'IP' if eth_type == 0x0800 else 'IPv6')], 'range': (0, 4)})
    elif lt == 113:
        if len(b) < 16:
            return _finish(pkt, layers, flat, b, number, 'Malformed SLL frame')
        eth_type = u16(b, 14)
        layers.append({'name': 'Linux cooked capture v1', 'fields': [('Protocol', f'{ETHERTYPES.get(eth_type, "Unknown")} (0x{eth_type:04x})')], 'range': (0, 16)})
        off = 16
    elif lt == 276:
        if len(b) < 20:
            return _finish(pkt, layers, flat, b, number, 'Malformed SLL2 frame')
        eth_type = u16(b, 0)
        layers.append({'name': 'Linux cooked capture v2', 'fields': [('Protocol', f'{ETHERTYPES.get(eth_type, "Unknown")} (0x{eth_type:04x})')], 'range': (0, 20)})
        off = 20
    else:
        return _finish(pkt, layers, flat, b, number, f'Unsupported link-layer type {pkt.link_type}')

    return _dispatch_ethertype(pkt, b, off, eth_type, layers, flat, number, fully_captured)


def _dispatch_ethertype(pkt, b, off, eth_type, layers, flat, number, fully_captured):
    if eth_type == 0x0806:
        return _decode_arp(pkt, b, off, layers, flat, number)
    if eth_type == 0x0800:
        return _decode_ipv4(pkt, b, off, layers, flat, number, fully_captured)
    if eth_type == 0x86dd:
        return _decode_ipv6(pkt, b, off, layers, flat, number, fully_captured)
    if eth_type == 0x88cc:
        return _decode_lldp(pkt, b, off, layers, flat, number)
    if eth_type in (0x8847, 0x8848):
        p, stack = off, []
        while p + 4 <= len(b):
            word = u32(b, p)
            stack.append(f'label {word >> 12}, TC {(word >> 9) & 7}, TTL {word & 0xff}')
            p += 4
            if word & 0x100:
                break
        layers.append({'name': 'MultiProtocol Label Switching', 'fields': [(f'Label {i + 1}', s) for i, s in enumerate(stack)],
                       'range': (off, p)})
        flat.add('mpls')
        if p < len(b):
            return _dispatch_ethertype(pkt, b, p, 0x86dd if (b[p] >> 4) == 6 else 0x0800, layers, flat, number, fully_captured)
    if eth_type == 0x888e and len(b) >= off + 4:
        kinds = {0: 'EAP Packet', 1: 'Start', 2: 'Logoff', 3: 'Key', 4: 'Encapsulated ASF Alert'}
        kn = kinds.get(b[off + 1], 'Unknown')
        layers.append({'name': '802.1X Authentication', 'fields': [('Version', str(b[off])), ('Type', f'{kn} ({b[off + 1]})'),
                                                                    ('Length', str(u16(b, off + 2)))], 'range': (off, len(b))})
        flat.add('eapol')
        flat.info = f'{kn}'
        return _finish(pkt, layers, flat, b, number, None, 'EAPOL')
    name = ETHERTYPES.get(eth_type)
    _add_data_layer(layers, flat, b, off, len(b))
    return _finish(pkt, layers, flat, b, number, f'Ethertype 0x{eth_type:04x}' + (f' ({name})' if name else ''),
                   (name or 'ETH').upper())


# ---- 802.3 / LLC / STP / LLDP -----------------------------------------------------------

def _decode_llc(pkt, b, off, length, layers, flat, number):
    if len(b) < off + 3:
        return _finish(pkt, layers, flat, b, number, 'Malformed 802.3 frame')
    dsap, ssap, ctrl = b[off], b[off + 1], b[off + 2]
    layers.append({'name': 'Logical-Link Control', 'fields': [('DSAP', f'0x{dsap:02x}'), ('SSAP', f'0x{ssap:02x}'),
                                                               ('Control', f'0x{ctrl:02x}')], 'range': (off, off + 3)})
    if dsap == 0x42 and ssap == 0x42:
        return _decode_stp(pkt, b, off + 3, layers, flat, number)
    if dsap == 0xaa and ssap == 0xaa and len(b) >= off + 8:
        et = u16(b, off + 6)
        layers[-1]['fields'].append(('SNAP Type', f'{ETHERTYPES.get(et, "Unknown")} (0x{et:04x})'))
        layers[-1]['range'] = (off, off + 8)
        return _dispatch_ethertype(pkt, b, off + 8, et, layers, flat, number, pkt.cap_len >= pkt.orig_len)
    _add_data_layer(layers, flat, b, off + 3, min(len(b), off + length))
    return _finish(pkt, layers, flat, b, number, f'802.2 LLC frame (DSAP 0x{dsap:02x}, SSAP 0x{ssap:02x})', 'LLC')


def _bridge_id(b, p):
    return f'{u16(b, p) >> 12 << 12}/{u16(b, p) & 0xfff}/{mac_to_str(b, p + 2)}'


def _decode_stp(pkt, b, off, layers, flat, number):
    if len(b) < off + 4:
        return _finish(pkt, layers, flat, b, number, 'Malformed STP frame')
    ver, bt = b[off + 2], b[off + 3]
    kinds = {0x00: 'Conf.', 0x80: 'TCN', 0x02: 'RST.'}
    fields = [('Protocol Identifier', f'0x{u16(b, off):04x}'), ('Version', str(ver)), ('BPDU Type', f'{kinds.get(bt, "?")} (0x{bt:02x})')]
    info = kinds.get(bt, 'BPDU')
    if bt in (0, 2) and len(b) >= off + 35:
        flg = b[off + 4]
        root, cost, bridge, port = _bridge_id(b, off + 5), u32(b, off + 13), _bridge_id(b, off + 17), u16(b, off + 25)
        fields += [('BPDU flags', f'0x{flg:02x}' + (' (Topology Change)' if flg & 1 else '')), ('Root Identifier', root),
                   ('Root Path Cost', str(cost)), ('Bridge Identifier', bridge), ('Port identifier', f'0x{port:04x}'),
                   ('Message Age', f'{u16(b, off + 27) / 256:.0f}'), ('Max Age', f'{u16(b, off + 29) / 256:.0f}'),
                   ('Hello Time', f'{u16(b, off + 31) / 256:.0f}'), ('Forward Delay', f'{u16(b, off + 33) / 256:.0f}')]
        info += f' Root = {root}  Cost = {cost}  Port = 0x{port:04x}'
        if flg & 1:
            flat.warn('note', 'STP', 'Spanning-tree topology change notification flag set')
    elif bt == 0x80:
        info = 'Conf. TC + Topology Change Notification'
        flat.warn('note', 'STP', 'Spanning-tree topology change')
    layers.append({'name': 'Spanning Tree Protocol', 'fields': fields, 'range': (off, len(b))})
    flat.add('stp')
    flat.info = info
    return _finish(pkt, layers, flat, b, number, None, 'STP')


LLDP_TLVS = {1: 'Chassis Id', 2: 'Port Id', 3: 'Time To Live', 4: 'Port Description', 5: 'System Name',
             6: 'System Description', 7: 'System Capabilities', 8: 'Management Address', 127: 'Organization Specific'}


def _decode_lldp(pkt, b, off, layers, flat, number):
    p, fields, guard, ident = off, [], 0, {}
    while p + 2 <= len(b) and guard < 40:
        guard += 1
        hdr = u16(b, p)
        t, ln = hdr >> 9, hdr & 0x1ff
        val = bytes(b[p + 2:p + 2 + ln])
        p += 2 + ln
        if t == 0:
            fields.append(('End of LLDPDU', ''))
            break
        nm = LLDP_TLVS.get(t, f'TLV {t}')
        txt = val.hex()
        if t in (1, 2) and len(val) >= 2:
            txt = mac_to_str(val, 1) if (val[0] == 4 and len(val) == 7) else val[1:].decode('utf-8', errors='replace')
            ident['chassis' if t == 1 else 'port'] = txt
        elif t in (4, 5, 6):
            txt = val.decode('utf-8', errors='replace')
            if t == 5:
                ident['name'] = txt
        elif t == 3 and len(val) == 2:
            txt = f'{u16(val, 0)} seconds'
            ident['ttl'] = u16(val, 0)
        fields.append((nm, txt))
    layers.append({'name': 'Link Layer Discovery Protocol', 'fields': fields, 'range': (off, p)})
    flat.add('lldp')
    flat.info = ' '.join(f'{k}={v}' for k, v in ident.items()) or 'LLDP'
    return _finish(pkt, layers, flat, b, number, None, 'LLDP')


# ---- ARP --------------------------------------------------------------------------------------

def _decode_arp(pkt, b, off, layers, flat, number):
    if len(b) < off + 28:
        return _finish(pkt, layers, flat, b, number, 'Malformed ARP packet (truncated)')
    hw_type, proto_type, hw_len, proto_len = struct.unpack_from('>HHBB', b, off)
    op = u16(b, off + 6)
    sha, spa = mac_to_str(b, off + 8), ipv4_to_str(b, off + 14)
    tha, tpa = mac_to_str(b, off + 18), ipv4_to_str(b, off + 24)
    opname = {1: 'request', 2: 'reply', 3: 'reverse request', 4: 'reverse reply'}.get(op, str(op))
    layers.append({'name': f'Address Resolution Protocol ({opname})', 'fields': [
        ('Hardware type', f'Ethernet ({hw_type})' if hw_type == 1 else str(hw_type)),
        ('Protocol type', f'IPv4 (0x{proto_type:04x})' if proto_type == 0x0800 else f'0x{proto_type:04x}'),
        ('Hardware size', str(hw_len)), ('Protocol size', str(proto_len)), ('Opcode', f'{opname} ({op})'),
        ('Sender MAC address', sha), ('Sender IP address', spa), ('Target MAC address', tha), ('Target IP address', tpa),
    ], 'range': (off, off + 28)})
    flat.add('arp')
    flat.ip_src, flat.ip_dst = spa, tpa
    flat.f.update({'arp.opcode': op, 'arp.src.proto_ipv4': spa, 'arp.dst.proto_ipv4': tpa,
                   'arp.src.hw_mac': sha, 'arp.dst.hw_mac': tha})
    if op == 1 and spa == tpa:
        info = f'Gratuitous ARP for {tpa} (Request)'
        flat.warn('note', 'ARP', f'Gratuitous ARP announcement for {tpa}')
    elif op == 2 and spa == tpa:
        info = f'Gratuitous ARP for {tpa} (Reply)'
        flat.warn('note', 'ARP', f'Gratuitous ARP reply for {tpa}')
    elif op == 1 and spa == '0.0.0.0':
        info = f'ARP Probe: who has {tpa}? (address conflict detection)'
    elif op == 1:
        info = f'Who has {tpa}? Tell {spa}'
    elif op == 2:
        info = f'{spa} is at {sha}'
    else:
        info = f'ARP opcode {op}'
    flat.info = info
    flat.summary_src, flat.summary_dst = flat.eth_src or spa, flat.eth_dst or tpa
    flat.trailer = (off + 28, len(b))
    return _finish(pkt, layers, flat, b, number, None, 'ARP')


# ---- IPv4 ---------------------------------------------------------------------------------------

def _decode_ipv4(pkt, b, off, layers, flat, number, fully_captured):
    if len(b) < off + 20:
        return _finish(pkt, layers, flat, b, number, 'Malformed IPv4 header (truncated)')
    ihl = (b[off] & 0x0f) * 4
    if b[off] >> 4 != 4 or ihl < 20 or len(b) < off + ihl:
        return _finish(pkt, layers, flat, b, number, f'Malformed IPv4 header (version {b[off] >> 4}, header length {ihl})')
    dscp_ecn = b[off + 1]
    total_len = u16(b, off + 2)
    ident = u16(b, off + 4)
    flags_frag = u16(b, off + 6)
    ttl, proto = b[off + 8], b[off + 9]
    src, dst = ipv4_to_str(b, off + 12), ipv4_to_str(b, off + 16)
    frag_off = (flags_frag & 0x1fff) * 8
    mf, df = bool(flags_frag & 0x2000), bool(flags_frag & 0x4000)

    fields = [
        ('Version', '4'), ('Header length', f'{ihl} bytes ({ihl // 4})'),
        sub('Differentiated Services Field', f'0x{dscp_ecn:02x} (DSCP: {DSCP_NAMES.get(dscp_ecn >> 2, dscp_ecn >> 2)}, ECN: {ECN_NAMES[dscp_ecn & 3].split(" (")[0]})', [
            (f'{bitline(dscp_ecn, 8, 2, 6)} = Differentiated Services Codepoint', f'{DSCP_NAMES.get(dscp_ecn >> 2, "Unknown")} ({dscp_ecn >> 2})'),
            (f'{bitline(dscp_ecn, 8, 0, 2)} = Explicit Congestion Notification', f'{ECN_NAMES[dscp_ecn & 3]} ({dscp_ecn & 3})')]),
        ('Total length', str(total_len)), ('Identification', f'0x{ident:04x} ({ident})'),
        sub('Flags', f'0x{flags_frag >> 13:x}' + (' Don\'t fragment' if df else '') + (' More fragments' if mf else ''),
            [('Reserved bit', yesno(flags_frag & 0x8000)), ("Don't fragment", yesno(df)), ('More fragments', yesno(mf))]),
        ('Fragment offset', str(frag_off)), ('Time to live', str(ttl)),
        ('Protocol', f'{IP_PROTOS.get(proto, "Unknown")} ({proto})'),
    ]
    try:
        stored, valid, correct = ipv4_checksum_check(b, off, ihl)
        fields.append(('Header checksum', checksum_field_text(stored, valid, correct)))
        fields.append(('[Header checksum status]', checksum_status(valid)))
        checksum_expert(flat, 'IPv4 header', stored, valid)
    except Exception:
        pass
    fields += [('Source address', src), ('Destination address', dst)]
    if ihl > 20:
        fields.append(sub('Options', f'{ihl - 20} bytes', parse_ipv4_options(b, off + 20, off + ihl)))
    layers.append({'name': 'Internet Protocol Version 4', 'fields': fields, 'range': (off, off + ihl),
                   'summary': f', Src: {src}, Dst: {dst}'})
    flat.ip_src, flat.ip_dst, flat.ip_proto, flat.ip_ttl, flat.ip_version = src, dst, proto, ttl, 4
    flat.add('ip')
    flat.summary_src, flat.summary_dst = src, dst
    flat.f.update({'ip.ttl': ttl, 'ip.len': total_len, 'ip.id': ident, 'ip.flags.df': df, 'ip.flags.mf': mf,
                   'ip.frag_offset': frag_off, 'ip.version': 4, 'ip.dsfield.dscp': dscp_ecn >> 2})
    if total_len < ihl and total_len != 0:
        return _finish(pkt, layers, flat, b, number, f'Malformed IPv4 packet (bogus total length {total_len})')
    ip_end = off + total_len if total_len else len(b)
    payload_end = min(len(b), ip_end)
    if total_len and len(b) > ip_end:
        flat.trailer = (ip_end, len(b))
    seg_full = fully_captured and (ip_end <= len(b))
    if ttl <= 1 and not (dst.startswith('224.') or dst.startswith('239.')):
        flat.warn('note', 'IP', f'Low TTL ({ttl}) \u2014 packet may expire in transit')
    if mf or frag_off:
        flat.f['ip.fragment'] = True
        flat.warn('note', 'IP', f'Fragmented IPv4 datagram (ID 0x{ident:04x}, offset {frag_off}{", more fragments" if mf else ", last fragment"})')
        seg_full = False
        if frag_off > 0:
            _add_data_layer(layers, flat, b, off + ihl, payload_end, 'Fragment data')
            flat.info = (f'Fragmented IP protocol (proto={IP_PROTOS.get(proto, proto)} {proto}, off={frag_off}, ID={ident:04x})')
            return _finish(pkt, layers, flat, b, number, None, 'IPv4')
    return _dispatch_transport(pkt, b, off, off + ihl, payload_end, proto, layers, flat, src, dst, number,
                               is_v6=False, seg_fully_captured=seg_full)


# ---- IPv6 ------------------------------------------------------------------------------------------

def _decode_ipv6(pkt, b, off, layers, flat, number, fully_captured):
    if len(b) < off + 40:
        return _finish(pkt, layers, flat, b, number, 'Malformed IPv6 header (truncated)')
    ver_tc_fl = struct.unpack_from('>I', b, off)[0]
    traffic_class = (ver_tc_fl >> 20) & 0xff
    flow_label = ver_tc_fl & 0xfffff
    payload_len = u16(b, off + 4)
    next_header, hop_limit = b[off + 6], b[off + 7]
    src, dst = ipv6_to_str(b, off + 8), ipv6_to_str(b, off + 24)
    layers.append({'name': 'Internet Protocol Version 6', 'fields': [
        ('Version', '6'), ('Traffic class', f'0x{traffic_class:02x} (DSCP {traffic_class >> 2}, ECN {traffic_class & 3})'),
        ('Flow label', f'0x{flow_label:05x}'), ('Payload length', str(payload_len)),
        ('Next header', f'{IP_PROTOS.get(next_header, "Unknown")} ({next_header})'),
        ('Hop limit', str(hop_limit)), ('Source address', src), ('Destination address', dst),
    ], 'range': (off, off + 40), 'summary': f', Src: {src}, Dst: {dst}'})
    flat.ip_src, flat.ip_dst, flat.ip_ttl, flat.ip_version = src, dst, hop_limit, 6
    flat.add('ipv6')
    flat.summary_src, flat.summary_dst = src, dst
    flat.f.update({'ipv6.hlim': hop_limit, 'ip.version': 6})

    cursor, header, guard = off + 40, next_header, 0
    while header in IPV6_EXT_HEADERS and guard < 8 and cursor + 2 <= len(b):
        nh = b[cursor]
        if header == 44:
            ext_len = 8
        elif header == 51:
            ext_len = (b[cursor + 1] + 2) * 4
        else:
            ext_len = (b[cursor + 1] + 1) * 8
        layers.append({'name': f'IPv6 Extension Header \u2014 {IP_PROTOS.get(header, {0: "Hop-by-Hop Options", 43: "Routing", 44: "Fragment", 60: "Destination Options"}.get(header, header))}',
                       'fields': [('Next header', str(nh)), ('Length', f'{ext_len} bytes')], 'range': (cursor, cursor + ext_len)})
        if header == 44:
            flat.warn('note', 'IP', 'Fragmented IPv6 datagram')
        cursor += ext_len
        header = nh
        guard += 1
    flat.ip_proto = header
    payload_end = min(len(b), off + 40 + payload_len) if payload_len else len(b)
    if payload_len and len(b) > off + 40 + payload_len:
        flat.trailer = (off + 40 + payload_len, len(b))
    return _dispatch_transport(pkt, b, off, cursor, payload_end, header, layers, flat, src, dst, number,
                               is_v6=True, seg_fully_captured=fully_captured)


def _dispatch_transport(pkt, b, ip_off, off, end, proto, layers, flat, src, dst, number, is_v6, seg_fully_captured):
    if proto == 6:
        return _decode_tcp(pkt, b, ip_off, off, end, layers, flat, number, is_v6, seg_fully_captured)
    if proto == 17:
        return _decode_udp(pkt, b, ip_off, off, end, layers, flat, number, is_v6, seg_fully_captured)
    if proto in (1, 58):
        return _decode_icmp(pkt, b, ip_off, off, end, layers, flat, number, proto == 58, seg_fully_captured)
    if proto == 2:
        return _decode_igmp(pkt, b, off, end, layers, flat, number)
    if proto == 50 and end - off >= 8:
        spi, seq = u32(b, off), u32(b, off + 4)
        layers.append({'name': 'Encapsulating Security Payload', 'fields': [('SPI', f'0x{spi:08x}'), ('Sequence', str(seq))],
                       'range': (off, off + 8)})
        flat.add('esp')
        flat.info = f'ESP (SPI=0x{spi:08x})'
        return _finish(pkt, layers, flat, b, number, None, 'ESP')
    if proto == 132 and end - off >= 12:
        sp, dp, vtag = u16(b, off), u16(b, off + 2), u32(b, off + 4)
        ctype = {0: 'DATA', 1: 'INIT', 2: 'INIT_ACK', 3: 'SACK', 4: 'HEARTBEAT', 5: 'HEARTBEAT_ACK', 6: 'ABORT',
                 7: 'SHUTDOWN', 10: 'COOKIE_ECHO', 11: 'COOKIE_ACK'}.get(b[off + 12], str(b[off + 12])) if end - off > 12 else ''
        layers.append({'name': 'Stream Control Transmission Protocol', 'fields': [
            ('Source port', str(sp)), ('Destination port', str(dp)), ('Verification tag', f'0x{vtag:08x}'),
            ('First chunk', ctype)], 'range': (off, end)})
        flat.add('sctp')
        flat.info = f'{sp} \u2192 {dp} {ctype}'
        return _finish(pkt, layers, flat, b, number, None, 'SCTP')
    _add_data_layer(layers, flat, b, off, end)
    flat.info = f'{IP_PROTOS.get(proto, f"Protocol {proto}")} {src} \u2192 {dst}'
    return _finish(pkt, layers, flat, b, number, None, IP_PROTOS.get(proto, f'proto-{proto}').upper())


# ---- IGMP -----------------------------------------------------------------------------------------------

IGMP_TYPES = {0x11: 'Membership Query', 0x12: 'Membership Report (v1)', 0x16: 'Membership Report (v2)',
              0x17: 'Leave Group', 0x22: 'Membership Report (v3)'}


def _decode_igmp(pkt, b, off, end, layers, flat, number):
    if end - off < 8:
        return _finish(pkt, layers, flat, b, number, 'Malformed IGMP message')
    t, max_resp, cks = b[off], b[off + 1], u16(b, off + 2)
    group = ipv4_to_str(b, off + 4)
    tn = IGMP_TYPES.get(t, f'Type 0x{t:02x}')
    fields = [('Type', f'{tn} (0x{t:02x})'), ('Max response time', f'{max_resp / 10:.1f} s'), ('Checksum', f'0x{cks:04x}'),
              ('Group address', group)]
    if t == 0x22:
        n = u16(b, off + 6)
        fields = [('Type', f'{tn} (0x22)'), ('Checksum', f'0x{cks:04x}'), ('Number of group records', str(n))]
        p, joins = off + 8, []
        rtypes = {1: 'Mode Is Include', 2: 'Mode Is Exclude', 3: 'Change To Include', 4: 'Change To Exclude', 5: 'Allow New Sources', 6: 'Block Old Sources'}
        for _ in range(n):
            if p + 8 > end:
                break
            rt, aux, ns = b[p], b[p + 1], u16(b, p + 2)
            g = ipv4_to_str(b, p + 4)
            fields.append((f'Group record {g}', f'{rtypes.get(rt, rt)}, {ns} source(s)'))
            joins.append(('Join' if rt in (2, 4) and ns == 0 else 'Leave' if rt in (1, 3) and ns == 0 else 'Update') + f' group {g}' + (' for any sources' if ns == 0 else f' for {ns} source(s)'))
            p += 8 + 4 * ns + 4 * aux
        info = 'Membership Report / ' + '; '.join(joins)
    elif t == 0x11:
        info = 'Membership Query, ' + ('general' if group == '0.0.0.0' else f'specific for group {group}')
    elif t in (0x12, 0x16):
        info = f'V{1 if t == 0x12 else 2} Membership Report / Join group {group}'
    elif t == 0x17:
        info = f'Leave Group {group}'
    else:
        info = tn
    layers.append({'name': 'Internet Group Management Protocol', 'fields': fields, 'range': (off, end)})
    flat.add('igmp')
    flat.info = info
    return _finish(pkt, layers, flat, b, number, None, 'IGMP')


# ---- TCP ---------------------------------------------------------------------------------------------------

TCP_FLAG_BITS = [('FIN', 0x01), ('SYN', 0x02), ('RST', 0x04), ('PSH', 0x08), ('ACK', 0x10), ('URG', 0x20),
                 ('ECE', 0x40), ('CWR', 0x80)]
TCP_FLAG_LONG = {'FIN': 'Fin', 'SYN': 'Syn', 'RST': 'Reset', 'PSH': 'Push', 'ACK': 'Acknowledgment', 'URG': 'Urgent',
                 'ECE': 'ECN-Echo', 'CWR': 'Congestion Window Reduced'}


TLS_TCP_PORTS = {261, 443, 448, 465, 563, 614, 636, 989, 990, 992, 993, 994, 995, 2252, 2478, 2479, 2480, 2481, 2482, 2483, 2484,
                 3269, 5061, 6619, 6620, 6621}


def tcp_info_line(t, seq, ack, win):
    flags = ', '.join(t['flag_names']) or '<None>'
    s = f'{t["sport"]} \u2192 {t["dport"]} [{flags}] Seq={seq}'
    if t['flags'] & 0x10:
        s += f' Ack={ack}'
    s += f' Win={win} Len={t["plen"]}'
    if t['opts']:
        s += ' ' + ' '.join(t['opts'])
    return s


def _decode_tcp(pkt, b, ip_off, off, end, layers, flat, number, is_v6, seg_full):
    if len(b) < off + 20:
        return _finish(pkt, layers, flat, b, number, 'Malformed TCP header (truncated)')
    sport, dport = struct.unpack_from('>HH', b, off)
    seq, ack = struct.unpack_from('>II', b, off + 4)
    data_offset = (b[off + 12] >> 4) * 4
    if data_offset < 20:
        return _finish(pkt, layers, flat, b, number, f'Malformed TCP header (bad data offset {data_offset})')
    flags_byte = b[off + 13]
    window = u16(b, off + 14)
    urg = u16(b, off + 18)
    set_flags = [name for name, bit in TCP_FLAG_BITS if flags_byte & bit]
    flags12 = ((b[off + 12] & 0x0f) << 8) | flags_byte
    flag_kids = [(f'{bitline(flags12, 12, 9, 3)} = Reserved', yesno(flags12 & 0xe00)),
                 (f'{bitline(flags12, 12, 8, 1)} = Accurate ECN', yesno(flags12 & 0x100))]
    for n, bit in reversed(TCP_FLAG_BITS):
        flag_kids.append((f'{bitline(flags12, 12, bit.bit_length() - 1, 1)} = {TCP_FLAG_LONG[n]}', yesno(flags_byte & bit)))
    flag_letters = '\u00b7\u00b7\u00b7' + ''.join(ch if flags12 & m else '\u00b7' for ch, m in (
        ('N', 0x100), ('C', 0x80), ('E', 0x40), ('U', 0x20), ('A', 0x10), ('P', 0x08), ('R', 0x04), ('S', 0x02), ('F', 0x01)))
    flag_kids.append(('[TCP Flags]', flag_letters))

    def svc(p):
        s = WELL_KNOWN_PORTS.get(p)
        return f'{p} ({s})' if s else str(p)
    fields = [('Source port', svc(sport)), ('Destination port', svc(dport)),
              ('Sequence number (raw)', str(seq)), ('Acknowledgment number (raw)', str(ack)),
              ('Header length', f'{data_offset} bytes ({data_offset // 4})'),
              sub('Flags', f'0x{flags12:03x} ({", ".join(set_flags) or "<None>"})', flag_kids),
              ('Window', str(window))]
    seg_len = max(0, min(end, len(b)) - off)
    have_full = seg_full and len(b) >= off + seg_len
    try:
        fn = transport_checksum_check_v6 if is_v6 else transport_checksum_check_v4
        stored, valid, correct = fn(b, ip_off, 6, off, seg_len, off + 16, have_full)
        fields.append(('Checksum', checksum_field_text(stored, valid, correct)))
        fields.append(('[Checksum Status]', checksum_status(valid)))
        checksum_expert(flat, 'TCP', stored, valid)
    except Exception:
        pass
    fields.append(('Urgent pointer', str(urg)))
    opt_tokens, ws_shift = [], None
    if data_offset > 20 and len(b) >= off + data_offset:
        kids, opt_tokens = parse_tcp_options(b, off + 20, off + data_offset)
        fields.append(sub('Options', f'{data_offset - 20} bytes', kids))
        for tk in opt_tokens:
            if tk.startswith('WS='):
                ws_shift = int(tk[3:]).bit_length() - 1

    layer = {'name': 'Transmission Control Protocol', 'fields': fields, 'range': (off, off + data_offset),
             'summary': f', Src Port: {sport}, Dst Port: {dport}, Seq: {seq}, Len: {max(0, min(end, len(b)) - off - data_offset)}'}
    layers.append(layer)
    flat.tcp_layer = layer
    payload_start = off + data_offset
    payload_end = max(payload_start, min(end, len(b)))
    payload_len = max(0, payload_end - payload_start)
    flat.tcp_sport, flat.tcp_dport, flat.tcp_flags = sport, dport, set_flags
    flat.l4 = 'tcp'
    flat.add('tcp')
    flat.payload = (payload_start, payload_end)
    flat.tcp = {'sport': sport, 'dport': dport, 'seq': seq, 'ack': ack, 'flags': flags_byte, 'flag_names': set_flags,
                'win': window, 'plen': payload_len, 'opts': opt_tokens, 'ws_shift': ws_shift}
    flat.f.update({'tcp.len': payload_len, 'tcp.seq_raw': seq, 'tcp.ack_raw': ack, 'tcp.window_size_value': window,
                   'tcp.hdr_len': data_offset, 'tcp.flags': flags_byte, 'tcp.urgent_pointer': urg})
    if flags_byte & 0x03 == 0x03:
        flat.warn('warning', 'Security', 'TCP: SYN and FIN both set (invalid combination, often used for scanning)')
    elif flags_byte & 0x3f == 0x29:
        flat.warn('warning', 'Security', 'TCP: FIN+PSH+URG set ("Xmas" scan signature)')
    elif flags_byte == 0 and payload_len == 0:
        flat.warn('note', 'Security', 'TCP: no flags set ("NULL" scan signature)')

    flat.info = tcp_info_line(flat.tcp, seq, ack, window)
    ports = {sport, dport}
    res = None
    if payload_len > 0:
        if 53 in ports and payload_len >= 14 and u16(b, payload_start) == payload_len - 2:
            res = dissect_dns(b, payload_start, payload_end, flat, 'dns', prefix=2)
        if not res:
            res = dissect_tls(b, payload_start, payload_end, flat, dtls=False)
        if not res and (3478 in ports or 5349 in ports):
            res = dissect_stun(b, payload_start, payload_end, flat, 'tcp')
        if not res:
            res = dissect_text_app(b, payload_start, payload_end, flat, sport, dport, 'tcp')
        if not res:
            res = dissect_line_proto(b, payload_start, payload_end, flat, sport, dport)
        if not res and 22 in ports:
            res = ('SSH', 'SSH Encrypted packet', [{'name': 'SSH Protocol', 'fields': [('Encrypted packet', f'{payload_len} bytes')],
                                                    'range': (payload_start, payload_end)}])
    if not res and payload_len >= 5 and ports & TLS_TCP_PORTS:
        # Wireshark's SSL/TLS dissector owns these ports; data that is not the start of a valid record is "Continuation Data"
        res = ('SSL', 'Continuation Data', [{'name': 'Transport Layer Security', 'range': (payload_start, payload_end),
                                            'fields': [('Continuation Data', f'{payload_len} bytes (not the start of a TLS record — mid-record segment or non-TLS data)')]}])
        flat.f['tls.continuation'] = True
    if res:
        proto, info, new_layers = res
        layers.extend(new_layers)
        flat.add('tls' if proto == 'SSL' else proto.lower())
        flat.app_info = info
        flat.highest_proto = 'tls' if proto == 'SSL' else proto.lower()
        if proto in ('TLS', 'DTLS', 'SSL'):
            flat.f['tls'] = True
        return _finish(pkt, layers, flat, b, number, None, proto)
    if payload_len:
        _add_data_layer(layers, flat, b, payload_start, payload_end)
        if payload_len >= 500:
            flat.tcp['reassembly_hint'] = True
    return _finish(pkt, layers, flat, b, number, None, 'TCP')


# ---- UDP ----------------------------------------------------------------------------------------------------

def _udp_app(b, ps, pe, flat, sport, dport):
    """Application-layer dispatch for a UDP payload. Returns (proto, info, layers) or None."""
    ports = {sport, dport}
    res = None
    if 53 in ports:
        res = dissect_dns(b, ps, pe, flat, 'dns')
    elif 5353 in ports:
        res = dissect_dns(b, ps, pe, flat, 'mdns')
    elif 5355 in ports:
        res = dissect_dns(b, ps, pe, flat, 'llmnr')
    elif ports & {67, 68}:
        res = dissect_dhcp(b, ps, pe, flat)
    elif ports & {546, 547}:
        res = dissect_dhcpv6(b, ps, pe, flat)
    elif 123 in ports:
        res = dissect_ntp(b, ps, pe, flat)
    if not res:
        res = dissect_text_app(b, ps, pe, flat, sport, dport, 'udp')
    if not res:
        res = dissect_stun(b, ps, pe, flat, 'udp')
    if not res:
        res = dissect_turn_channel(b, ps, pe, flat, sport, dport)
    if not res:
        res = dissect_quic(b, ps, pe, flat, sport, dport)
    if not res:
        res = dissect_tls(b, ps, pe, flat, dtls=True)
        if res and flat.l4 == 'udp':
            MEDIA_HINTS.add((flat.ip_src, sport))
            MEDIA_HINTS.add((flat.ip_dst, dport))
    if not res:
        pk = rtcp_check(b, ps, pe)
        if pk:
            info, layer = build_rtcp(b, ps, pe, pk, flat)
            res = ('RTCP', info, [layer])
    if not res:
        r = rtp_check(b, ps, pe)
        if r:
            if (flat.ip_src, sport) in MEDIA_HINTS or (flat.ip_dst, dport) in MEDIA_HINTS:
                info, layer = build_rtp(b, ps, pe, r, flat)
                res = ('RTP', info, [layer])
            elif sport >= 1024 and dport >= 1024:
                flat.rtp_candidate = ((flat.ip_src, sport, flat.ip_dst, dport, r['ssrc']), r['seq'], r)
    return res


def _decode_embedded(b, start, end, layers, flat):
    """Dissect the original datagram quoted inside an ICMP error message, nested like Wireshark does
    (icmp > ip > udp/tcp > application). Findings are merged into `flat.f` so display filters such as
    stun.type or dns.qry.name also match the quoted packet."""
    try:
        if end - start < 20:
            return
        ver = b[start] >> 4
        scratch = Flat()
        if ver == 4:
            ihl = (b[start] & 0x0f) * 4
            if ihl < 20 or end - start < ihl:
                return
            proto, total = b[start + 9], u16(b, start + 2)
            src, dst = ipv4_to_str(b, start + 12), ipv4_to_str(b, start + 16)
            tstart = start + ihl
            ip_end = min(end, start + total) if total >= ihl else end
            layers.append({'name': 'Internet Protocol Version 4 (original datagram)', 'range': (start, tstart),
                           'summary': f', Src: {src}, Dst: {dst}',
                           'fields': [('Protocol', f'{IP_PROTOS.get(proto, "Unknown")} ({proto})'), ('Time to live', str(b[start + 8])),
                                      ('Total length', str(total)), ('Identification', f'0x{u16(b, start + 4):04x}'),
                                      ('Source address', src), ('Destination address', dst)]})
            flat.add('ip')
        elif ver == 6 and end - start >= 40:
            proto = b[start + 6]
            src, dst = ipv6_to_str(b, start + 8), ipv6_to_str(b, start + 24)
            tstart, ip_end = start + 40, end
            layers.append({'name': 'Internet Protocol Version 6 (original datagram)', 'range': (start, tstart),
                           'summary': f', Src: {src}, Dst: {dst}',
                           'fields': [('Next header', f'{IP_PROTOS.get(proto, "Unknown")} ({proto})'), ('Hop limit', str(b[start + 7])),
                                      ('Source address', src), ('Destination address', dst)]})
            flat.add('ipv6')
        else:
            return
        scratch.ip_src, scratch.ip_dst = src, dst
        flat.f['icmp.inner'] = True
        if proto == 17 and ip_end - tstart >= 8:
            sport, dport, ulen = struct.unpack_from('>HHH', b, tstart)
            layers.append({'name': 'User Datagram Protocol (original datagram)', 'range': (tstart, tstart + 8),
                           'summary': f', Src Port: {sport}, Dst Port: {dport}',
                           'fields': [('Source port', str(sport)), ('Destination port', str(dport)), ('Length', str(ulen))]})
            flat.add('udp')
            flat.f['icmp.inner_key'] = ((src, sport), (dst, dport), 'udp')
            ps = tstart + 8
            pe = min(ip_end, tstart + ulen) if ulen >= 8 else ip_end
            if pe - ps >= 4:
                res = _udp_app(b, ps, pe, scratch, sport, dport)
                if res:
                    proto_name, _info, new_layers = res
                    layers.extend(new_layers)
                    flat.add(proto_name.lower())
                    for k, v in scratch.f.items():
                        flat.f.setdefault(k, v)
                    flat.f['icmp.inner_app'] = proto_name
        elif proto == 6 and ip_end - tstart >= 8:
            sport, dport, seq = u16(b, tstart), u16(b, tstart + 2), u32(b, tstart + 4)
            layers.append({'name': 'Transmission Control Protocol (original datagram)', 'range': (tstart, tstart + 8),
                           'summary': f', Src Port: {sport}, Dst Port: {dport}, Seq: {seq}',
                           'fields': [('Source port', str(sport)), ('Destination port', str(dport)), ('Sequence number (raw)', str(seq))]})
            flat.add('tcp')
            flat.f['icmp.inner_key'] = ((src, sport), (dst, dport), 'tcp')
    except (IndexError, struct.error):
        return


def _decode_udp(pkt, b, ip_off, off, end, layers, flat, number, is_v6, seg_full):
    if len(b) < off + 8:
        return _finish(pkt, layers, flat, b, number, 'Malformed UDP header (truncated)')
    sport, dport, length = struct.unpack_from('>HHH', b, off)

    def svc(p):
        s = WELL_KNOWN_PORTS.get(p)
        return f'{p} ({s})' if s else str(p)
    fields = [('Source port', svc(sport)), ('Destination port', svc(dport)), ('Length', str(length))]
    if length < 8 and length != 0:
        layers.append({'name': 'User Datagram Protocol', 'fields': fields, 'range': (off, off + 8)})
        return _finish(pkt, layers, flat, b, number, f'Malformed UDP datagram (bad length {length})')
    try:
        stored = u16(b, off + 6)
        if stored == 0 and not is_v6:
            fields.append(('Checksum', '0x0000 [none \u2014 optional for UDP over IPv4]'))
        else:
            have_full = seg_full and length >= 8 and len(b) >= off + length
            fn = transport_checksum_check_v6 if is_v6 else transport_checksum_check_v4
            stored, valid, correct = fn(b, ip_off, 17, off, length or (end - off), off + 6, have_full)
            fields.append(('Checksum', checksum_field_text(stored, valid, correct)))
            fields.append(('[Checksum Status]', checksum_status(valid)))
            checksum_expert(flat, 'UDP', stored, valid)
    except Exception:
        pass
    layers.append({'name': 'User Datagram Protocol', 'fields': fields, 'range': (off, off + 8),
                   'summary': f', Src Port: {sport}, Dst Port: {dport}'})
    flat.udp_sport, flat.udp_dport = sport, dport
    flat.l4 = 'udp'
    flat.add('udp')
    payload_start = off + 8
    payload_end = max(payload_start, min(end, len(b), off + length if length else end))
    plen = payload_end - payload_start
    flat.payload = (payload_start, payload_end)
    flat.f.update({'udp.length': length, 'udp.payload_len': plen})
    flat.info = f'{sport} \u2192 {dport} Len={plen}'
    res = _udp_app(b, payload_start, payload_end, flat, sport, dport) if plen > 0 else None
    if res:
        proto, info, new_layers = res
        layers.extend(new_layers)
        if flat.chain[-1] != proto.lower():
            flat.add(proto.lower())
        if flat.f.pop('_quic_tls', False):
            flat.add('tls')
        flat.info = info
        return _finish(pkt, layers, flat, b, number, None, proto)
    if plen:
        layers[-1]['fields'].append(('UDP payload', f'{plen} bytes'))
        _add_data_layer(layers, flat, b, payload_start, payload_end)
    return _finish(pkt, layers, flat, b, number, None, 'UDP')


# ---- ICMP / ICMPv6 -------------------------------------------------------------------------------------------------

ICMP_TYPES = {0: 'Echo (ping) reply', 3: 'Destination unreachable', 4: 'Source quench', 5: 'Redirect',
              8: 'Echo (ping) request', 9: 'Router advertisement', 10: 'Router solicitation',
              11: 'Time-to-live exceeded', 12: 'Parameter problem', 13: 'Timestamp request', 14: 'Timestamp reply',
              17: 'Address mask request', 18: 'Address mask reply'}
ICMP_UNREACHABLE_CODES = {0: 'Network unreachable', 1: 'Host unreachable', 2: 'Protocol unreachable',
                          3: 'Port unreachable', 4: 'Fragmentation needed', 5: 'Source route failed',
                          6: 'Destination network unknown', 7: 'Destination host unknown', 9: 'Network administratively prohibited',
                          10: 'Host administratively prohibited', 13: 'Communication administratively prohibited'}
ICMP_TIME_CODES = {0: 'Time to live exceeded in transit', 1: 'Fragment reassembly time exceeded'}
ICMP_REDIRECT_CODES = {0: 'Redirect for network', 1: 'Redirect for host', 2: 'Redirect for TOS and network', 3: 'Redirect for TOS and host'}
ICMP6_TYPES = {1: 'Destination unreachable', 2: 'Packet too big', 3: 'Time exceeded', 4: 'Parameter problem',
               128: 'Echo (ping) request', 129: 'Echo (ping) reply', 130: 'Multicast Listener Query',
               131: 'Multicast Listener Report', 132: 'Multicast Listener Done', 133: 'Router Solicitation',
               134: 'Router Advertisement', 135: 'Neighbor Solicitation', 136: 'Neighbor Advertisement',
               137: 'Redirect', 143: 'Multicast Listener Report Message v2'}
ICMP6_UNREACH_CODES = {0: 'No route to destination', 1: 'Communication administratively prohibited', 3: 'Address unreachable',
                       4: 'Port unreachable'}


def _describe_embedded_packet(b, start):
    try:
        if start >= len(b):
            return None
        ver = b[start] >> 4
        if ver == 4 and len(b) >= start + 20:
            ihl = (b[start] & 0x0f) * 4
            proto = b[start + 9]
            src, dst = ipv4_to_str(b, start + 12), ipv4_to_str(b, start + 16)
            extra = ''
            if proto in (6, 17) and len(b) >= start + ihl + 4:
                extra = f', ports {u16(b, start + ihl)}\u2192{u16(b, start + ihl + 2)}'
            return f'{IP_PROTOS.get(proto, proto)} {src} \u2192 {dst}{extra}'
        if ver == 6 and len(b) >= start + 40:
            nh = b[start + 6]
            return f'{IP_PROTOS.get(nh, nh)} {ipv6_to_str(b, start + 8)} \u2192 {ipv6_to_str(b, start + 24)}'
    except Exception:
        return None
    return None


def _nd_options(b, p, end):
    fields, lladdr = [], None
    guard = 0
    while p + 2 <= end and guard < 12:
        guard += 1
        t, ln = b[p], b[p + 1] * 8
        if ln == 0 or p + ln > end:
            break
        if t in (1, 2) and ln >= 8:
            lladdr = mac_to_str(b, p + 2)
            fields.append(('Source link-layer address' if t == 1 else 'Target link-layer address', lladdr))
        elif t == 3 and ln >= 32:
            fields.append(('Prefix information', f'{ipv6_to_str(b, p + 16)}/{b[p + 2]}, valid {u32(b, p + 4)}s, preferred {u32(b, p + 8)}s'))
        elif t == 5 and ln >= 8:
            fields.append(('MTU', str(u32(b, p + 4))))
        elif t == 25 and ln >= 8:
            fields.append(('Recursive DNS server', ', '.join(ipv6_to_str(b, q) for q in range(p + 8, p + ln, 16) if q + 16 <= p + ln)))
        else:
            fields.append((f'Option {t}', f'{ln} bytes'))
        p += ln
    return fields, lladdr


def _decode_icmp(pkt, b, ip_off, off, end, layers, flat, number, is_v6, seg_full):
    if len(b) < off + 4:
        return _finish(pkt, layers, flat, b, number, 'Malformed ICMP header (truncated)')
    icmp_type, code = b[off], b[off + 1]
    checksum = u16(b, off + 2)
    table = ICMP6_TYPES if is_v6 else ICMP_TYPES
    label = table.get(icmp_type, f'Type {icmp_type}')
    msg_len = max(0, min(end, len(b)) - off)
    have_full = seg_full and len(b) >= off + msg_len
    try:
        if is_v6:
            stored, valid, correct = transport_checksum_check_v6(b, ip_off, 58, off, msg_len, off + 2, have_full)
        elif have_full:
            message = bytearray(b[off:off + msg_len])
            stored = u16(message, 2)
            valid = checksum_is_valid(bytes(message))
            correct = None
            if not valid:
                message[2] = message[3] = 0
                correct = compute_correct_checksum(bytes(message))
        else:
            stored, valid, correct = checksum, None, None
        checksum_text = checksum_field_text(stored, valid, correct)
        checksum_expert(flat, 'ICMPv6' if is_v6 else 'ICMP', stored, valid)
    except Exception:
        checksum_text = f'0x{checksum:04x}'
    fields = [('Type', f'{label} ({icmp_type})'), ('Code', str(code)), ('Checksum', checksum_text)]
    info, embedded = label, None
    inner_layers = []
    flat.icmp_type, flat.icmp_code = icmp_type, code
    flat.f.update({'icmp.type': icmp_type, 'icmp.code': code} if not is_v6 else {'icmpv6.type': icmp_type, 'icmpv6.code': code})

    if icmp_type in ((129, 128) if is_v6 else (0, 8)) and len(b) >= off + 8:
        ident, seq = u16(b, off + 4), u16(b, off + 6)
        seq_le = ((seq & 0xff) << 8) | (seq >> 8)
        fields[1] = ('Code', str(code))
        fields += [('Identifier (BE)', f'{ident} (0x{ident:04x})'), ('Sequence number (BE)', str(seq)),
                   ('Sequence number (LE)', str(seq_le))]
        plen = max(0, end - (off + 8))
        if plen:
            fields.append(('Data', f'{plen} bytes'))
        info = f'{label}  id=0x{ident:04x}, seq={seq}/{seq_le}, ttl={flat.ip_ttl}'
        flat.icmp_echo = (ident, seq, icmp_type in (8, 128))
        flat.f.update({'icmp.ident': ident, 'icmp.seq': seq})
    elif not is_v6 and icmp_type in (3, 4, 11, 12, 5):
        codes = {3: ICMP_UNREACHABLE_CODES, 11: ICMP_TIME_CODES, 5: ICMP_REDIRECT_CODES}.get(icmp_type, {})
        cn = codes.get(code)
        fields[1] = ('Code', f'{code}' + (f' ({cn})' if cn else ''))
        if icmp_type == 5:
            fields.append(('Gateway address', ipv4_to_str(b, off + 4)))
        if icmp_type == 3 and code == 4 and len(b) >= off + 8:
            fields.append(('MTU of next hop', str(u16(b, off + 6))))
        embedded = _describe_embedded_packet(b, off + 8)
        if embedded:
            fields.append(('Original datagram', embedded))
        _decode_embedded(b, off + 8, min(end, len(b)), inner_layers, flat)
        info = label + (f' ({cn})' if cn else '')
        sev = 'note'
        flat.warn(sev, 'ICMP', f'{label}' + (f' ({cn})' if cn else ''))
    elif is_v6 and icmp_type in (1, 2, 3, 4):
        cn = ICMP6_UNREACH_CODES.get(code) if icmp_type == 1 else None
        fields[1] = ('Code', f'{code}' + (f' ({cn})' if cn else ''))
        if icmp_type == 2:
            fields.append(('MTU', str(u32(b, off + 4))))
            info = f'{label} (MTU {u32(b, off + 4)})'
        else:
            info = label + (f' ({cn})' if cn else '')
        embedded = _describe_embedded_packet(b, off + 8)
        if embedded:
            fields.append(('Original datagram', embedded))
        _decode_embedded(b, off + 8, min(end, len(b)), inner_layers, flat)
        flat.warn('note', 'ICMPv6', info)
    elif is_v6 and icmp_type in (135, 136) and len(b) >= off + 24:
        target = ipv6_to_str(b, off + 8)
        kids, ll = _nd_options(b, off + 24, end)
        fields.append(('Target address', target))
        if icmp_type == 136:
            fl = b[off + 4]
            fnames = [n for n, bit in (('rtr', 0x80), ('sol', 0x40), ('ovr', 0x20)) if fl & bit]
            fields.append(('Flags', f'0x{fl:02x} ({", ".join(fnames) or "none"})'))
            info = f'{label} {target} ({", ".join(fnames)})' + (f' is at {ll}' if ll else '')
        else:
            info = f'{label} for {target}' + (f' from {ll}' if ll else '')
        fields += kids
        flat.f['icmpv6.nd.target'] = target
        if icmp_type == 136 and not (b[off + 4] & 0x20) and ll:
            pass
    elif is_v6 and icmp_type in (133, 134) and len(b) >= off + 8:
        start_opts = off + (16 if icmp_type == 134 else 8)
        if icmp_type == 134 and len(b) >= off + 16:
            fields += [('Cur hop limit', str(b[off + 4])), ('Flags', f'0x{b[off + 5]:02x}'),
                       ('Router lifetime', f'{u16(b, off + 6)} s')]
        kids, ll = _nd_options(b, start_opts, end)
        fields += kids
        info = label + (f' from {ll}' if ll else '')
    elif is_v6 and icmp_type in (130, 131, 132, 143):
        if icmp_type != 143 and len(b) >= off + 24:
            fields.append(('Multicast address', ipv6_to_str(b, off + 8)))
            info = f'{label} {ipv6_to_str(b, off + 8)}'
    elif not is_v6 and icmp_type in (9, 10):
        pass

    layers.append({'name': 'Internet Control Message Protocol v6' if is_v6 else 'Internet Control Message Protocol',
                   'fields': fields, 'range': (off, min(end, len(b)))})
    proto = 'icmpv6' if is_v6 else 'icmp'
    flat.add(proto)
    layers.extend(inner_layers)
    flat.info = info
    return _finish(pkt, layers, flat, b, number, None, proto.upper())


# ---- common tail -----------------------------------------------------------------------------------------------------

def protocols_in_frame(flat):
    """Wireshark's frame.protocols text: 'ethertype' follows 'eth' on Ethernet II frames, and undissected payload is 'data'."""
    parts = list(flat.chain)
    if 'eth' in parts and flat.f.get('eth.type', 0) > 1500:
        parts.insert(parts.index('eth') + 1, 'ethertype')
    if flat.data_layer is not None:
        parts.append('data')
    return ':'.join(parts)


def _finish(pkt, layers, flat, b, number, forced_info, proto_override=None):
    protocol = (proto_override or flat.highest_proto or 'eth')
    protocol = protocol.upper()
    if forced_info and forced_info.startswith('Malformed'):
        flat.warn('error', 'Malformed', forced_info)
        protocol = protocol if proto_override else 'MALFORMED'
    if pkt.cap_len < pkt.orig_len:
        flat.warn('note', 'Capture', f'Frame truncated by snap length: {pkt.cap_len} of {pkt.orig_len} bytes captured')
    if flat.trailer and flat.trailer[1] > flat.trailer[0]:
        t0, t1 = flat.trailer
        layers.append({'name': 'Ethernet padding / trailer', 'fields': [('Trailer', hexs(bytes(b[t0:t1]), 32)),
                                                                        ('Length', f'{t1 - t0} bytes')], 'range': (t0, t1)})
    info = forced_info or flat.app_info or flat.info or ''
    flat.info = info
    layers[0]['fields'].append(('[Protocols in frame]', protocols_in_frame(flat)))
    summary = {'no': number, 'src': flat.summary_src or flat.eth_src or '', 'dst': flat.summary_dst or flat.eth_dst or '',
               'protocol': protocol, 'length': pkt.orig_len, 'info': info,
               'dir': {'inbound': 'in', 'outbound': 'out'}.get(flat.direction, '')}
    return DecodedPacket(number, pkt.ts_sec, pkt.ts_usec, pkt.orig_len, layers, b, flat, summary, pkt)


# ============================================================================
# PART 6 -- cross-packet analysis: TCP analyzer, streams, request/response matching,
#           RTP detection, Expert Info, display-filter language, live capture
# ============================================================================

MASK32 = 0xffffffff
SEV_ORDER = {'error': 3, 'warning': 2, 'note': 1, 'chat': 0}


def _seq_lt(a, b):
    return ((a - b) & MASK32) > 0x7fffffff and a != b


def _seq_le(a, b):
    return a == b or _seq_lt(a, b)


def tls_label(vname):
    return {'SSL 3.0': 'SSLv3', 'TLS 1.0': 'TLSv1', 'TLS 1.1': 'TLSv1.1', 'TLS 1.2': 'TLSv1.2',
            'TLS 1.3': 'TLSv1.3'}.get(vname, 'TLS')


def tcp_stream_state(st):
    """Human-readable lifecycle state of a TCP stream (like Wireshark's conversation completeness)."""
    if st['rst']:
        if st['synack'] and st['ack3']:
            return 'Reset after establishment'
        return 'Connection refused / reset' if st['syn'] and not st['synack'] else 'Reset'
    if st['syn'] and not st['synack']:
        return 'SYN unanswered'
    if st['synack'] and not st['ack3']:
        return 'Handshake incomplete'
    if not st['syn'] and not st['synack']:
        return 'Midstream (no handshake captured)'
    if all(st['fin']):
        return 'Complete (handshake + close)' if any(st['data']) else 'Complete, no data'
    if any(st['fin']):
        return 'Closing (one side sent FIN)'
    return 'Established (open)' if any(st['data']) else 'Established, no data'


def shannon_entropy(s):
    if not s:
        return 0.0
    import math
    counts = collections.Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def add_expert(pkt, severity, group, message):
    """Attach an expert finding to a packet after it was decoded (used by the whole-capture passes)."""
    if (severity, group, message) in pkt.flat.expert:
        return
    pkt.flat.warn(severity, group, message)
    pkt.flat.f['expert_dirty'] = True


def refresh_expert_layer(pkt):
    f = pkt.flat
    pkt.layers[:] = [l for l in pkt.layers if l['name'] != '[Expert Info]']
    f.f.pop('expert_dirty', None)
    if f.expert:
        f.f['expert'] = True
        f.f['expert.severity'] = max(f.expert, key=lambda e: SEV_ORDER[e[0]])[0]
        f.f['expert.message'] = ' | '.join(e[2] for e in f.expert)
        f.f['expert.group'] = ' | '.join(e[1] for e in f.expert)
        pkt.layers.append({'name': '[Expert Info]', 'range': (0, 0), 'fields': [
            (f'[Expert Info ({sev.capitalize()}/{grp})]', msg) for sev, grp, msg in f.expert]})


class Analysis:
    """Stateful cross-packet analysis. Feed packets in capture order, call finish() after an offline load."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.streams, self.udp_streams = {}, {}
        self.stream_list, self.udp_list = [], []     # by stream index
        self.t0_ns = self.prev_ns = self.prev_ns_before = None
        self.icmp_pending, self.icmp_done = {}, set()
        self.dns_pending, self.stun_pending = {}, {}
        self.dns_rtts, self.stun_rtts = [], []
        self.nonmonotonic = 0
        self.max_ts = 0.0

    # -- entry point -----------------------------------------------------------------
    def feed(self, pkt):
        f = pkt.flat
        ns = pkt.ts_sec * 1000000000 + (pkt.rawinfo.ts_nsec if pkt.rawinfo is not None else pkt.ts_usec * 1000)
        if self.t0_ns is None:
            self.t0_ns = ns
        d_first = ns - self.t0_ns
        d_prev = ns - self.prev_ns if self.prev_ns is not None else 0
        self.prev_ns_before = self.prev_ns
        self.prev_ns = ns
        ts = d_first / 1e9
        f.t_rel = ts
        if self.prev_ns_before is not None:
            f.f['frame.time_delta'] = d_prev / 1e9
        head = pkt.layers[0]
        idx = head.get('time_index', len(head['fields']))
        head['fields'][idx:idx] = [('[Time delta from previous captured frame]', f'{fmt_ns(d_prev)} seconds'),
                                   ('[Time since reference or first frame]', f'{fmt_ns(d_first)} seconds')]
        pkt.summary['rel_time'] = fmt_ns(d_first, 6)
        if d_prev < 0:
            self.nonmonotonic += 1
            f.warn('warning', 'Capture', 'Timestamp is earlier than the previous frame (capture clock went backwards or frames are out of order)')
        if pkt.rawinfo is not None and pkt.rawinfo.drops:
            f.warn('warning', 'Capture', f'{pkt.rawinfo.drops:,} packet(s) were dropped by the capturing system before this frame')
        inner = bool(f.f.get('icmp.inner'))      # protocols found inside a quoted ICMP datagram are not real traffic
        if f.tcp:
            self._tcp(pkt, ts)
        elif f.l4 == 'udp' and f.ip_src:
            self._udp(pkt, ts)
        if f.icmp_echo:
            self._icmp(pkt)
        if not inner and ('dns' in f.protocols or 'mdns' in f.protocols or 'llmnr' in f.protocols):
            self._dns(pkt, ts)
        if f.stun_txid is not None and not inner:
            self._stun(pkt, ts)
        if not inner and 'tls' in f.protocols and 'tcp' in f.protocols and f.stream is not None:
            self._tls_label(pkt)
        ik = f.f.get('icmp.inner_key')
        if ik:   # the quoted datagram belongs to an existing UDP/TCP stream: report that stream's index (Wireshark does too)
            st = (self.udp_streams if ik[2] == 'udp' else self.streams).get(tuple(sorted([ik[0], ik[1]])))
            if st is not None:
                f.f[ik[2] + '.stream'] = st['id']
        refresh_expert_layer(pkt)

    # -- TCP ---------------------------------------------------------------------------
    @staticmethod
    def _newdir():
        return {'isn': None, 'next': None, 'last_ack': None, 'last_win': None, 'last_win_scaled': None, 'ws': None,
                'ack_seen': None, 'dup': 0, 'dup_ts': 0.0, 'ack_frame': 0, 'gap': None, 'unacked': collections.OrderedDict()}

    def _new_stream(self, src, dst, ts, number, reused=False):
        st = {'id': len(self.stream_list), 'a': src, 'b': dst, 't0': ts, 'last': ts, 'tls_ver': None,
              'dir': [self._newdir(), self._newdir()], 'pkts': [], 'syn': 0, 'synack': 0, 'ack3': False, 'fin': [False, False],
              'rst': False, 'retrans': 0, 'dup': 0, 'lost': 0, 'zerowin': 0, 'data': [0, 0], 'npk': [0, 0], 'rtts': [],
              'irtt': None, 'syn_ts': None, 'first_frame': number, 'first_syn_frame': None, 'reused': reused,
              'rst_frame': None, 'first_retrans_frame': None, 'initiator': None, 'synack_isn': None, 'synack_pkt': None}
        self.stream_list.append(st)
        return st

    def _tcp(self, pkt, ts):
        f, t = pkt.flat, pkt.flat.tcp
        if not f.ip_src:
            return
        src, dst = (f.ip_src, t['sport']), (f.ip_dst, t['dport'])
        key = tuple(sorted([src, dst]))
        flags, seq, plen = t['flags'], t['seq'], t['plen']
        syn, fin, rst, ackf = flags & 2, flags & 1, flags & 4, flags & 0x10
        st = self.streams.get(key)
        reused = False
        if st is not None and syn and not ackf:
            d0 = 0 if src == st['a'] else 1
            old_isn = st['dir'][d0]['isn']
            if old_isn is not None and seq != old_isn:
                reused, st = True, None
        if st is None:
            st = self._new_stream(src, dst, ts, pkt.number, reused)
            self.streams[key] = st
        d = 0 if src == st['a'] else 1
        me, peer = st['dir'][d], st['dir'][1 - d]
        st['pkts'].append((pkt, d))
        st['npk'][d] += 1
        seglen = plen + (1 if syn else 0) + (1 if fin else 0)
        if me['isn'] is None:
            me['isn'] = seq if syn else (seq - 1) & MASK32
        if ackf and peer['isn'] is None:
            peer['isn'] = (t['ack'] - 1) & MASK32
        rel_seq = (seq - me['isn']) & MASK32
        rel_ack = (t['ack'] - peer['isn']) & MASK32 if ackf else None
        end = (seq + seglen) & MASK32
        win = t['win']
        if not syn and me['ws'] is not None and peer['ws'] is not None:
            win = t['win'] << me['ws']
        if syn and t['ws_shift'] is not None:
            me['ws'] = t['ws_shift']
        tags = []          # (key, prefix, severity, message)
        extra_fields = []  # fields for the [SEQ/ACK analysis] subtree

        # ---- handshake bookkeeping --------------------------------------------------
        if syn and not ackf:
            st['syn'] += 1
            st['initiator'] = d
            if st['syn_ts'] is None:
                st['syn_ts'], st['first_syn_frame'] = ts, pkt.number
        elif syn and ackf:
            st['synack'] += 1
            st['synack_isn'] = seq
            st['synack_pkt'] = pkt
        elif st['synack'] and not st['ack3'] and d == st['initiator'] and ackf and st['synack_isn'] is not None \
                and t['ack'] == (st['synack_isn'] + 1) & MASK32:
            st['ack3'] = True
            if st['syn_ts'] is not None:
                st['irtt'] = ts - st['syn_ts']
                sp = st['synack_pkt']
                if sp is not None and sp.flat.tcp_layer is not None:    # Wireshark (two-pass) shows the iRTT on the SYN-ACK too
                    sp.flat.f['tcp.analysis.initial_rtt'] = st['irtt']
                    entry = ('[iRTT]', f'{st["irtt"]:.9f} seconds')
                    for fld in sp.flat.tcp_layer['fields']:
                        if fld[0] == '[SEQ/ACK analysis]':
                            fld[2].append(entry)
                            break
                    else:
                        sp.flat.tcp_layer['fields'].append(sub('[SEQ/ACK analysis]', '', [entry]))
        pending_irtt = st['irtt']      # attached below once we know whether the frame has any other analysis to show
        if reused:
            tags.append(('reused_ports', '[TCP Port numbers reused] ', 'note', 'TCP port numbers reused for a new connection'))
        if fin:
            st['fin'][d] = True
        if rst:
            st['rst'], st['rst_frame'] = True, pkt.number
        if plen:
            st['data'][d] += plen

        # ---- sequence analysis ---------------------------------------------------------
        keepalive = (plen <= 1 and not (syn or fin or rst) and me['next'] is not None and
                     seq == (me['next'] - 1) & MASK32 and (flags & 0x10 or plen))
        is_retrans = False
        if keepalive:
            tags.append(('keep_alive', '[TCP Keep-Alive] ', 'note', 'TCP keep-alive segment'))
            me['ka_next'] = (seq + 1) & MASK32
        elif (plen == 1 and peer['last_win_scaled'] == 0 and me['next'] is not None and seq == me['next']
              and not (syn or fin or rst)):
            tags.append(('zero_window_probe', '[TCP ZeroWindowProbe] ', 'note', 'TCP zero-window probe'))
        elif seglen > 0 and not rst:
            if me['next'] is None or seq == me['next']:
                pass
            elif _seq_lt(seq, me['next']):
                gap = me['gap']
                if gap and _seq_le(gap[0], seq) and _seq_le(end, gap[1]):
                    tags.append(('out_of_order', '[TCP Out-Of-Order] ', 'warning', 'TCP segment arrived out of order'))
                    me['gap'] = None
                elif peer['ack_seen'] is not None and _seq_le(end, peer['ack_seen']):
                    tags.append(('spurious_retransmission', '[TCP Spurious Retransmission] ', 'note',
                                 'Data was already acknowledged \u2014 spurious retransmission'))
                    st['retrans'] += 1
                    is_retrans = True
                else:
                    is_retrans = True
                    st['retrans'] += 1
                    if peer['dup'] >= 2 and peer['last_ack'] == seq and ts - peer['dup_ts'] < 0.02:
                        tags.append(('fast_retransmission', '[TCP Fast Retransmission] ', 'note',
                                     'Fast retransmission (triggered by duplicate ACKs)'))
                    tags.append(('retransmission', '[TCP Retransmission] ' if not any(x[0] == 'fast_retransmission' for x in tags) else '',
                                 'note', 'This frame is a (suspected) retransmission'))
                if is_retrans and st['first_retrans_frame'] is None:
                    st['first_retrans_frame'] = pkt.number
            else:
                tags.append(('lost_segment', '[TCP Previous segment not captured] ', 'warning',
                             'Previous segment(s) not captured (common at capture start; otherwise packet loss)'))
                st['lost'] += 1
                me['gap'] = (me['next'], seq)
            if me['next'] is None or _seq_lt(me['next'], end):
                me['next'] = end
            if not is_retrans and seglen > 0 and len(me['unacked']) < 4096:
                me['unacked'][end] = (pkt.number, ts)
        elif seglen == 0 and me['next'] is None:
            me['next'] = seq

        # ---- acknowledgement analysis ------------------------------------------------------
        pure_ack = plen == 0 and not (syn or fin or rst)
        if pure_ack and ackf and peer.get('ka_next') is not None and t['ack'] == peer['ka_next']:
            tags.append(('keep_alive_ack', '[TCP Keep-Alive ACK] ', 'note', 'ACK of a TCP keep-alive probe'))
            peer['ka_next'] = None
        if ackf and not keepalive:
            a = t['ack']
            if peer['next'] is not None and _seq_lt(peer['next'], a) and not syn:
                tags.append(('ack_lost_segment', '[TCP ACKed unseen segment] ', 'warning',
                             'ACKed segment that was not captured (common at capture start)'))
            hit = peer['unacked'].get(a)
            if hit is not None:
                rtt = ts - hit[1]
                st['rtts'].append(rtt)
                extra_fields.append(('[This is an ACK to the segment in frame]', str(hit[0])))
                extra_fields.append(('[The RTT to ACK the segment was]', f'{rtt:.9f} seconds'))
                f.f['tcp.analysis.ack_rtt'] = rtt
                f.f['tcp.analysis.acks_frame'] = hit[0]
            for k in [k for k in peer['unacked'] if _seq_le(k, a)]:
                del peer['unacked'][k]
            if pure_ack and me['last_ack'] == a and me['last_win'] == t['win'] and \
                    peer['next'] is not None and _seq_lt(a, peer['next']):
                me['dup'] += 1
                me['dup_ts'] = ts
                st['dup'] += 1
                tags.append(('duplicate_ack', f'[TCP Dup ACK {me["ack_frame"]}#{me["dup"]}] ', 'note',
                             f'Duplicate ACK #{me["dup"]} (the receiver is asking for the same data again)'))
            else:
                if me['last_ack'] != a:
                    me['ack_frame'] = pkt.number
                    me['dup'] = 0
                elif pure_ack and me['last_win'] is not None and t['win'] != me['last_win'] and t['win'] > 0:
                    tags.append(('window_update', '[TCP Window Update] ', 'chat', 'TCP window update'))
            me['last_ack'] = a
            if me['ack_seen'] is None or _seq_lt(me['ack_seen'], a):
                me['ack_seen'] = a
        me['last_win'] = t['win']
        me['last_win_scaled'] = win
        if t['win'] == 0 and not (rst or syn):
            st['zerowin'] += 1
            tags.append(('zero_window', '[TCP ZeroWindow] ', 'warning', 'TCP receive window is zero \u2014 receiver cannot accept more data'))
        if plen and me['next'] is not None and peer['ack_seen'] is not None:
            inflight = (me['next'] - peer['ack_seen']) & MASK32
            if inflight < 0x7fffffff:
                extra_fields.append(('[Bytes in flight]', str(inflight)))
                f.f['tcp.analysis.bytes_in_flight'] = inflight
                pw = peer['last_win_scaled']
                if pw and inflight >= pw and not is_retrans and not keepalive:
                    tags.append(('window_full', '[TCP Window Full] ', 'warning',
                                 f'TCP window full: {inflight} bytes in flight equals the receiver window ({pw})'))
        if pending_irtt is not None:
            # Wireshark shows [iRTT] inside [SEQ/ACK analysis]; a bare FIN with nothing else to report gets no such section at all
            bare_fin = fin and plen == 0 and not extra_fields and not any(k not in ('syn', 'synack', 'fin', 'reset') for k, *_ in tags)
            if not bare_fin:
                extra_fields.append(('[iRTT]', f'{pending_irtt:.9f} seconds'))
                f.f['tcp.analysis.initial_rtt'] = pending_irtt
        if rst:
            tags.append(('reset', '', 'warning', 'Connection reset (RST)'))
        if syn and not ackf:
            tags.append(('syn', '', 'chat', 'Connection establish request (SYN)'))
        elif syn and ackf:
            tags.append(('synack', '', 'chat', 'Connection establish acknowledge (SYN+ACK)'))
        if fin:
            tags.append(('fin', '', 'chat', 'Connection finish (FIN)'))

        blank_info = False
        if not is_retrans:
            if f.f.get('tls.continuation') and me.get('tls_rem', 0) > 0 and plen <= me['tls_rem']:
                # middle/end of a TLS record whose header an earlier segment carried: Wireshark prints "TLS segment data" and no Info
                me['tls_rem'] -= plen
                blank_info = True
                f.f['tls.segment_data'] = True
                for l in pkt.layers:
                    if l['name'] == 'Transport Layer Security' and l['fields'] and l['fields'][0][0] == 'Continuation Data':
                        l['fields'] = [(f'TLS segment data ({plen} bytes)', 'continuation of a record that started in an earlier segment')]
            elif f.f.get('tls.partial_remaining'):
                me['tls_rem'] = f.f['tls.partial_remaining']
            elif plen:
                me['tls_rem'] = 0
        if plen:      # counts every data segment, retransmissions too, and is shown on all of them (not only on PSH segments)
            me['push_bytes'] = me.get('push_bytes', 0) + plen
            extra_fields.append(('[Bytes sent since last PSH flag]', str(me['push_bytes'])))
            f.f['tcp.analysis.push_bytes_sent'] = me['push_bytes']
            if flags & 0x08:
                me['push_bytes'] = 0
        if f.app_info and any(k in ('keep_alive', 'zero_window_probe') for k, *_ in tags):
            self._strip_app(pkt)    # Wireshark does not hand keep-alive / zero-window-probe bytes to application dissectors
        f.stream = st['id']
        f.f.update({'tcp.stream': st['id'], 'tcp.seq': rel_seq, 'tcp.nxtseq': (rel_seq + seglen) & MASK32,
                    'tcp.window_size': win, 'tcp.state': tcp_stream_state(st)})
        f.f['tcp.ack'] = rel_ack if rel_ack is not None else t['ack']
        prefix, kids = '', []
        for k, pre, sev, msg in tags:
            f.f['tcp.analysis.' + k] = True
            if k not in ('syn', 'synack', 'fin', 'reset'):
                f.f['tcp.analysis.flags'] = True
            prefix += pre
            f.warn(sev, 'TCP' if k not in ('syn', 'synack', 'fin') else 'Sequence', msg)
            kids.append((msg, ''))
        base = f.app_info if f.app_info else tcp_info_line(t, rel_seq, rel_ack or 0, win)
        if blank_info:
            base = ''
        elif prefix and f.f.get('tls.continuation'):
            base = ', ' + base      # Wireshark separates the TCP-analysis prefix from SSL "Continuation Data" with a comma
        if not f.app_info and t.get('reassembly_hint'):
            base += ' [TCP segment of a reassembled PDU]'
        f.info = prefix + base
        pkt.summary['info'] = f.info

        layer = f.tcp_layer
        if layer is not None:
            fl = layer['fields']
            ins = [('[Stream index]', str(st['id'])),
                   ('[Stream state]', tcp_stream_state(st)),
                   ('Sequence number', f'{rel_seq}    (relative sequence number)'),
                   ('[Next sequence number]', f'{(rel_seq + seglen) & MASK32}    (relative sequence number)')]
            if rel_ack is not None:
                ins.append(('Acknowledgment number', f'{rel_ack}    (relative ack number)'))
            fl[2:2] = ins
            fl.append(('[Calculated window size]', str(win)))
            fl.append(sub('[Timestamps]', '', [
                ('Time since first frame in this TCP stream', f'{ts - st["t0"]:.9f} seconds'),
                ('Time since previous frame in this TCP stream', f'{ts - st["last"]:.9f} seconds')]))
            rank = {'[This is an ACK to the segment in frame]': 0, '[The RTT to ACK the segment was]': 1, '[iRTT]': 2,
                    '[Bytes in flight]': 3, '[Bytes sent since last PSH flag]': 4}
            analysis_kids = kids + sorted(extra_fields, key=lambda x: rank.get(x[0], 9))
            if analysis_kids:
                fl.append(sub('[SEQ/ACK analysis]', '', analysis_kids))
            if plen:
                fl.append(('TCP payload', f'{plen} bytes'))
            layer['summary'] = f', Src Port: {t["sport"]}, Dst Port: {t["dport"]}, Seq: {rel_seq}' + \
                (f', Ack: {rel_ack}' if rel_ack is not None else '') + f', Len: {plen}'
        st['last'] = ts

    @staticmethod
    def _strip_app(pkt):
        f = pkt.flat
        f.app_info = None
        pkt.summary['protocol'] = 'TCP'
        if 'tcp' in f.chain:
            del f.chain[f.chain.index('tcp') + 1:]
        f.protocols = set(f.chain)
        f.highest_proto = 'tcp'
        f.f.pop('tls.continuation', None)
        idx = next((i for i, l in enumerate(pkt.layers) if l is f.tcp_layer), None)
        if idx is not None:
            pkt.layers[idx + 1:] = [l for l in pkt.layers[idx + 1:] if l['name'] == 'Ethernet padding / trailer']
        f.data_layer = None
        pkt.layers[0]['fields'] = [(fld[0], protocols_in_frame(f)) if fld[0] == '[Protocols in frame]' else fld for fld in pkt.layers[0]['fields']]

    def _tls_label(self, pkt):
        f = pkt.flat
        if f.f.get('tls.continuation'):
            return
        st = self.stream_list[f.stream]
        v = f.f.get('tls.handshake.version')
        if v and f.f.get('tls.handshake.type') in (1, 2):
            st['tls_ver'] = v
        ver = st['tls_ver'] or f.f.get('tls.record.version')
        if ver:
            pkt.summary['protocol'] = tls_label(ver)

    # -- UDP -------------------------------------------------------------------------------
    def _udp(self, pkt, ts):
        f = pkt.flat
        src, dst = (f.ip_src, f.udp_sport), (f.ip_dst, f.udp_dport)
        key = tuple(sorted([src, dst]))
        st = self.udp_streams.get(key)
        if st is None:
            st = {'id': len(self.udp_list), 'a': src, 'b': dst, 't0': ts, 'last': ts}
            self.udp_streams[key] = st
            self.udp_list.append(st)
        f.stream = st['id']
        f.f['udp.stream'] = st['id']
        for l in pkt.layers:
            if l['name'] == 'User Datagram Protocol':
                l['fields'].insert(0, ('[Stream index]', str(st['id'])))
                l['fields'].append(sub('[Timestamps]', '', [
                    ('Time since first frame', f'{ts - st["t0"]:.9f} seconds'),
                    ('Time since previous frame', f'{ts - st["last"]:.9f} seconds')]))
                break
        st['last'] = ts

    # -- ICMP echo matching -----------------------------------------------------------------------
    def _icmp(self, pkt):
        f = pkt.flat
        ident, seq, is_req = f.icmp_echo
        if is_req:
            self.icmp_pending[(f.ip_src, f.ip_dst, ident, seq)] = pkt
        else:
            req = self.icmp_pending.pop((f.ip_dst, f.ip_src, ident, seq), None)
            if req is not None:
                self.icmp_done.add(req.number)
                pkt.summary['info'] += f'  (request in {req.number})'
                req.summary['info'] += f'  (reply in {pkt.number})'
                req.flat.f['icmp.resp_in'] = pkt.number
                pkt.flat.f['icmp.resp_to'] = req.number
                dt = pkt.flat.t_rel - req.flat.t_rel
                pkt.layers[-1]['fields'].append(('[Request frame]', str(req.number)))
                pkt.layers[-1]['fields'].append(('[Response time]', f'{dt * 1000:.3f} ms'))
                req.layers[-1]['fields'].append(('[Response frame]', str(pkt.number)))
                pkt.flat.f['icmp.resptime'] = dt * 1000
                pkt.flat.icmp_echo = None

    # -- DNS request/response matching ---------------------------------------------------------------
    def _dns(self, pkt, ts):
        f = pkt.flat
        txid = f.f.get('dns.id')
        if txid is None or not f.ip_src:
            return
        name = (f.dns_name or '').lower()
        is_resp = f.f.get('dns.flags.response')
        if not is_resp:
            self.dns_pending[(txid, name, f.ip_src, f.ip_dst)] = (pkt, ts)
            return
        hit = self.dns_pending.pop((txid, name, f.ip_dst, f.ip_src), None)
        if not hit:
            return
        req, rts = hit
        dt = ts - rts
        f.f['dns.response_to'] = req.number
        f.f['dns.time'] = dt
        req.flat.f['dns.response_in'] = pkt.number
        self.dns_rtts.append(dt)
        for p2, extra in ((pkt, [('[Request In]', str(req.number)), ('[Time]', f'{dt:.9f} seconds')]),
                          (req, [('[Response In]', str(pkt.number))])):
            for l in p2.layers:
                if l['name'].endswith('Name System') or 'Multicast' in l['name'] or 'Link-local' in l['name']:
                    l['fields'].extend(extra)
        if dt > 1.0:
            f.warn('note', 'Response time', 'Slow DNS response (more than 1 second after the query)')

    # -- STUN request/response matching --------------------------------------------------------------
    def _stun(self, pkt, ts):
        f = pkt.flat
        txid, cls = f.stun_txid, f.f.get('stun.class')
        if cls == 0:
            self.stun_pending[(txid, f.ip_src, f.ip_dst)] = (pkt, ts)
        elif cls in (2, 3):
            hit = self.stun_pending.pop((txid, f.ip_dst, f.ip_src), None)
            if hit:
                req, rts = hit
                dt = ts - rts
                self.stun_rtts.append(dt)
                f.f['stun.response_to'] = req.number
                f.f['stun.time'] = dt
                req.flat.f['stun.response_in'] = pkt.number
                for p2, extra in ((pkt, [('[Request In]', str(req.number)), ('[Response Time]', f'{dt * 1000:.3f} ms')]),
                                  (req, [('[Response In]', str(pkt.number))])):
                    for l in p2.layers:
                        if l['name'].startswith('Session Traversal'):
                            l['fields'].extend(extra)

    # -- end of an offline load ------------------------------------------------------------------------
    def finish(self, packets):
        for req in list(self.icmp_pending.values()):
            if req.number not in self.icmp_done:
                req.summary['info'] += '  (no response found!)'
                add_expert(req, 'warning', 'Sequence', 'ICMP echo request has no matching reply in this capture')
        self.icmp_pending.clear()
        refine_rtp(packets)
        postpass(self, packets)
        for p in packets:
            if p.flat.f.get('expert_dirty'):
                refresh_expert_layer(p)


def rtp_sequence_analysis(packets):
    flows = {}
    for p in packets:
        f = p.flat
        if 'rtp' not in f.protocols or f.f.get('rtp.ssrc') is None or f.f.get('icmp.inner'):
            continue
        key = (f.ip_src, f.udp_sport, f.ip_dst, f.udp_dport, f.f['rtp.ssrc'])
        seq, pt = f.f['rtp.seq'], f.f['rtp.p_type']
        st = flows.get(key)
        if st is None:
            flows[key] = {'last': seq, 'pt': pt}
            continue
        exp = (st['last'] + 1) & 0xffff
        if seq == exp:
            st['last'] = seq
        elif seq == st['last']:
            add_expert(p, 'note', 'RTP', 'RTP: duplicate sequence number')
        elif ((seq - exp) & 0xffff) < 1000:
            lost = (seq - exp) & 0xffff
            add_expert(p, 'warning' if lost >= 3 else 'note', 'RTP', f'RTP: sequence gap \u2014 {lost} packet(s) lost or not captured')
            f.f['rtp.lost'] = lost
            st['last'] = seq
        elif ((st['last'] - seq) & 0xffff) < 1000:
            add_expert(p, 'warning', 'RTP', 'RTP: packet arrived out of order (sequence number went backwards)')
        else:
            add_expert(p, 'note', 'RTP', 'RTP: sequence number jumped (stream restarted or SSRC collision)')
            st['last'] = seq
        if pt != st['pt']:
            add_expert(p, 'chat', 'RTP', 'RTP: payload type changed within the stream')
            st['pt'] = pt


def postpass(an, packets):
    """Whole-capture checks that need to see every packet: security heuristics, stream summaries, capture quality."""
    rtp_sequence_analysis(packets)
    by_num = {p.number: p for p in packets}

    # --- TCP streams ---------------------------------------------------------------------------------------
    for st in an.stream_list:
        first = by_num.get(st['first_syn_frame'] or st['first_frame'])
        if first is None:
            continue
        if st['syn'] and not st['synack'] and not st['rst']:
            add_expert(first, 'warning', 'TCP', 'TCP connection attempt was never answered (SYN without SYN-ACK)')
        elif st['syn'] and not st['synack'] and st['rst']:
            add_expert(by_num.get(st['rst_frame'], first), 'warning', 'TCP', 'TCP connection refused (RST in response to SYN)')
        total = sum(st['npk'])
        if total >= 20 and st['retrans'] / max(1, total) >= 0.05:
            add_expert(by_num.get(st['first_retrans_frame'], first), 'warning', 'TCP',
                       f'High TCP retransmission rate in this stream ({st["retrans"]} of {total} segments = {100 * st["retrans"] / total:.0f}%)')
        if st['irtt'] is not None and st['irtt'] > 1.0:
            add_expert(first, 'note', 'TCP', f'Slow TCP handshake (round-trip {st["irtt"]:.2f} s)')
        if st['rtts']:
            srt = sorted(st['rtts'])
            p95 = srt[int(0.95 * (len(srt) - 1))]
            if len(srt) >= 10 and p95 > 1.0:
                add_expert(first, 'note', 'TCP', f'High ACK round-trip times in this stream (95th percentile {p95:.2f} s)')
        if st['zerowin'] >= 3:
            add_expert(first, 'warning', 'TCP', f'Receiver advertised a zero window {st["zerowin"]} times (application not reading)')

    # --- scans / floods ---------------------------------------------------------------------------------------
    answered_by_init = collections.Counter()
    for st in an.stream_list:
        if st['synack'] and st['initiator'] is not None:
            answered_by_init[(st['a'] if st['initiator'] == 0 else st['b'])[0]] += 1
    syn_targets, syn_first = collections.defaultdict(set), {}
    syn_ports_by_dst = collections.defaultdict(set)
    echo_targets, echo_first = collections.defaultdict(set), {}
    arp_targets, arp_first = collections.defaultdict(set), {}
    unreach = collections.defaultdict(lambda: [0, None, set()])
    syn_src_to_dst = collections.defaultdict(lambda: collections.defaultdict(set))
    for p in packets:
        f = p.flat
        if f.tcp and f.tcp['flags'] & 0x12 == 0x02 and f.ip_src:
            syn_targets[f.ip_src].add((f.ip_dst, f.tcp['dport']))
            syn_ports_by_dst[(f.ip_src, f.ip_dst)].add(f.tcp['dport'])
            syn_first.setdefault(f.ip_src, p)
            syn_src_to_dst[(f.ip_dst, f.tcp['dport'])][f.ip_src].add(p.number)
        elif f.icmp_type == 8 and f.ip_version == 4 and 'icmp' in f.protocols:
            echo_targets[f.ip_src].add(f.ip_dst)
            echo_first.setdefault(f.ip_src, p)
        elif 'arp' in f.protocols and f.f.get('arp.opcode') == 1 and f.f.get('arp.src.proto_ipv4') not in (None, '0.0.0.0'):
            arp_targets[f.f['arp.src.hw_mac']].add(f.f['arp.dst.proto_ipv4'])
            arp_first.setdefault(f.f['arp.src.hw_mac'], p)
        elif f.icmp_type == 3 and f.icmp_code == 3 and 'icmp' in f.protocols:
            u = unreach[f.ip_src]
            u[0] += 1
            u[1] = u[1] or p
            ik = f.f.get('icmp.inner_key')
            if ik:
                u[2].add(ik[1][1])
    for src, targets in syn_targets.items():
        answered = answered_by_init.get(src, 0)
        hosts = {h for h, _ in targets}
        if len(targets) >= 20 and answered < 0.5 * len(targets):
            kind = 'port scan of one host' if len(hosts) == 1 else f'scan across {len(hosts)} hosts'
            add_expert(syn_first[src], 'warning', 'Security',
                       f'Possible TCP SYN scan: {src} probed {len(targets)} host:port targets ({kind}); only {answered} connection(s) answered')
    for dst_port, srcs in syn_src_to_dst.items():
        if len(srcs) >= 30 and sum(answered_by_init.get(s, 0) for s in srcs) < 0.3 * len(srcs):
            first_no = min(min(v) for v in srcs.values())
            add_expert(by_num[first_no], 'warning', 'Security',
                       f'Possible SYN flood: {len(srcs)} different sources sent SYNs to {dst_port[0]}:{dst_port[1]} with few completions')
    for src, targets in echo_targets.items():
        if len(targets) >= 20:
            add_expert(echo_first[src], 'warning', 'Security', f'Possible ping sweep: {src} sent echo requests to {len(targets)} hosts')
    for mac, targets in arp_targets.items():
        if len(targets) >= 30:
            add_expert(arp_first[mac], 'warning', 'Security', f'Possible ARP scan: {mac} asked for {len(targets)} different IP addresses')
    for host, (cnt, first, ports) in unreach.items():
        if len(ports) >= 20:
            add_expert(first, 'warning', 'Security', f'Possible UDP scan: {host} returned ICMP port-unreachable for {len(ports)} different ports')
        elif cnt >= 20:
            add_expert(first, 'note', 'ICMP', f'{host} rejected UDP traffic {cnt} times with ICMP port-unreachable (peer closed its port?)')

    # --- ARP / DHCP consistency ------------------------------------------------------------------------------------
    bindings, dhcp_servers = {}, {}
    for p in packets:
        f = p.flat
        if f.f.get('icmp.inner'):
            continue
        if 'arp' in f.protocols:
            ip, mac = f.f.get('arp.src.proto_ipv4'), f.f.get('arp.src.hw_mac')
            if ip and mac and ip != '0.0.0.0' and mac != 'ff:ff:ff:ff:ff:ff':
                old = bindings.get(ip)
                if old is None:
                    bindings[ip] = (mac, p.number)
                elif old[0] != mac:
                    add_expert(p, 'warning', 'Security',
                               f'IP address {ip} is now claimed by {mac} but frame {old[1]} said {old[0]} (ARP spoofing, duplicate IP or address change)')
                    bindings[ip] = (mac, p.number)
        if f.f.get('dhcp.option.dhcp') in (2, 5) and f.ip_src:
            if f.ip_src not in dhcp_servers:
                dhcp_servers[f.ip_src] = p.number
                if len(dhcp_servers) == 2:
                    add_expert(p, 'warning', 'Security', f'Second DHCP server answered ({f.ip_src}; first was {next(iter(dhcp_servers))}) \u2014 possible rogue DHCP server')

    # --- DNS anomalies -----------------------------------------------------------------------------------------------
    nx_by_client, resp_by_client, nx_first = collections.Counter(), collections.Counter(), {}
    for p in packets:
        f = p.flat
        if f.f.get('dns.flags.response') is None or f.f.get('icmp.inner'):
            continue
        name = f.dns_name or ''
        if not f.f.get('dns.flags.response'):
            labels = name.split('.')
            longest = max(labels, key=len) if labels else ''
            if len(name) > 100 or (len(longest) >= 30 and shannon_entropy(longest) >= 3.7):
                add_expert(p, 'note', 'Security', 'DNS query name looks machine-generated or very long (possible DNS tunnelling / DGA)')
        else:
            resp_by_client[f.ip_dst] += 1
            if f.f.get('dns.flags.rcode') == 3:
                nx_by_client[f.ip_dst] += 1
                nx_first.setdefault(f.ip_dst, p)
    for cl, n in nx_by_client.items():
        if n >= 20 and n >= 0.5 * resp_by_client[cl]:
            add_expert(nx_first[cl], 'note', 'Security', f'{cl} received {n} NXDOMAIN answers ({100 * n // resp_by_client[cl]}% of its DNS responses) \u2014 DGA/malware or broken configuration')
    for (txid, name, cip, sip), (req, _ts) in an.dns_pending.items():
        if 'mdns' not in req.flat.protocols:
            add_expert(req, 'note', 'Response time', 'DNS query has no response in this capture')

    # --- capture quality ---------------------------------------------------------------------------------------------------
    seen, deltas = {}, []
    for p in packets:
        d = p.flat.f.get('frame.time_delta') or 0.0
        if d > 0:
            deltas.append(d)
    mean_delta = (sum(deltas) / len(deltas)) if deltas else 0.0
    for p in packets:
        f = p.flat
        d = f.f.get('frame.time_delta') or 0.0
        if d > max(10.0, 100 * mean_delta) and p.number > 1:
            add_expert(p, 'chat', 'Capture', f'Idle gap of {d:.1f} s since the previous frame')
        if len(p.raw) >= 34 and not f.f.get('tcp.analysis.retransmission'):
            h = hash(bytes(p.raw))
            prev = seen.get(h)
            t = f.t_rel
            if prev is not None and t - prev < 0.001 and 'arp' not in f.protocols:
                add_expert(p, 'note', 'Capture', 'Duplicate frame: identical bytes seen less than 1 ms earlier (capture on several interfaces, SPAN/mirror, or a forwarding loop)')
            seen[h] = t


def refine_rtp(packets):
    """Promote generic UDP packets to RTP when they form a stream of consecutive sequence numbers."""
    groups = {}
    for p in packets:
        c = p.flat.rtp_candidate
        if c and 'rtp' not in p.flat.protocols:
            groups.setdefault(c[0], []).append(p)
    promoted = 0
    for lst in groups.values():
        if len(lst) < 3:
            continue
        good = sum(1 for i in range(1, len(lst))
                   if 0 < ((lst[i].flat.rtp_candidate[1] - lst[i - 1].flat.rtp_candidate[1]) & 0xffff) <= 3)
        if good < 0.6 * (len(lst) - 1):
            continue
        for p in lst:
            f = p.flat
            key, seq, r = f.rtp_candidate
            ps, pe = f.payload
            info, layer = build_rtp(p.raw, ps, pe, r, f)
            if f.data_layer in p.layers:
                p.layers.remove(f.data_layer)
            idx = next((i for i, l in enumerate(p.layers) if l['name'] == 'User Datagram Protocol'), len(p.layers) - 1) + 1
            p.layers.insert(idx, layer)
            f.add('rtp')
            f.info = info
            p.summary['protocol'] = 'RTP'
            p.summary['info'] = info
            f.rtp_candidate = None
            f.expert = [e for e in f.expert]
            p.layers[0]['fields'] = [(fld[0], protocols_in_frame(f)) if fld[0] == '[Protocols in frame]' else fld
                                     for fld in p.layers[0]['fields']]
            promoted += 1
    return promoted


def build_rtp_streams(packets):
    streams = {}
    for p in packets:
        f = p.flat
        if 'rtp' in f.protocols and f.f.get('rtp.ssrc') is not None:
            key = (f.ip_src, f.udp_sport, f.ip_dst, f.udp_dport, f.f['rtp.ssrc'])
            s = streams.setdefault(key, {'pkts': 0, 'first_seq': f.f['rtp.seq'], 'last_seq': f.f['rtp.seq'], 'cycles': 0,
                                         'pt': f.f['rtp.p_type'], 't0': p.ts_sec + p.ts_usec / 1e6, 't1': 0, 'bytes': 0,
                                         'jitter': 0.0, 'prev': None})
            seq = f.f['rtp.seq']
            if s['pkts'] and seq < s['last_seq'] and s['last_seq'] - seq > 0x8000:
                s['cycles'] += 1
            s['last_seq'] = seq if not (seq < s['last_seq'] and s['last_seq'] - seq <= 0x8000) else s['last_seq']
            s['pkts'] += 1
            s['bytes'] += p.length
            t = p.ts_sec + p.ts_usec / 1e6
            s['t1'] = t
            clock = 90000 if s['pt'] >= 96 else 8000
            if s['prev'] is not None:
                d = abs((t - s['prev'][0]) - (f.f['rtp.timestamp'] - s['prev'][1]) / clock)
                s['jitter'] += (d - s['jitter']) / 16
            s['prev'] = (t, f.f['rtp.timestamp'])
    out = []
    for (src, sp, dst, dp, ssrc), s in streams.items():
        expected = s['cycles'] * 65536 + s['last_seq'] - s['first_seq'] + 1
        lost = max(0, expected - s['pkts'])
        out.append({'src': f'{src}:{sp}', 'dst': f'{dst}:{dp}', 'ssrc': f'0x{ssrc:08X}', 'pt': rtp_pt_name(s['pt']),
                    'packets': s['pkts'], 'lost': lost, 'lost_pct': (lost * 100.0 / expected) if expected else 0.0,
                    'jitter_ms': s['jitter'] * 1000, 'duration': s['t1'] - s['t0']})
    return sorted(out, key=lambda x: -x['packets'])


def packet_severity(pkt):
    sev = None
    for s, grp, _msg in pkt.flat.expert:
        if grp == 'Checksum':
            s = 'note' if s == 'warning' else s
        if sev is None or SEV_ORDER[s] > SEV_ORDER[sev]:
            sev = s
    return sev


def collect_expert(packets):
    rows = []
    for p in packets:
        for sev, grp, msg in p.flat.expert:
            rows.append({'no': p.number, 'severity': sev, 'group': grp, 'summary': msg, 'protocol': p.summary['protocol']})
    rows.sort(key=lambda r: (-SEV_ORDER[r['severity']], r['group'], r['no']))
    return rows


def follow_stream_text(analysis, packets_by_stream_id, stream_id):
    """Returns [(direction 0/1, bytes)] for a TCP stream, skipping retransmissions."""
    st = analysis.stream_list[stream_id]
    out = []
    for pkt, d in st['pkts']:
        f = pkt.flat
        if f.f.get('tcp.analysis.retransmission') or f.f.get('tcp.analysis.spurious_retransmission'):
            continue
        s, e = f.payload
        if e > s:
            data = bytes(pkt.raw[s:e])
            if out and out[-1][0] == d:
                out[-1] = (d, out[-1][1] + data)
            else:
                out.append((d, data))
    return st, out


# ---- display-filter language ------------------------------------------------------------------------

_IDENT_RE = re.compile(r'[A-Za-z0-9_.:/\-]')
_NUM_RE = re.compile(r'^-?\d+(\.\d+)?$')
_HEX_RE = re.compile(r'^0x[0-9a-fA-F]+$')


class ParseError(Exception):
    pass


def tokenize(src):
    toks, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c.isspace():
            i += 1
            continue
        if c in '(){}':
            toks.append((c, None))
            i += 1
            continue
        if c in ('"', "'"):
            j, s = i + 1, ''
            while j < n and src[j] != c:
                s += src[j]
                j += 1
            toks.append(('STR', s))
            i = j + 1
            continue
        for lit, name in (('&&', 'AND'), ('||', 'OR'), ('==', 'EQ'), ('!=', 'NE'), ('>=', 'GE'), ('<=', 'LE')):
            if src.startswith(lit, i):
                toks.append((name, None))
                i += 2
                break
        else:
            if c == '>':
                toks.append(('GT', None)); i += 1; continue
            if c == '<':
                toks.append(('LT', None)); i += 1; continue
            if c == '!':
                toks.append(('NOT', None)); i += 1; continue
            if _IDENT_RE.match(c):
                j, s = i, ''
                while j < n and _IDENT_RE.match(src[j]):
                    s += src[j]
                    j += 1
                low = s.lower()
                if low == 'and':
                    toks.append(('AND', None))
                elif low == 'or':
                    toks.append(('OR', None))
                elif low == 'not':
                    toks.append(('NOT', None))
                elif low == 'contains':
                    toks.append(('CONTAINS', None))
                elif low == 'in':
                    toks.append(('IN', None))
                elif _HEX_RE.match(s):
                    toks.append(('NUM', float(int(s, 16))))
                elif _NUM_RE.match(s):
                    toks.append(('NUM', float(s)))
                else:
                    toks.append(('IDENT', low))
                i = j
                continue
            i += 1
            continue
        if toks and toks[-1][0] in ('AND', 'OR', 'EQ', 'NE', 'GE', 'LE') and False:
            pass
    return toks


def parse_filter(src):
    toks = tokenize(src)
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def eat(t):
        cur = peek()
        if cur and cur[0] == t:
            pos[0] += 1
            return cur
        return None

    def parse_or():
        left = parse_and()
        while peek() and peek()[0] == 'OR':
            eat('OR')
            left = {'op': 'or', 'left': left, 'right': parse_and()}
        return left

    def parse_and():
        left = parse_not()
        while peek() and peek()[0] == 'AND':
            eat('AND')
            left = {'op': 'and', 'left': left, 'right': parse_not()}
        return left

    def parse_not():
        if peek() and peek()[0] == 'NOT':
            eat('NOT')
            return {'op': 'not', 'expr': parse_not()}
        return parse_comparison()

    def parse_comparison():
        cur = peek()
        if cur and cur[0] == '(':
            eat('(')
            e = parse_or()
            if not eat(')'):
                raise ParseError()
            return e
        if cur and cur[0] == 'STR':
            eat('STR')
            return {'op': 'global_contains', 'value': cur[1]}
        if cur and cur[0] == 'CONTAINS':
            eat('CONTAINS')
            vt = peek()
            if not vt:
                raise ParseError()
            eat(vt[0])
            return {'op': 'global_contains', 'value': vt[1]}
        if not cur or cur[0] != 'IDENT':
            raise ParseError()
        eat('IDENT')
        field = cur[1]
        op_tok = peek()
        if op_tok and op_tok[0] in ('EQ', 'NE', 'GT', 'LT', 'GE', 'LE'):
            eat(op_tok[0])
            val_tok = peek()
            if val_tok and val_tok[0] in ('NUM', 'STR', 'IDENT'):
                eat(val_tok[0])
                return {'op': 'cmp', 'field': field, 'cmp': op_tok[0], 'value': val_tok[1]}
            raise ParseError()
        if op_tok and op_tok[0] == 'CONTAINS':
            eat('CONTAINS')
            val_tok = peek()
            if not val_tok:
                raise ParseError()
            eat(val_tok[0])
            return {'op': 'field_contains', 'field': field, 'value': val_tok[1]}
        if op_tok and op_tok[0] == 'IN':
            eat('IN')
            if not eat('{'):
                raise ParseError()
            vals = []
            while peek() and peek()[0] in ('NUM', 'STR', 'IDENT'):
                vals.append(peek()[1])
                eat(peek()[0])
            if not eat('}'):
                raise ParseError()
            return {'op': 'in', 'field': field, 'values': vals}
        return {'op': 'exists', 'field': field}

    ast = parse_or()
    if pos[0] != len(toks):
        raise ParseError()
    return ast


PROTO_ALIAS = {'ssl': 'tls', 'bootp': 'dhcp', 'ipv4': 'ip', 'frame': 'eth'}


def resolve_field(pkt, name):
    f = pkt.flat
    m = {
        'ip.addr': lambda: [f.ip_src, f.ip_dst] if f.ip_version == 4 or 'arp' in f.protocols else None,
        'ip.src': lambda: f.ip_src if f.ip_version == 4 or 'arp' in f.protocols else None,
        'ip.dst': lambda: f.ip_dst if f.ip_version == 4 or 'arp' in f.protocols else None,
        'ipv6.src': lambda: f.ip_src if f.ip_version == 6 else None,
        'ipv6.dst': lambda: f.ip_dst if f.ip_version == 6 else None,
        'ipv6.addr': lambda: [f.ip_src, f.ip_dst] if f.ip_version == 6 else None,
        'ip.proto': lambda: f.ip_proto,
        'eth.addr': lambda: [f.eth_src, f.eth_dst], 'eth.src': lambda: f.eth_src, 'eth.dst': lambda: f.eth_dst,
        'tcp.port': lambda: [f.tcp_sport, f.tcp_dport] if f.tcp else None,
        'tcp.srcport': lambda: f.tcp_sport, 'tcp.dstport': lambda: f.tcp_dport,
        'udp.port': lambda: [f.udp_sport, f.udp_dport] if f.l4 == 'udp' else None,
        'udp.srcport': lambda: f.udp_sport, 'udp.dstport': lambda: f.udp_dport,
        'tcp.flags.syn': lambda: 'SYN' in f.tcp_flags, 'tcp.flags.ack': lambda: 'ACK' in f.tcp_flags,
        'tcp.flags.fin': lambda: 'FIN' in f.tcp_flags, 'tcp.flags.reset': lambda: 'RST' in f.tcp_flags,
        'tcp.flags.rst': lambda: 'RST' in f.tcp_flags, 'tcp.flags.push': lambda: 'PSH' in f.tcp_flags,
        'tcp.flags.psh': lambda: 'PSH' in f.tcp_flags, 'tcp.flags.urg': lambda: 'URG' in f.tcp_flags,
        'dns.name': lambda: f.dns_name, 'tls.sni': lambda: f.tls_sni,
        'frame.len': lambda: pkt.length, 'frame.length': lambda: pkt.length, 'frame.number': lambda: pkt.number,
        'frame.time_relative': lambda: float(pkt.summary.get('rel_time') or 0),
        'frame': lambda: bytes(pkt.raw),
        'tcp.payload': lambda: bytes(pkt.raw[f.payload[0]:f.payload[1]]) if f.tcp else None,
        'udp.payload': lambda: bytes(pkt.raw[f.payload[0]:f.payload[1]]) if f.l4 == 'udp' else None,
        'ip.stream': lambda: f.stream,
    }
    if name in m:
        return m[name]()
    if name == 'icmp.type':
        return f.f.get('icmp.type')
    if name in f.f:
        return f.f[name]
    if name == 'tls.handshake.extensions_server_name':
        return f.tls_sni
    return None


def _coerce(a, b):
    try:
        if isinstance(a, bool) or isinstance(b, bool):
            return float(bool(a)), float(bool(b) if not isinstance(b, str) else b not in ('false', '0'))
        if isinstance(a, (int, float)) or isinstance(b, (int, float)):
            return float(a), float(b)
    except (TypeError, ValueError):
        pass
    return str(a if a is not None else '').lower(), str(b if b is not None else '').lower()


def _cmp_op(a, b, op):
    if a is None:
        return op == 'NE'
    if isinstance(b, str) and '/' in b and op in ('EQ', 'NE'):
        try:
            import ipaddress
            hit = ipaddress.ip_address(str(a)) in ipaddress.ip_network(b, strict=False)
            return hit if op == 'EQ' else not hit
        except ValueError:
            pass
    x, y = _coerce(a, b)
    return {'EQ': x == y, 'NE': x != y, 'GT': x > y, 'LT': x < y, 'GE': x >= y, 'LE': x <= y}.get(op, False) \
        if type(x) is type(y) else (op == 'NE')


def _text_haystack(pkt):
    s = pkt.summary
    return f"{s['info']} {s['src']} {s['dst']} {s['protocol']}".lower()


def eval_ast(ast, pkt):
    op = ast['op']
    if op == 'and':
        return eval_ast(ast['left'], pkt) and eval_ast(ast['right'], pkt)
    if op == 'or':
        return eval_ast(ast['left'], pkt) or eval_ast(ast['right'], pkt)
    if op == 'not':
        return not eval_ast(ast['expr'], pkt)
    if op == 'global_contains':
        return str(ast['value']).lower() in _text_haystack(pkt)
    if op == 'exists':
        field = ast['field']
        if '.' not in field and field != 'frame':
            return PROTO_ALIAS.get(field, field) in pkt.flat.protocols
        v = resolve_field(pkt, field)
        if isinstance(v, list):
            return any(x not in (None, False) for x in v)
        return v is not None and v is not False and v != b''
    if op == 'cmp':
        v = resolve_field(pkt, ast['field'])
        if isinstance(v, list):
            if ast['cmp'] == 'NE':
                return all(_cmp_op(x, ast['value'], 'NE') for x in v)
            return any(_cmp_op(x, ast['value'], ast['cmp']) for x in v)
        return _cmp_op(v, ast['value'], ast['cmp'])
    if op == 'in':
        v = resolve_field(pkt, ast['field'])
        vs = v if isinstance(v, list) else [v]
        return any(_cmp_op(x, val, 'EQ') for x in vs for val in ast['values'])
    if op == 'field_contains':
        v = resolve_field(pkt, ast['field'])
        if isinstance(v, (bytes, bytearray)):
            return str(ast['value']).encode('utf-8', 'ignore').lower() in bytes(v).lower()
        hay = ' '.join(str(x) for x in v) if isinstance(v, list) else str(v if v is not None else '')
        return str(ast['value']).lower() in hay.lower()
    return False


def build_filter(text):
    """Returns (predicate_fn, mode) where mode is 'all' | 'expr' | 'plain'."""
    trimmed = text.strip()
    if not trimmed:
        return (lambda pkt: True), 'all'
    try:
        ast = parse_filter(trimmed)

        def fn(pkt, _ast=ast):
            try:
                return eval_ast(_ast, pkt)
            except Exception:
                return False
        return fn, 'expr'
    except Exception:
        needle = trimmed.lower()
        return (lambda pkt: needle in _text_haystack(pkt)), 'plain'


# ---- live capture via scapy (optional, lazily imported) -----------------------------------------------------------

class LiveCaptureError(Exception):
    pass


_INSTALL_HINT = "scapy is required for live capture. Install it with:  pip install scapy"


def is_scapy_available():
    try:
        import scapy.all  # noqa: F401
        return True
    except Exception:
        return False


def list_interfaces():
    try:
        from scapy.all import get_if_list
    except Exception as e:
        raise LiveCaptureError(_INSTALL_HINT) from e
    try:
        return get_if_list()
    except Exception as e:
        raise LiveCaptureError(f"Could not list network interfaces: {e}") from e


class LiveCapture:
    """Runs scapy.sniff() in a background thread. poll() drains captured (ts_sec, ts_usec, raw) tuples."""

    def __init__(self, iface=None, bpf_filter=None, count=0):
        self.iface, self.bpf_filter, self.count = iface, bpf_filter, count
        self._queue = queue.Queue()
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if not is_scapy_available():
            raise LiveCaptureError(_INSTALL_HINT)
        self._stop_event = threading.Event()
        self._queue = queue.Queue()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def _run(self):
        from scapy.all import sniff
        captured = 0

        def on_packet(pkt):
            nonlocal captured
            try:
                raw = bytes(pkt)
                ts = float(pkt.time)
                ts_sec = int(ts)
                self._queue.put((ts_sec, int(round((ts - ts_sec) * 1e6)), raw))
                captured += 1
            except Exception:
                pass

        try:
            while not self._stop_event.is_set():
                if self.count and captured >= self.count:
                    break
                sniff(iface=self.iface, filter=self.bpf_filter, prn=on_packet, store=False, timeout=1)
        except PermissionError as e:
            self._queue.put(('__error__', f"Permission denied opening interface '{self.iface}' \u2014 try running with sudo. ({e})"))
        except OSError as e:
            self._queue.put(('__error__', f"Could not capture on interface '{self.iface}': {e}"))
        except Exception as e:
            self._queue.put(('__error__', str(e)))
        finally:
            self._queue.put(('__done__', None))

    def poll(self, max_items=500):
        packets, error, done = [], None, False
        for _ in range(max_items):
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            if isinstance(item, tuple) and len(item) == 2 and item[0] == '__error__':
                error = item[1]
            elif isinstance(item, tuple) and len(item) == 2 and item[0] == '__done__':
                done = True
            else:
                packets.append(item)
        return packets, error, done


# ============================================================================
# PART 8 -- pure app-state logic (no GUI-toolkit calls -- unit-testable)
# ============================================================================

THEMES = {
    'dark': {
        'bg': '#0e0f12', 'panel': '#15171b', 'panel_alt': '#1b1e23', 'input_bg': '#101216',
        'hover': '#20242a', 'selected': '#3a1b22', 'border': '#262a30', 'border_soft': '#1e2126',
        'text': '#e6e7ea', 'text_dim': '#9299a3', 'text_faint': '#5b6169',
        'accent': '#e0334f', 'accent_hover': '#ef4d68', 'danger': '#ff5c5c', 'warn': '#f0b429', 'success': '#34c78e',
        'zebra': '#171a1e', 'statusbar': '#e0334f', 'statusbar_text': '#ffffff',
        'tab_active': '#0e0f12', 'tab_inactive': '#1b1e23',
    },
    'light': {
        'bg': '#f7f7f8', 'panel': '#ffffff', 'panel_alt': '#eef0f2', 'input_bg': '#ffffff',
        'hover': '#f0f1f3', 'selected': '#fbe3e7', 'border': '#e2e4e8', 'border_soft': '#ebedf0',
        'text': '#16181c', 'text_dim': '#62666d', 'text_faint': '#9a9ea5',
        'accent': '#d1263f', 'accent_hover': '#b31f34', 'danger': '#c81e1e', 'warn': '#a15c00', 'success': '#1f9d68',
        'zebra': '#fafafb', 'statusbar': '#d1263f', 'statusbar_text': '#ffffff',
        'tab_active': '#ffffff', 'tab_inactive': '#eef0f2',
    },
}

PROTO_COLORS = {
    'dark': {
        'TCP': '#4C9FE0', 'UDP': '#3FBF9F', 'DNS': '#B07CE0', 'MDNS': '#B07CE0', 'LLMNR': '#B07CE0', 'ARP': '#E0A64C',
        'ICMP': '#E0334F', 'ICMPV6': '#E0334F', 'HTTP': '#7FC97F', 'TLS': '#E0C34C', 'SSH': '#4CC9E0', 'DHCP': '#C9A24C',
        'DHCPV6': '#C9A24C', 'IP': '#9299A3', 'IPV6': '#9299A3', 'STUN': '#F08D49', 'RTP': '#5AD1A5', 'RTCP': '#3CB4C8',
        'QUIC': '#8FA7FF', 'SIP': '#F07CB0', 'SSDP': '#C0C86A', 'NTP': '#8FBF7F', 'IGMP': '#D08A8A', 'LLDP': '#9AA5C0',
        'STP': '#9AA5C0', 'MALFORMED': '#ff5c5c', 'FTP': '#7FC97F', 'SMTP': '#7FC97F', 'POP': '#7FC97F', 'IMAP': '#7FC97F',
        'TELNET': '#7FC97F', 'ESP': '#9299A3', 'SCTP': '#4C9FE0',
    },
    'light': {
        'TCP': '#1D6FB8', 'UDP': '#1E8F76', 'DNS': '#7C3FA6', 'MDNS': '#7C3FA6', 'LLMNR': '#7C3FA6', 'ARP': '#A66A1E',
        'ICMP': '#C22540', 'ICMPV6': '#C22540', 'HTTP': '#2E7D32', 'TLS': '#8A6D1E', 'SSH': '#1E7A96', 'DHCP': '#96721E',
        'DHCPV6': '#96721E', 'IP': '#62666D', 'IPV6': '#62666D', 'STUN': '#C4630F', 'RTP': '#12876A', 'RTCP': '#0F7A8C',
        'QUIC': '#4A5FD0', 'SIP': '#B0306F', 'SSDP': '#7C8420', 'NTP': '#4A7A3A', 'IGMP': '#A04A4A', 'LLDP': '#54607F',
        'STP': '#54607F', 'MALFORMED': '#C81E1E', 'FTP': '#2E7D32', 'SMTP': '#2E7D32', 'POP': '#2E7D32', 'IMAP': '#2E7D32',
        'TELNET': '#2E7D32', 'ESP': '#62666D', 'SCTP': '#1D6FB8',
    },
}
DEFAULT_PROTO_COLOR = {'dark': '#9299A3', 'light': '#62666D'}
LAYER_PALETTE = {
    'dark': ['#4CC9E0', '#B07CE0', '#E0C34C', '#3FBF9F', '#4C9FE0', '#E0A64C'],
    'light': ['#1E7A96', '#7C3FA6', '#8A6D1E', '#1E8F76', '#1D6FB8', '#A66A1E'],
}
MONOSPACE_STACK = ['SF Mono', 'Menlo', 'Consolas', 'Cascadia Mono', 'DejaVu Sans Mono', 'Courier New', 'Courier']
UI_FONT_STACK = ['Inter', 'Segoe UI', 'SF Pro Text', 'Helvetica Neue', 'Ubuntu', 'Arial']


def theme_colors(theme):
    return THEMES.get(theme, THEMES['dark'])


def proto_key(proto):
    """Normalizes a protocol label (e.g. 'TLSv1.2', 'DTLS') to a colour-table / Treeview-tag key."""
    p = (proto or '').upper()
    if p.startswith('TLSV') or p.startswith('SSLV') or p in ('DTLS', 'SSL'):
        return 'TLS'
    return p.replace('.', '_').replace(' ', '_')


def proto_color(proto, theme='dark'):
    table = PROTO_COLORS.get(theme, PROTO_COLORS['dark'])
    return table.get(proto_key(proto), DEFAULT_PROTO_COLOR.get(theme, '#9299A3'))


def layer_color(index, theme='dark'):
    palette = LAYER_PALETTE.get(theme, LAYER_PALETTE['dark'])
    return palette[index % len(palette)]


class AppState:
    def __init__(self, export_dir='.'):
        self.packets = []
        self.filtered = []
        self.filter_text = ''
        self.filter_mode = 'all'
        self.status = ''
        self.status_is_error = False
        self.source_label = '(no capture loaded)'
        self.live = None
        self.capturing = False
        self.export_dir = export_dir
        self.save_pcap_path = None
        self.theme = 'dark'
        self.marked = set()
        self.analysis = Analysis()
        self.warnings = []
        self.meta = {}


def toggle_mark(state, number):
    if number in state.marked:
        state.marked.discard(number)
        return False
    state.marked.add(number)
    return True


def apply_filter(state):
    fn, mode = build_filter(state.filter_text)
    state.filtered = [p for p in state.packets if fn(p)]
    state.filter_mode = mode


def safe_decode(rp):
    """decode_frame that never raises: a dissector bug becomes an expert-info error on that packet instead."""
    try:
        return decode_frame(rp)
    except Exception as e:  # pragma: no cover - defensive
        flat = Flat()
        flat.warn('error', 'Malformed', f'Dissector error: {type(e).__name__}: {e}')
        layers = [{'name': f'Frame {rp.number}', 'fields': [('Frame length', f'{rp.orig_len} bytes')], 'range': (0, 0)}]
        return DecodedPacket(rp.number, rp.ts_sec, rp.ts_usec, rp.orig_len, layers, rp.data, flat,
                             {'no': rp.number, 'src': '', 'dst': '', 'protocol': 'MALFORMED', 'length': rp.orig_len,
                              'info': f'Dissector error: {e}', 'dir': ''}, rp)


def _finalize_load(state, raw_packets, label):
    reset_dissector_state()
    state.analysis.reset()
    decoded = []
    for rp in raw_packets:
        d = safe_decode(rp)
        state.analysis.feed(d)
        decoded.append(d)
    state.analysis.finish(decoded)
    state.packets = decoded
    state.marked = set()
    state.source_label = label
    state.warnings = list(LAST_PARSE_WARNINGS)
    state.meta = dict(CAPTURE_META)
    apply_filter(state)


def load_file_into_state(state, path):
    with open(os.path.expanduser(path), 'rb') as f:
        buf = f.read()
    _lt, raw_packets = parse_capture_bytes(buf)
    _finalize_load(state, raw_packets, os.path.basename(path))
    return len(raw_packets)


def load_bytes_into_state(state, buf, label):
    _lt, raw_packets = parse_capture_bytes(buf)
    _finalize_load(state, raw_packets, label)
    return len(raw_packets)


def ingest_live_packets(state, items):
    """items: iterable of (ts_sec, ts_usec, raw_bytes) as produced by LiveCapture.poll()."""
    if not items:
        return 0
    for ts_sec, ts_usec, raw in items:
        rp = RawPacket(len(state.packets) + 1, ts_sec, ts_usec, len(raw), len(raw), raw, 1)
        d = safe_decode(rp)
        state.analysis.feed(d)
        state.packets.append(d)
    apply_filter(state)
    if state.save_pcap_path:
        try:
            _append_to_pcap(state.save_pcap_path, items)
        except Exception:
            pass
    return len(items)


def finish_live(state):
    """Call when a live capture stops: runs the whole-capture passes (RTP detection, unanswered pings)."""
    n = refine_rtp(state.packets)
    state.analysis.finish(state.packets)
    apply_filter(state)
    return n


def _append_to_pcap(path, items):
    if not os.path.exists(path):
        write_pcap(path, list(items))
        return
    with open(path, 'ab') as f:
        for sec, usec, raw in items:
            f.write(struct.pack('<IIII', int(sec), int(usec), len(raw), len(raw)))
            f.write(raw)


# ---- exports -----------------------------------------------------------------------------------------------

def export_csv_to_path(state, path):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])
        for p in state.filtered:
            s = p.summary
            w.writerow([s['no'], s.get('rel_time', ''), s['src'], s['dst'], s['protocol'], s['length'], s['info']])
    return path


def export_pcap_to_path(state, path):
    write_pcap(path, [(p.ts_sec, p.ts_usec, bytes(p.raw)) for p in state.filtered])
    return path


def _fields_to_json(fields):
    out = []
    for fld in fields:
        item = {'name': fld[0], 'value': fld[1]}
        if len(fld) > 2 and fld[2]:
            item['children'] = _fields_to_json(fld[2])
        out.append(item)
    return out


def packet_to_dict(p):
    return {'number': p.number, 'time': p.summary.get('rel_time'), 'source': p.summary['src'], 'destination': p.summary['dst'],
            'protocol': p.summary['protocol'], 'length': p.length, 'info': p.summary['info'],
            'expert': [{'severity': s, 'group': g, 'message': m} for s, g, m in p.flat.expert],
            'layers': [{'name': l['name'], 'fields': _fields_to_json(l['fields'])} for l in p.layers],
            'hex': bytes(p.raw).hex()}


def export_json_to_path(state, path):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump([packet_to_dict(p) for p in state.filtered], f, indent=1, ensure_ascii=False)
    return path


def default_export_filename(ext='csv'):
    return f"fathom-export-{int(time.time())}.{ext}"


# ---- hex view / statistics / sorting --------------------------------------------------------------------------

def build_hex_lines(raw_bytes, layers):
    byte_layer = {}
    for i, layer in enumerate(layers):
        start, end = layer['range']
        for off in range(start, end):
            byte_layer[off] = i
    lines, n = [], len(raw_bytes)
    for row_start in range(0, n, 16):
        hex_segments, ascii_segments = [], []
        for i in range(16):
            off = row_start + i
            if off < n:
                b = raw_bytes[off]
                li = byte_layer.get(off)
                hex_segments.append((f'{b:02x} ', li))
                ascii_segments.append((chr(b) if 32 <= b <= 126 else '.', li))
            else:
                hex_segments.append(('   ', None))
                ascii_segments.append((' ', None))
            if i == 7:
                hex_segments.append((' ', None))
        lines.append({'offset': f'{row_start:04x}', 'hex': hex_segments, 'ascii': ascii_segments})
    return lines


def build_stats_summary(packets):
    proto_counts, total_bytes, convos = {}, 0, {}
    for p in packets:
        proto_counts[p.summary['protocol']] = proto_counts.get(p.summary['protocol'], 0) + 1
        total_bytes += p.length
        s, d = p.summary['src'], p.summary['dst']
        if s and d:
            key = tuple(sorted([str(s), str(d)]))
            c = convos.setdefault(key, {'packets': 0, 'bytes': 0})
            c['packets'] += 1
            c['bytes'] += p.length
    return {'total_packets': len(packets), 'total_bytes': total_bytes,
            'protocols': sorted(proto_counts.items(), key=lambda kv: -kv[1]),
            'conversations': sorted(convos.items(), key=lambda kv: -kv[1]['bytes'])[:15],
            'rtp_streams': build_rtp_streams(packets)}


SORT_COLUMNS = ('no', 'time', 'src', 'dst', 'proto', 'dir', 'len', 'info')


def _sort_key(pkt, column):
    s = pkt.summary
    return {'no': pkt.number, 'time': pkt.ts_sec + pkt.ts_usec / 1e6, 'src': str(s.get('src') or ''),
            'dst': str(s.get('dst') or ''), 'proto': str(s.get('protocol') or ''), 'dir': str(s.get('dir') or ''), 'len': pkt.length,
            'info': str(s.get('info') or '')}.get(column, 0)


def sort_packets(packets, column, reverse=False):
    if column not in SORT_COLUMNS:
        return list(packets)
    try:
        return sorted(packets, key=lambda p: _sort_key(p, column), reverse=reverse)
    except TypeError:
        return sorted(packets, key=lambda p: str(_sort_key(p, column)), reverse=reverse)


def format_absolute_time(ts_sec, ts_usec):
    try:
        d = datetime.fromtimestamp(ts_sec)
    except (OverflowError, OSError, ValueError):
        return f'{ts_sec}.{ts_usec:06d}'
    return f"{d.strftime('%Y-%m-%d %H:%M:%S')}.{ts_usec:06d}"


def display_time(pkt, absolute=False):
    return format_absolute_time(pkt.ts_sec, pkt.ts_usec) if absolute else pkt.summary.get('rel_time', '')


def find_matches(displayed_packets, query):
    if not query:
        return []
    q = query.lower()
    return [i for i, p in enumerate(displayed_packets) if q in _text_haystack(p)]


def quick_filter_for_source(pkt):
    if pkt.flat.ip_src:
        return f'ip.addr=={pkt.flat.ip_src}' if pkt.flat.ip_version != 6 else f'ipv6.addr=={pkt.flat.ip_src}'
    return f'eth.addr=={pkt.flat.eth_src}' if pkt.flat.eth_src else ''


def quick_filter_for_destination(pkt):
    if pkt.flat.ip_dst:
        return f'ip.addr=={pkt.flat.ip_dst}' if pkt.flat.ip_version != 6 else f'ipv6.addr=={pkt.flat.ip_dst}'
    return f'eth.addr=={pkt.flat.eth_dst}' if pkt.flat.eth_dst else ''


def quick_filter_for_conversation(pkt):
    a = pkt.flat.ip_src or pkt.flat.eth_src
    b = pkt.flat.ip_dst or pkt.flat.eth_dst
    if not a or not b:
        return ''
    field = ('ipv6.addr' if pkt.flat.ip_version == 6 else 'ip.addr') if pkt.flat.ip_src else 'eth.addr'
    return f'{field}=={a} and {field}=={b}'


def quick_filter_for_stream(pkt):
    if pkt.flat.stream is None:
        return ''
    return f'tcp.stream=={pkt.flat.stream}' if pkt.flat.tcp else f'udp.stream=={pkt.flat.stream}'


def quick_filter_for_protocol(pkt):
    return proto_key(pkt.summary['protocol']).lower() if proto_key(pkt.summary['protocol']) != 'TLS' else 'tls'


# ---- recent files --------------------------------------------------------------------------------------------------

def _recent_files_path():
    return os.path.expanduser('~/.fathom_recent_files.json')


def load_recent_files(limit=8):
    try:
        with open(_recent_files_path(), 'r') as f:
            data = json.load(f)
        if isinstance(data, list):
            return [str(p) for p in data if isinstance(p, str)][:limit]
    except Exception:
        pass
    return []


def save_recent_files(paths, limit=8):
    try:
        with open(_recent_files_path(), 'w') as f:
            json.dump(list(paths)[:limit], f)
    except Exception:
        pass


def add_recent_file(paths, path, limit=8):
    path = os.path.abspath(os.path.expanduser(path))
    updated = [p for p in paths if p != path]
    updated.insert(0, path)
    updated = updated[:limit]
    save_recent_files(updated, limit)
    return updated


# ---- text-mode output (no GUI) --------------------------------------------------------------------------------------

def _print_fields(fields, indent, out):
    for fld in fields:
        label, value = fld[0], fld[1]
        out.write('    ' * indent + field_text(label, value) + '\n')
        if len(fld) > 2 and fld[2]:
            _print_fields(fld[2], indent + 1, out)


def print_packet_list(state, verbose=False, out=None):
    out = out or sys.stdout
    for p in state.filtered:
        s = p.summary
        out.write(f"{s['no']:>6} {s.get('rel_time', ''):>11} {str(s['src']):<24} \u2192 {str(s['dst']):<24} "
                  f"{s['protocol']:<9} {s['length']:>5} {s['info']}\n")
        if verbose:
            for layer in p.layers:
                out.write(f"  {layer['name']}{layer.get('summary', '')}\n")
                _print_fields(layer['fields'], 2, out)
            out.write('\n')


def print_pcapng_info(state, out=None):
    """Diagnostic view of the capture-file container: every block/option kind found, incl. Apple process data."""
    out = out or sys.stdout
    meta = state.meta or {}
    w = out.write
    w(f"Format: {meta.get('format', '?')}   packets: {len(state.packets):,}   sections: {len(meta.get('sections', []))}   "
      f"interfaces: {len(meta.get('interfaces', []))}   byte order: {'big' if meta.get('big_endian') else 'little'}-endian\n")
    for it in meta.get('interfaces', []):
        w(f"  interface {it['id']} (section {it['section']}): {it.get('name')}  link type {it['link_type']}  snaplen {it['snaplen']}  tsresol {it['tsresol']}\n")
    procs = meta.get('processes', [])
    counts = collections.Counter(p.flat.f.get('frame.proc.id') for p in state.packets if p.flat.f.get('frame.proc.id') is not None)
    w(f"\nApple Darwin process blocks (type 0x80000001): {len(procs)}\n")
    for p in procs:
        w(f"  [{p['section']}:{p['index']}] pid {p['pid']:<7} {str(p['name']):<24} uuid {p['uuid']}   packets attributed: {counts.get(p['pid'], 0):,}\n")
    opts = meta.get('epb_options', {})
    w(f"\nOther per-packet (EPB) options found: {len(opts)} kinds\n")
    w("  code     count   lengths   sample values (hex)\n")
    names = {0x8001: 'Apple: process index', 0x8002: 'Apple: service class', 0x8003: 'Apple: effective process index',
             0x8004: 'Apple: Darwin flags (0x1 new flow, 0x2 keep-alive, 0x4 retransmit, 0x8 socket, 0x10 nexus channel, 0x20 wake)',
             0x8005: 'Apple: flow id', 0x800a: 'Apple: trace tag (Wireshark: frame.darwin.trace_tag)'}
    for code in sorted(opts):
        o = opts[code]
        w(f"  0x{code:04x} {o['count']:>8}   {','.join(str(x) for x in sorted(o['lengths'])):<8}  {' | '.join(o['samples'][:4])}   {names.get(code, '')}\n")
    if meta.get('unknown_blocks'):
        w("\nBlock types Fathom does not decode: " + ', '.join(f"0x{k:08x} x{v}" for k, v in meta['unknown_blocks'].items()) + "\n")
    w("\n(If a code above is not labelled but Wireshark shows data for it, send me this output so I can map it.)\n")


def print_expert(state, out=None):
    out = out or sys.stdout
    rows = collect_expert(state.packets)
    counts = {}
    for r in rows:
        counts[r['severity']] = counts.get(r['severity'], 0) + 1
    out.write('Expert Information: ' + ', '.join(f'{k}={v}' for k, v in sorted(counts.items(), key=lambda kv: -SEV_ORDER[kv[0]])) + '\n')
    for r in rows:
        out.write(f"{r['severity'].upper():<8} {r['group']:<14} pkt {r['no']:<6} {r['protocol']:<8} {r['summary']}\n")


# ============================================================================
# PART 8b -- statistics model and charts (pure Python; renders to Tk canvas *and* to SVG/HTML)
# ============================================================================

PROTO_PRETTY = {
    'eth': 'Ethernet', 'vlan': '802.1Q VLAN', 'mpls': 'MPLS', 'ip': 'Internet Protocol Version 4', 'ipv6': 'Internet Protocol Version 6',
    'arp': 'Address Resolution Protocol', 'udp': 'User Datagram Protocol', 'tcp': 'Transmission Control Protocol',
    'icmp': 'Internet Control Message Protocol', 'icmpv6': 'ICMPv6', 'igmp': 'IGMP', 'dns': 'Domain Name System',
    'mdns': 'Multicast DNS', 'llmnr': 'LLMNR', 'dhcp': 'DHCP', 'dhcpv6': 'DHCPv6', 'ntp': 'Network Time Protocol',
    'http': 'Hypertext Transfer Protocol', 'tls': 'Transport Layer Security', 'dtls': 'Datagram TLS', 'quic': 'QUIC IETF',
    'stun': 'STUN / TURN', 'rtp': 'Real-Time Transport Protocol', 'rtcp': 'RTP Control Protocol', 'sip': 'Session Initiation Protocol',
    'ssdp': 'Simple Service Discovery', 'ssh': 'SSH', 'lldp': 'LLDP', 'stp': 'Spanning Tree', 'esp': 'IPsec ESP', 'sctp': 'SCTP',
    'ftp': 'FTP', 'smtp': 'SMTP', 'pop': 'POP3', 'imap': 'IMAP', 'telnet': 'Telnet', 'eapol': '802.1X', 'darwin': 'Apple Darwin metadata',
}

# ---- number / size formatting -------------------------------------------------------------------------------

def fmt_count(v):
    v = float(v)
    for unit, div in (('G', 1e9), ('M', 1e6), ('k', 1e3)):
        if abs(v) >= div:
            s = f'{v / div:.1f}'
            return (s[:-2] if s.endswith('.0') else s) + unit
    return f'{v:.0f}' if abs(v - round(v)) < 0.05 else f'{v:.1f}'


def fmt_size(b):
    b = float(b)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if abs(b) < 1024 or unit == 'TB':
            return f'{b:.0f} {unit}' if unit == 'B' else f'{b:.1f} {unit}'
        b /= 1024.0


def fmt_bitrate(bps):
    for unit, div in (('Gbit/s', 1e9), ('Mbit/s', 1e6), ('kbit/s', 1e3)):
        if bps >= div:
            return f'{bps / div:.2f} {unit}'
    return f'{bps:.0f} bit/s'


def fmt_dur(s):
    if s < 1:
        return f'{s * 1000:.1f} ms'
    if s < 120:
        return f'{s:.2f} s'
    m, sec = divmod(int(s), 60)
    h, m = divmod(m, 60)
    return f'{h}h {m:02d}m {sec:02d}s' if h else f'{m}m {sec:02d}s'


def fmt_ms(seconds):
    return f'{seconds * 1000:.2f} ms'


def nice_scale(vmax, nticks=5):
    import math
    if vmax <= 0:
        return 1, [0, 1]
    raw = vmax / nticks
    mag = 10 ** math.floor(math.log10(raw))
    step = mag * 10
    for m in (1, 2, 2.5, 5, 10):
        if m * mag >= raw:
            step = m * mag
            break
    top = math.ceil(vmax / step - 1e-9) * step
    return step, [i * step for i in range(int(round(top / step)) + 1)]


def percentile(sorted_vals, q):
    if not sorted_vals:
        return 0.0
    return sorted_vals[min(len(sorted_vals) - 1, int(q * (len(sorted_vals) - 1) + 0.5))]


# ---- statistics model -------------------------------------------------------------------------------------------

IO_INTERVALS = [0.001, 0.01, 0.1, 0.5, 1, 2, 5, 10, 30, 60, 300, 600, 1800, 3600]
LENGTH_BUCKETS = [(0, 20), (20, 40), (40, 80), (80, 160), (160, 320), (320, 640), (640, 1280), (1280, 2560), (2560, 5120), (5120, 10 ** 9)]  # [lo, hi)
RTT_BUCKETS = [(0, 1), (1, 5), (5, 10), (10, 20), (20, 50), (50, 100), (100, 200), (200, 500), (500, 1000), (1000, 10 ** 9)]


def bucket_labels(buckets):
    """Short labels that fit under every bar: the upper bound of each bucket ('<80'), and '\u22655120' for the open-ended last one."""
    return [f'<{hi:g}' if hi < 10 ** 8 else f'\u2265{lo:g}' for lo, hi in buckets]


def auto_interval(duration):
    for iv in IO_INTERVALS:
        if duration / iv <= 150:
            return iv
    return IO_INTERVALS[-1]


def _label_proto(p):
    return 'TLS' if proto_key(p.summary['protocol']) == 'TLS' else p.summary['protocol']


def build_io(packets, interval=None, metric='packets', split='total', top=6, rate=True):
    """metric: packets | bytes | bits.  split: total | protocol | direction | problems."""
    if not packets:
        return {'interval': 1, 'nbins': 0, 'series': {}, 'order': [], 'stacked': False, 'metric': metric, 'rate': rate}
    duration = max(p.flat.t_rel for p in packets)
    interval = interval or auto_interval(duration)
    nbins = max(1, min(5000, int(duration / interval) + 1))
    weight = {'packets': lambda p: 1, 'bytes': lambda p: p.length, 'bits': lambda p: p.length * 8}[metric]
    series = collections.OrderedDict()

    def add(name, p):
        s = series.get(name)
        if s is None:
            s = series[name] = [0.0] * nbins
        s[min(nbins - 1, int(p.flat.t_rel / interval))] += weight(p)

    if split == 'protocol':
        totals = collections.Counter()
        for p in packets:
            totals[_label_proto(p)] += weight(p)
        keep = {k for k, _ in totals.most_common(top)}
        for p in packets:
            k = _label_proto(p)
            add(k if k in keep else 'Other', p)
        order = [k for k, _ in totals.most_common(top)] + (['Other'] if 'Other' in series else [])
        stacked = True
    elif split == 'direction':
        for p in packets:
            add({'inbound': 'Inbound', 'outbound': 'Outbound'}.get(p.flat.direction, 'Direction unknown'), p)
        order = [k for k in ('Inbound', 'Outbound', 'Direction unknown') if k in series]
        stacked = True
    elif split == 'problems':
        for p in packets:
            add('All packets', p)
            sev = packet_severity(p)
            if sev in ('warning', 'error'):
                add('Expert warnings / errors', p)
            if p.flat.f.get('tcp.analysis.flags'):
                add('TCP problems (retransmission, dup-ACK, loss, zero window...)', p)
        order = [k for k in ('All packets', 'Expert warnings / errors', 'TCP problems (retransmission, dup-ACK, loss, zero window...)') if k in series]
        stacked = False
    else:
        for p in packets:
            add('All packets', p)
        order, stacked = ['All packets'], False
    if rate:
        for v in series.values():
            for i in range(nbins):
                v[i] /= interval
    return {'interval': interval, 'nbins': nbins, 'series': series, 'order': order, 'stacked': stacked, 'metric': metric, 'rate': rate}


def build_protocol_hierarchy(packets):
    total_b = sum(p.length for p in packets) or 1
    counts = collections.defaultdict(lambda: [0, 0])
    kids = collections.defaultdict(set)
    for p in packets:
        path = ()
        for tok in p.flat.chain:
            parent, path = path, path + (tok,)
            counts[path][0] += 1
            counts[path][1] += p.length
            kids[parent].add(path)
    rows = []

    def walk(path, depth):
        for child in sorted(kids[path], key=lambda c: -counts[c][1]):
            pk, by = counts[child]
            rows.append({'path': child, 'depth': depth, 'name': PROTO_PRETTY.get(child[-1], child[-1].upper()),
                         'packets': pk, 'pct_packets': 100.0 * pk / max(1, len(packets)), 'bytes': by, 'pct_bytes': 100.0 * by / total_b})
            walk(child, depth + 1)
    walk((), 0)
    return rows


def _bucket_counts(values, buckets):
    out = [0] * len(buckets)
    for v in values:
        for i, (lo, hi) in enumerate(buckets):
            if lo <= v < hi:
                out[i] += 1
                break
    return out


def build_conversations(packets, kind):
    """kind: eth | ipv4 | ipv6 | tcp | udp."""
    convs = {}
    for p in packets:
        f = p.flat
        if kind == 'eth':
            if not f.eth_src:
                continue
            a, b = f.eth_src, f.eth_dst
        elif kind == 'ipv4':
            if f.ip_version != 4:
                continue
            a, b = f.ip_src, f.ip_dst
        elif kind == 'ipv6':
            if f.ip_version != 6:
                continue
            a, b = f.ip_src, f.ip_dst
        elif kind == 'tcp':
            if not f.tcp or not f.ip_src:
                continue
            a, b = f'{f.ip_src}:{f.tcp_sport}', f'{f.ip_dst}:{f.tcp_dport}'
        else:
            if f.l4 != 'udp' or not f.ip_src:
                continue
            a, b = f'{f.ip_src}:{f.udp_sport}', f'{f.ip_dst}:{f.udp_dport}'
        key = (a, b) if a <= b else (b, a)
        c = convs.get(key)
        if c is None:
            c = convs[key] = {'a': a, 'b': b, 'pk': 0, 'by': 0, 'ab_pk': 0, 'ab_by': 0, 'ba_pk': 0, 'ba_by': 0,
                              't0': f.t_rel, 't1': f.t_rel, 'stream': f.stream, 'protos': collections.Counter()}
        c['pk'] += 1
        c['by'] += p.length
        if a == c['a']:
            c['ab_pk'] += 1
            c['ab_by'] += p.length
        else:
            c['ba_pk'] += 1
            c['ba_by'] += p.length
        c['t1'] = f.t_rel
        c['protos'][p.summary['protocol']] += 1
    rows = []
    for c in convs.values():
        dur = c['t1'] - c['t0']
        rows.append({'a': c['a'], 'b': c['b'], 'packets': c['pk'], 'bytes': c['by'], 'ab_packets': c['ab_pk'], 'ab_bytes': c['ab_by'],
                     'ba_packets': c['ba_pk'], 'ba_bytes': c['ba_by'], 'start': c['t0'], 'duration': dur,
                     'bps_ab': (c['ab_by'] * 8 / dur) if dur > 0 else 0.0, 'bps_ba': (c['ba_by'] * 8 / dur) if dur > 0 else 0.0,
                     'stream': c['stream'], 'proto': c['protos'].most_common(1)[0][0]})
    rows.sort(key=lambda r: -r['bytes'])
    return rows


def build_endpoints(packets, kind):
    """kind: eth | ip | tcp | udp."""
    eps = {}
    for p in packets:
        f = p.flat
        if kind == 'eth':
            if not f.eth_src:
                continue
            a, b = f.eth_src, f.eth_dst
        elif kind == 'ip':
            if f.ip_version not in (4, 6):
                continue
            a, b = f.ip_src, f.ip_dst
        elif kind == 'tcp':
            if not f.tcp or not f.ip_src:
                continue
            a, b = f'{f.ip_src}:{f.tcp_sport}', f'{f.ip_dst}:{f.tcp_dport}'
        else:
            if f.l4 != 'udp' or not f.ip_src:
                continue
            a, b = f'{f.ip_src}:{f.udp_sport}', f'{f.ip_dst}:{f.udp_dport}'
        for addr, tx in ((a, True), (b, False)):
            e = eps.get(addr)
            if e is None:
                e = eps[addr] = {'tx_pk': 0, 'tx_by': 0, 'rx_pk': 0, 'rx_by': 0}
            e['tx_pk' if tx else 'rx_pk'] += 1
            e['tx_by' if tx else 'rx_by'] += p.length
    rows = [{'address': a, 'packets': e['tx_pk'] + e['rx_pk'], 'bytes': e['tx_by'] + e['rx_by'], 'tx_packets': e['tx_pk'],
             'tx_bytes': e['tx_by'], 'rx_packets': e['rx_pk'], 'rx_bytes': e['rx_by']} for a, e in eps.items()]
    rows.sort(key=lambda r: -r['bytes'])
    return rows


def build_statistics(packets, analysis=None, meta=None):
    """One pass over the capture producing everything the Statistics window / report needs."""
    meta = meta or {}
    n = len(packets)
    S = {'packets': n}
    total_bytes = sum(p.length for p in packets)
    duration = max((p.flat.t_rel for p in packets), default=0.0)
    S.update({'bytes': total_bytes, 'duration': duration, 'avg_size': total_bytes / n if n else 0,
              'pps': n / duration if duration > 0 else 0.0, 'bps': total_bytes * 8 / duration if duration > 0 else 0.0,
              'min_size': min((p.length for p in packets), default=0), 'max_size': max((p.length for p in packets), default=0),
              'first_time': packets[0].ts_sec if packets else 0, 'last_time': packets[-1].ts_sec if packets else 0})
    direction = {'inbound': [0, 0], 'outbound': [0, 0], None: [0, 0]}
    ifaces = collections.OrderedDict()
    proto_pk, proto_by = collections.Counter(), collections.Counter()
    truncated = broadcast = multicast = 0
    lengths = []
    ttl = collections.Counter()
    dst_tcp, dst_udp = collections.Counter(), collections.Counter()
    dns_q, dns_rc, dns_names, dns_servers = collections.Counter(), collections.Counter(), collections.Counter(), collections.Counter()
    http_m, http_s, http_h, http_ct, http_ua = (collections.Counter() for _ in range(5))
    tls_ver, tls_sni, tls_cipher, tls_ja3, tls_alpn, tls_cert, tls_alert = (collections.Counter() for _ in range(7))
    quic_ver, quic_sni = collections.Counter(), collections.Counter()
    stun_msg, stun_err, stun_srv, stun_mapped, stun_realm, stun_tr = (collections.Counter() for _ in range(6))
    rtp_pt = collections.Counter()
    dhcp_msg, dhcp_srv, dhcp_host = collections.Counter(), collections.Counter(), collections.Counter()
    icmp_t = collections.Counter()
    exp_sev, exp_grp, exp_msg = collections.Counter(), collections.Counter(), collections.Counter()
    comments = []
    proc_stats = {}
    udp_streams, udp_proto_bytes, udp_ports, udp_sizes = {}, collections.Counter(), collections.Counter(), []
    udp_dir = {'inbound': 0, 'outbound': 0, None: 0}
    udp_pk = udp_by = 0
    DHCP_T = {1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform'}
    for p in packets:
        f, L = p.flat, p.length
        d = direction[f.direction]
        d[0] += 1
        d[1] += L
        name = f.f.get('frame.interface_name', '(unknown)')
        it = ifaces.setdefault(name, [0, 0])
        it[0] += 1
        it[1] += L
        proto_pk[p.summary['protocol']] += 1
        proto_by[p.summary['protocol']] += L
        lengths.append(L)
        if p.rawinfo is not None and p.rawinfo.cap_len < p.rawinfo.orig_len:
            truncated += 1
        if f.eth_dst == 'ff:ff:ff:ff:ff:ff':
            broadcast += 1
        elif f.eth_dst and int(f.eth_dst[:2], 16) & 1:
            multicast += 1
        if f.ip_ttl is not None and f.ip_version == 4:
            ttl[f.ip_ttl] += 1
        if f.tcp and f.tcp['flags'] & 0x12 == 0x02:
            dst_tcp[f.tcp_dport] += 1
        elif f.l4 == 'udp':
            dst_udp[f.udp_dport] += 1
        fd = {} if f.f.get('icmp.inner') else f.f
        if 'dns' in f.protocols or 'mdns' in f.protocols or 'llmnr' in f.protocols:
            if fd.get('dns.flags.response') is False:
                dns_q[fd.get('dns.qry.type', '?')] += 1
                dns_names[f.dns_name or '?'] += 1
                dns_servers[f.ip_dst] += 1
            elif fd.get('dns.flags.response'):
                dns_rc[DNS_RCODES.get(fd.get('dns.flags.rcode', 0), str(fd.get('dns.flags.rcode')))] += 1
        if fd.get('http.request.method'):
            http_m[fd['http.request.method']] += 1
            if fd.get('http.host'):
                http_h[fd['http.host']] += 1
            if fd.get('http.user_agent'):
                http_ua[fd['http.user_agent'][:70]] += 1
        if fd.get('http.response.code') is not None:
            code = fd['http.response.code']
            http_s[f'{code // 100}xx'] += 1
            if fd.get('http.content_type'):
                http_ct[fd['http.content_type'].split(';')[0]] += 1
        if fd.get('tls.handshake.type') in (1, 2) or fd.get('tls.handshake.version'):
            if fd.get('tls.handshake.type') == 2 and fd.get('tls.handshake.version'):
                tls_ver[fd['tls.handshake.version']] += 1
            if fd.get('tls.handshake.ciphersuite'):
                tls_cipher[fd['tls.handshake.ciphersuite']] += 1
        if f.tls_sni and not f.f.get('icmp.inner'):
            (quic_sni if 'quic' in f.protocols else tls_sni)[f.tls_sni] += 1
        if fd.get('tls.handshake.ja3'):
            tls_ja3[fd['tls.handshake.ja3']] += 1
        for a in fd.get('tls.handshake.extensions_alpn') or []:
            tls_alpn[a] += 1
        if fd.get('tls.cert.subject'):
            tls_cert[fd['tls.cert.subject']] += 1
        if fd.get('tls.alert_message.desc') is not None:
            tls_alert[TLS_ALERTS.get(fd['tls.alert_message.desc'], str(fd['tls.alert_message.desc']))] += 1
        if fd.get('quic.version') is not None and fd.get('quic.header_form') == 1:
            quic_ver[quic_version_name(fd['quic.version'])] += 1
        if fd.get('stun.name'):
            stun_msg[fd['stun.name']] += 1
            if fd.get('stun.class') == 0:
                stun_srv[f.ip_dst] += 1
            if fd.get('stun.att.error'):
                stun_err[f"{fd['stun.att.error']} {STUN_ERRORS.get(fd['stun.att.error'], '')}".strip()] += 1
            if fd.get('stun.att.ipv4-xord') and fd.get('stun.class') == 2:
                stun_mapped[fd['stun.att.ipv4-xord']] += 1
            if fd.get('stun.att.realm'):
                stun_realm[fd['stun.att.realm']] += 1
            if fd.get('stun.att.transport'):
                stun_tr[fd['stun.att.transport']] += 1
        if 'rtp' in f.protocols and fd.get('rtp.p_type') is not None:
            rtp_pt[rtp_pt_name(fd['rtp.p_type'])] += 1
        if fd.get('dhcp.option.dhcp') is not None:
            dhcp_msg[DHCP_T.get(fd['dhcp.option.dhcp'], str(fd['dhcp.option.dhcp']))] += 1
            if fd['dhcp.option.dhcp'] in (2, 5):
                dhcp_srv[f.ip_src] += 1
            if fd.get('dhcp.option.hostname'):
                dhcp_host[fd['dhcp.option.hostname']] += 1
        if f.icmp_type is not None and 'icmp' in f.protocols:
            icmp_t[ICMP_TYPES.get(f.icmp_type, f'Type {f.icmp_type}')] += 1
        for sev, grp, msg in f.expert:
            exp_sev[sev] += 1
            exp_grp[grp] += 1
            exp_msg[(sev, grp, msg)] += 1
        if f.l4 == 'udp' and f.stream is not None and not f.f.get('icmp.inner'):
            a_ = f'{f.ip_src}:{f.udp_sport}'
            u_ = udp_streams.setdefault(f.stream, {'a': a_, 'b': f'{f.ip_dst}:{f.udp_dport}', 'pk': 0, 'by': 0, 'ab': 0, 'ba': 0,
                                                   't0': f.t_rel, 't1': f.t_rel, 'protos': collections.Counter()})
            u_['pk'] += 1
            u_['by'] += L
            u_['ab' if a_ == u_['a'] else 'ba'] += L
            u_['t1'] = f.t_rel
            u_['protos'][p.summary['protocol']] += 1
            udp_proto_bytes[p.summary['protocol']] += L
            udp_ports[min(f.udp_sport, f.udp_dport)] += L
            udp_sizes.append(L)
            udp_dir[f.direction] += L
            udp_pk += 1
            udp_by += L
        pname = f.f.get('frame.proc.name')
        if pname is not None:
            ps = proc_stats.setdefault((pname, f.f.get('frame.proc.id')), {'packets': 0, 'bytes': 0, 'out': 0, 'in': 0})
            ps['packets'] += 1
            ps['bytes'] += L
            if f.direction in ('inbound', 'outbound'):
                ps['in' if f.direction == 'inbound' else 'out'] += L
        if p.rawinfo is not None and p.rawinfo.comments:
            comments.extend((p.number, c) for c in p.rawinfo.comments)
    S['direction'] = {'inbound': direction['inbound'], 'outbound': direction['outbound'], 'unknown': direction[None]}
    S['interfaces'] = ifaces
    S['protocols_packets'], S['protocols_bytes'] = proto_pk, proto_by
    S['hierarchy'] = build_protocol_hierarchy(packets)
    S['length_hist'] = _bucket_counts(lengths, LENGTH_BUCKETS)
    S['truncated'], S['broadcast'], S['multicast'] = truncated, broadcast, multicast
    S['ttl'], S['tcp_dst_ports'], S['udp_dst_ports'] = ttl, dst_tcp, dst_udp
    S['dns'] = {'qtypes': dns_q, 'rcodes': dns_rc, 'names': dns_names, 'servers': dns_servers,
                'rtts': list(analysis.dns_rtts) if analysis else [], 'unanswered': len([1 for k, v in (analysis.dns_pending.items() if analysis else []) if 'mdns' not in v[0].flat.protocols])}
    S['http'] = {'methods': http_m, 'status': http_s, 'hosts': http_h, 'types': http_ct, 'agents': http_ua}
    S['tls'] = {'versions': tls_ver, 'sni': tls_sni, 'ciphers': tls_cipher, 'ja3': tls_ja3, 'alpn': tls_alpn, 'certs': tls_cert,
                'alerts': tls_alert, 'quic_versions': quic_ver, 'quic_sni': quic_sni}
    S['stun'] = {'messages': stun_msg, 'errors': stun_err, 'servers': stun_srv, 'mapped': stun_mapped, 'realms': stun_realm,
                 'transports': stun_tr, 'rtts': list(analysis.stun_rtts) if analysis else []}
    S['rtp'] = {'streams': build_rtp_streams(packets), 'payload_types': rtp_pt}
    S['dhcp'] = {'messages': dhcp_msg, 'servers': dhcp_srv, 'hosts': dhcp_host}
    S['icmp'] = icmp_t
    S['expert'] = {'severity': exp_sev, 'groups': exp_grp, 'messages': exp_msg.most_common(15)}
    S['comments'] = comments
    udp_rows = []
    for sid, u_ in udp_streams.items():
        dur = u_['t1'] - u_['t0']
        udp_rows.append({'stream': sid, 'a': u_['a'], 'b': u_['b'], 'proto': u_['protos'].most_common(1)[0][0], 'packets': u_['pk'],
                         'bytes': u_['by'], 'ab_bytes': u_['ab'], 'ba_bytes': u_['ba'], 'duration': dur,
                         'pps': (u_['pk'] / dur) if dur > 0 else 0.0, 'bps': (u_['by'] * 8 / dur) if dur > 0 else 0.0})
    udp_rows.sort(key=lambda r: -r['bytes'])
    S['udp'] = {'packets': udp_pk, 'bytes': udp_by, 'streams': udp_rows, 'proto_bytes': udp_proto_bytes, 'ports': udp_ports,
                'size_hist': _bucket_counts(udp_sizes, LENGTH_BUCKETS), 'dir': udp_dir}
    S['processes'] = sorted(({'name': k[0], 'pid': k[1], **v} for k, v in proc_stats.items()), key=lambda r: -r['bytes'])
    S['meta'] = meta

    # ---- TCP streams ----
    tcp_rows, states, rtt_all, irtt_all = [], collections.Counter(), [], []
    totals = collections.Counter()
    srv_ports = collections.Counter()
    for st in (analysis.stream_list if analysis else []):
        pk = sum(st['npk'])
        by = sum(pkt.length for pkt, _d in st['pkts'])
        state = tcp_stream_state(st)
        states[state] += 1
        srt = sorted(st['rtts'])
        rtt_all.extend(st['rtts'])
        if st['irtt'] is not None:
            irtt_all.append(st['irtt'])
        srv = (st['b'] if st['initiator'] in (0, None) else st['a'])
        srv_ports[srv[1] if st['initiator'] is not None else min(st['a'][1], st['b'][1])] += 1
        totals['retrans'] += st['retrans']
        totals['dup'] += st['dup']
        totals['lost'] += st['lost']
        totals['zerowin'] += st['zerowin']
        totals['rst'] += 1 if st['rst'] else 0
        totals['segments'] += pk
        tcp_rows.append({'stream': st['id'], 'a': f"{st['a'][0]}:{st['a'][1]}", 'b': f"{st['b'][0]}:{st['b'][1]}", 'packets': pk, 'bytes': by,
                         'duration': st['last'] - st['t0'], 'state': state, 'irtt': st['irtt'] if st['irtt'] is not None else -1,
                         'rtt_avg': (sum(srt) / len(srt)) if srt else -1, 'rtt_p95': percentile(srt, 0.95) if srt else -1,
                         'retrans': st['retrans'], 'dup': st['dup'], 'lost': st['lost'], 'zerowin': st['zerowin'],
                         'c2s': st['data'][0], 's2c': st['data'][1]})
    S['tcp'] = {'streams': tcp_rows, 'states': states, 'rtts': rtt_all, 'irtts': irtt_all, 'totals': totals, 'server_ports': srv_ports,
                'rtt_hist': _bucket_counts([r * 1000 for r in rtt_all], RTT_BUCKETS),
                'irtt_hist': _bucket_counts([r * 1000 for r in irtt_all], RTT_BUCKETS)}
    S['udp_streams'] = len(analysis.udp_list) if analysis else 0
    return S


# ---- plots: a tiny retained-mode drawing list that renders to Tk or SVG ------------------------------------------------

def chart_palette(theme='dark'):
    c = theme_colors(theme)
    series = ['#4C9FE0', '#E0A64C', '#3FBF9F', '#B07CE0', '#E0334F', '#7FC97F', '#4CC9E0', '#F08D49', '#F07CB0', '#8FA7FF'] \
        if theme == 'dark' else ['#1D6FB8', '#A66A1E', '#1E8F76', '#7C3FA6', '#C22540', '#2E7D32', '#1E7A96', '#C4630F', '#B0306F', '#4A5FD0']
    return {'bg': c['panel'], 'text': c['text'], 'dim': c['text_dim'], 'faint': c['text_faint'], 'grid': c['border'],
            'accent': c['accent'], 'danger': c['danger'], 'warn': c['warn'], 'series': series, 'panel_alt': c['panel_alt']}


class Plot:
    font_family = 'Helvetica'

    def __init__(self, w, h, pal):
        self.w, self.h, self.pal, self.items = w, h, pal, []

    def rect(self, x, y, w, h, fill=None, outline=None):
        self.items.append(('rect', x, y, w, h, fill, outline))

    def line(self, x1, y1, x2, y2, color, width=1, dash=False):
        self.items.append(('line', x1, y1, x2, y2, color, width, dash))

    def polyline(self, pts, color, width=1.6):
        if len(pts) >= 2:
            self.items.append(('polyline', list(pts), color, width))

    def polygon(self, pts, fill, outline=None):
        self.items.append(('polygon', list(pts), fill, outline))

    def circle(self, cx, cy, r, fill, outline=None):
        self.items.append(('circle', cx, cy, r, fill, outline))

    def wedge(self, cx, cy, r, start, extent, fill, outline=None):
        self.items.append(('wedge', cx, cy, r, start, extent, fill, outline))

    def text(self, x, y, s, color, size=9, anchor='w', bold=False):
        self.items.append(('text', x, y, str(s), color, size, anchor, bold))

    # -- Tk canvas ---------------------------------------------------------------------------------
    def draw(self, cv):
        for it in self.items:
            k = it[0]
            if k == 'rect':
                _, x, y, w, h, fill, outline = it
                cv.create_rectangle(x, y, x + w, y + h, fill=fill or '', outline=outline or '')
            elif k == 'line':
                _, x1, y1, x2, y2, color, width, dash = it
                cv.create_line(x1, y1, x2, y2, fill=color, width=width, dash=((3, 3) if dash else ()))
            elif k == 'polyline':
                _, pts, color, width = it
                cv.create_line(*[c for pt in pts for c in pt], fill=color, width=width, joinstyle='round')
            elif k == 'polygon':
                _, pts, fill, outline = it
                cv.create_polygon(*[c for pt in pts for c in pt], fill=fill or '', outline=outline or '')
            elif k == 'circle':
                _, cx, cy, r, fill, outline = it
                cv.create_oval(cx - r, cy - r, cx + r, cy + r, fill=fill or '', outline=outline or '')
            elif k == 'wedge':
                _, cx, cy, r, start, extent, fill, outline = it
                cv.create_arc(cx - r, cy - r, cx + r, cy + r, start=start, extent=extent, fill=fill, outline=outline or fill, style='pieslice')
            elif k == 'text':
                _, x, y, s, color, size, anchor, bold = it
                cv.create_text(x, y, text=s, fill=color, anchor={'w': 'w', 'e': 'e', 'c': 'center', 'n': 'n', 's': 's', 'nw': 'nw', 'ne': 'ne'}[anchor],
                               font=(self.font_family, int(size), 'bold' if bold else 'normal'))

    # -- SVG ---------------------------------------------------------------------------------------
    def to_svg(self):
        import math
        esc = html.escape
        out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" width="{self.w}" height="{self.h}" '
               f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif">',
               f'<rect width="{self.w}" height="{self.h}" fill="{self.pal["bg"]}"/>']
        for it in self.items:
            k = it[0]
            if k == 'rect':
                _, x, y, w, h, fill, outline = it
                out.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{max(0, w):.1f}" height="{max(0, h):.1f}" fill="{fill or "none"}" stroke="{outline or "none"}"/>')
            elif k == 'line':
                _, x1, y1, x2, y2, color, width, dash = it
                out.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{color}" stroke-width="{width}"'
                           + (' stroke-dasharray="3 3"' if dash else '') + '/>')
            elif k == 'polyline':
                _, pts, color, width = it
                out.append(f'<polyline points="{" ".join(f"{x:.1f},{y:.1f}" for x, y in pts)}" fill="none" stroke="{color}" stroke-width="{width}" stroke-linejoin="round"/>')
            elif k == 'polygon':
                _, pts, fill, outline = it
                out.append(f'<polygon points="{" ".join(f"{x:.1f},{y:.1f}" for x, y in pts)}" fill="{fill or "none"}" stroke="{outline or "none"}"/>')
            elif k == 'circle':
                _, cx, cy, r, fill, outline = it
                out.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}" fill="{fill or "none"}" stroke="{outline or "none"}"/>')
            elif k == 'wedge':
                _, cx, cy, r, start, extent, fill, outline = it
                if abs(extent) >= 359.9:
                    out.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}" fill="{fill}"/>')
                else:
                    a1, a2 = math.radians(start), math.radians(start + extent)
                    x1, y1 = cx + r * math.cos(a1), cy - r * math.sin(a1)
                    x2, y2 = cx + r * math.cos(a2), cy - r * math.sin(a2)
                    large = 1 if abs(extent) > 180 else 0
                    sweep = 0 if extent > 0 else 1
                    out.append(f'<path d="M{cx:.1f},{cy:.1f} L{x1:.1f},{y1:.1f} A{r:.1f},{r:.1f} 0 {large} {sweep} {x2:.1f},{y2:.1f} Z" fill="{fill}" stroke="{outline or fill}"/>')
            elif k == 'text':
                _, x, y, s, color, size, anchor, bold = it
                a = {'w': 'start', 'e': 'end', 'c': 'middle', 'n': 'middle', 's': 'middle', 'nw': 'start', 'ne': 'end'}[anchor]
                dy = {'n': 0.9, 'nw': 0.9, 'ne': 0.9, 's': 0.0}.get(anchor, 0.35)
                out.append(f'<text x="{x:.1f}" y="{y + dy * size:.1f}" fill="{color}" font-size="{size + 1}" text-anchor="{a}"'
                           + (' font-weight="bold"' if bold else '') + f'>{esc(str(s))}</text>')
        out.append('</svg>')
        return ''.join(out)


def _trunc(s, n):
    s = str(s)
    return s if len(s) <= n else s[:max(1, n - 1)] + '\u2026'


def chart_hbars(items, w, h, pal, title='', fmt=fmt_count, max_items=12, colors=None):
    """items: [(label, value)] -> horizontal bar chart."""
    p = Plot(w, h, pal)
    top = 26 if title else 8
    if title:
        p.text(10, 13, title, pal['text'], 10, 'w', True)
    items = [(l, v) for l, v in items if v is not None][:max_items]
    if not items or max(v for _, v in items) <= 0:
        p.text(w / 2, h / 2, 'no data', pal['dim'], 10, 'c')
        return p
    label_w = min(w * 0.42, max(len(str(l)) for l, _ in items) * 6.0 + 10)
    value_w = 62
    vmax = max(v for _, v in items)
    row_h = (h - top - 6) / len(items)
    bar_area = max(10, w - label_w - value_w - 18)
    for i, (label, val) in enumerate(items):
        y = top + i * row_h
        col = (colors or {}).get(label) or pal['series'][i % len(pal['series'])]
        bw = max(1, bar_area * val / vmax)
        bh = min(row_h * 0.68, 26)
        p.text(label_w, y + row_h / 2, _trunc(label, int(label_w / 6)), pal['text'], 9, 'e')
        p.rect(label_w + 8, y + (row_h - bh) / 2, bw, bh, col)
        p.text(label_w + 12 + bw, y + row_h / 2, fmt(val), pal['dim'], 9, 'w')
    return p


def chart_columns(items, w, h, pal, title='', fmt=fmt_count, color=None, y_title=''):
    """items: [(label, value)] -> vertical histogram."""
    p = Plot(w, h, pal)
    left, bottom, top, right = 46, 34, 30 if title else 12, 10
    if title:
        p.text(10, 13, title, pal['text'], 10, 'w', True)
    if not items or max(v for _, v in items) <= 0:
        p.text(w / 2, h / 2, 'no data', pal['dim'], 10, 'c')
        return p
    _, ticks = nice_scale(max(v for _, v in items), 4)
    ymax = ticks[-1] or 1
    H, W = h - top - bottom, w - left - right
    for t in ticks:
        y = top + H - H * t / ymax
        p.line(left, y, w - right, y, pal['grid'], 1, dash=t != 0)
        p.text(left - 5, y, fmt(t), pal['dim'], 8, 'e')
    slot = W / len(items)
    every = max(1, int((max(len(str(l)) for l, _ in items) * 5.0 + 4) / slot + 0.999))
    for i, (label, val) in enumerate(items):
        bh = H * val / ymax
        x = left + i * slot + slot * 0.14
        p.rect(x, top + H - bh, slot * 0.72, bh, color or pal['series'][0])
        if val:
            p.text(x + slot * 0.36, top + H - bh - 7, fmt(val), pal['dim'], 8, 'c')
        if i % every == 0:
            p.text(left + i * slot + slot / 2, top + H + 12, _trunc(label, 14), pal['dim'], 8, 'c')
    if y_title:
        p.text(w - right, h - 6, y_title, pal['faint'], 8, 'e')
    return p


def chart_donut(items, w, h, pal, title='', center='', fmt=fmt_count, colors=None, max_items=8):
    p = Plot(w, h, pal)
    top = 28 if title else 8
    if title:
        p.text(10, 13, title, pal['text'], 10, 'w', True)
    items = [(l, v) for l, v in items if v and v > 0]
    if not items:
        p.text(w / 2, h / 2, 'no data', pal['dim'], 10, 'c')
        return p
    if len(items) > max_items:
        rest = sum(v for _, v in items[max_items - 1:])
        items = items[:max_items - 1] + [('Other', rest)]
    total = float(sum(v for _, v in items))
    r = max(20, min((h - top - 8) / 2, w * 0.3))
    cx, cy = 14 + r, top + (h - top) / 2
    ang = 90.0
    for i, (label, val) in enumerate(items):
        ext = -360.0 * val / total
        p.wedge(cx, cy, r, ang, ext, (colors or {}).get(label) or pal['series'][i % len(pal['series'])], pal['bg'])
        ang += ext
    p.circle(cx, cy, r * 0.56, pal['bg'])
    if center:
        p.text(cx, cy, center, pal['text'], 10, 'c', True)
    lx = cx + r + 22
    row = min(20, (h - top - 10) / len(items))
    for i, (label, val) in enumerate(items):
        y = top + 8 + i * row
        p.rect(lx, y - 5, 10, 10, (colors or {}).get(label) or pal['series'][i % len(pal['series'])])
        p.text(lx + 15, y, f'{_trunc(label, max(6, int((w - lx - 70) / 6)))}', pal['text'], 9, 'w')
        p.text(w - 8, y, f'{100 * val / total:.1f}%  ({fmt(val)})' if w - lx > 230 else f'{100 * val / total:.1f}%', pal['dim'], 9, 'e')
    return p


def fmt_axis_time(t, interval):
    if interval >= 1 or t >= 60:
        return fmt_dur(t) if t >= 120 else f'{t:.0f}s'
    return f'{t * 1000:.0f}ms' if t < 1 else f'{t:.2f}s'


def chart_io(data, w, h, pal, title='', y_unit=None):
    """I/O graph from build_io(): stacked areas for protocol/direction splits, lines otherwise."""
    p = Plot(w, h, pal)
    left, bottom, top, right = 58, 28, 44 if title else 30, 14
    if title:
        p.text(10, 13, title, pal['text'], 10, 'w', True)
    series, order, nbins, iv = data['series'], data['order'], data['nbins'], data['interval']
    if not series or nbins == 0:
        p.text(w / 2, h / 2, 'no data', pal['dim'], 10, 'c')
        return p
    colors = {}
    for i, name in enumerate(order):
        colors[name] = pal['series'][i % len(pal['series'])]
    if 'Expert warnings / errors' in colors:
        colors['Expert warnings / errors'] = pal['warn']
        colors['TCP problems (retransmission, dup-ACK, loss, zero window...)'] = pal['danger']
    if 'Inbound' in colors:
        colors['Inbound'], colors['Outbound'] = pal['series'][2], pal['series'][0]
    # legend
    lx = left
    for name in order:
        p.rect(lx, top - 18, 10, 10, colors[name])
        lab = _trunc(name, 28)
        p.text(lx + 14, top - 13, lab, pal['text'], 8, 'w')
        lx += 14 + len(lab) * 5.3 + 14
    if data['stacked']:
        totals = [sum(series[n][i] for n in order) for i in range(nbins)]
        ymax_raw = max(totals)
    else:
        ymax_raw = max(max(series[n]) for n in order)
    _, ticks = nice_scale(ymax_raw or 1, 5)
    ymax = ticks[-1] or 1
    H, W = h - top - bottom, w - left - right

    def X(i):
        return left + (i + 0.5) / nbins * W

    def Y(v):
        return top + H - H * v / ymax
    unit = y_unit or ('packets/s' if data['metric'] == 'packets' else ('bytes/s' if data['metric'] == 'bytes' else 'bit/s'))
    if not data['rate']:
        unit = unit.replace('/s', f' per {iv:g}s bin')
    for t in ticks:
        p.line(left, Y(t), w - right, Y(t), pal['grid'], 1, dash=t != 0)
        p.text(left - 5, Y(t), fmt_count(t), pal['dim'], 8, 'e')
    p.text(6, top - 18 if not title else 28, unit, pal['faint'], 8, 'w')
    nx = min(8, nbins)
    for k in range(nx + 1):
        i = k * (nbins - 1) / max(1, nx)
        p.text(X(i), top + H + 12, fmt_axis_time(i * iv, iv), pal['dim'], 8, 'c')
    if data['stacked']:
        base = [0.0] * nbins
        for name in order:
            s = series[name]
            upper = [base[i] + s[i] for i in range(nbins)]
            pts = [(X(i), Y(upper[i])) for i in range(nbins)] + [(X(i), Y(base[i])) for i in range(nbins - 1, -1, -1)]
            p.polygon(pts, colors[name])
            base = upper
    else:
        for name in order:
            pts = [(X(i), Y(v)) for i, v in enumerate(series[name])]
            if nbins == 1:
                p.circle(pts[0][0], pts[0][1], 3, colors[name])
            p.polyline(pts, colors[name], 1.8)
    return p


def chart_timeseq(st, w, h, pal, title=''):
    """Stevens-style time/sequence graph for one TCP stream: relative sequence number vs time, per direction."""
    p = Plot(w, h, pal)
    left, bottom, top, right = 64, 30, 34, 14
    p.text(10, 13, title or f'TCP stream {st["id"]}: time / sequence graph', pal['text'], 10, 'w', True)
    pts = {0: [], 1: []}
    retr = {0: [], 1: []}
    for pkt, d in st['pkts']:
        f = pkt.flat
        if f.f.get('tcp.nxtseq') is None:
            continue
        pt = (f.t_rel, f.f['tcp.nxtseq'])
        pts[d].append(pt)
        if f.f.get('tcp.analysis.retransmission') or f.f.get('tcp.analysis.fast_retransmission'):
            retr[d].append(pt)
    allp = pts[0] + pts[1]
    if len(allp) < 2:
        p.text(w / 2, h / 2, 'not enough data', pal['dim'], 10, 'c')
        return p
    t0, t1 = min(x for x, _ in allp), max(x for x, _ in allp)
    ymax = max(y for _, y in allp) or 1
    _, yt = nice_scale(ymax, 5)
    ymax = yt[-1] or 1
    H, W = h - top - bottom, w - left - right
    X = lambda t: left + (t - t0) / max(1e-9, t1 - t0) * W
    Y = lambda v: top + H - H * v / ymax
    for t in yt:
        p.line(left, Y(t), w - right, Y(t), pal['grid'], 1, dash=t != 0)
        p.text(left - 5, Y(t), fmt_count(t), pal['dim'], 8, 'e')
    for k in range(6):
        t = t0 + (t1 - t0) * k / 5
        p.text(X(t), top + H + 12, fmt_axis_time(t - t0, t1 - t0), pal['dim'], 8, 'c')
    names = {0: f"{st['a'][0]}:{st['a'][1]} \u2192", 1: f"{st['b'][0]}:{st['b'][1]} \u2192"}
    lx = left
    for d in (0, 1):
        col = pal['series'][d]
        p.rect(lx, top - 20, 10, 10, col)
        p.text(lx + 14, top - 15, names[d], pal['text'], 8, 'w')
        lx += 14 + len(names[d]) * 5.4 + 16
        p.polyline([(X(x), Y(y)) for x, y in pts[d]], col, 1.6)
    for d in (0, 1):
        for x, y in retr[d]:
            p.circle(X(x), Y(y), 3.2, pal['danger'])
    p.rect(w - 150, top - 20, 10, 10, pal['danger'])
    p.text(w - 136, top - 15, 'retransmission', pal['text'], 8, 'w')
    return p


# ---- text / HTML output of the statistics --------------------------------------------------------------------------------

def print_statistics(S, out=None):
    out = out or sys.stdout
    w = out.write
    w(f"\n{'=' * 78}\nCAPTURE STATISTICS\n{'=' * 78}\n")
    w(f"  Packets        : {S['packets']:,}  ({fmt_size(S['bytes'])})   avg {S['avg_size']:.0f} B, min {S['min_size']}, max {S['max_size']}\n")
    w(f"  Duration       : {fmt_dur(S['duration'])}   {S['pps']:.1f} packets/s   {fmt_bitrate(S['bps'])}\n")
    di = S['direction']
    if di['inbound'][0] or di['outbound'][0]:
        w(f"  Direction      : inbound {di['inbound'][0]:,} pkts / {fmt_size(di['inbound'][1])}   outbound {di['outbound'][0]:,} pkts / {fmt_size(di['outbound'][1])}"
          f"   unknown {di['unknown'][0]:,}\n")
    for name, (pk, by) in S['interfaces'].items():
        w(f"  Interface      : {name}: {pk:,} packets, {fmt_size(by)}\n")
    w(f"  Broadcast/mcast: {S['broadcast']:,} / {S['multicast']:,}   truncated by snaplen: {S['truncated']:,}   "
      f"TCP streams: {len(S['tcp']['streams']):,}   UDP streams: {S['udp_streams']:,}\n")

    def counter_block(title, counter, n=8, fmt=str):
        if counter:
            w(f"\n  {title}\n")
            for k, v in counter.most_common(n):
                w(f"    {str(k)[:58]:<58} {fmt(v):>10}\n")

    w('\n  PROTOCOL HIERARCHY                                     packets   %pkts       bytes   %bytes\n')
    for r in S['hierarchy'][:40]:
        w(f"    {'  ' * r['depth']}{r['name'][:44 - 2 * r['depth']]:<{46 - 2 * r['depth']}} {r['packets']:>12,} {r['pct_packets']:>6.1f}% {r['bytes']:>11,} {r['pct_bytes']:>7.1f}%\n")
    ud = S['udp']
    if ud['packets']:
        w(f"\n  UDP: {ud['packets']:,} datagrams, {fmt_size(ud['bytes'])}, {len(ud['streams']):,} streams\n")
        for proto, by in ud['proto_bytes'].most_common(6):
            w(f"    {proto:<12} {fmt_size(by):>10}\n")
        for r in ud['streams'][:5]:
            w(f"    stream {r['stream']:<4} {r['a']:>22} <-> {r['b']:<22} {r['proto']:<6} {r['packets']:>7,} pkts {fmt_size(r['bytes']):>9}  {fmt_dur(r['duration'])}\n")
    t = S['tcp']
    if t['streams']:
        tt = t['totals']
        w(f"\n  TCP: {len(t['streams'])} streams, {tt['segments']:,} segments; retransmissions {tt['retrans']}, dup-ACKs {tt['dup']}, "
          f"lost-segment gaps {tt['lost']}, zero-window {tt['zerowin']}, reset streams {tt['rst']}\n")
        if t['rtts']:
            srt = sorted(t['rtts'])
            w(f"       ACK RTT: median {fmt_ms(percentile(srt, .5))}, 95th pct {fmt_ms(percentile(srt, .95))}, max {fmt_ms(srt[-1])}   ({len(srt):,} samples)\n")
        counter_block('TCP stream states', t['states'])
        counter_block('Most contacted TCP server ports', t['server_ports'], 6)
    d = S['dns']
    counter_block('DNS query types', d['qtypes'])
    counter_block('DNS response codes', d['rcodes'])
    counter_block('Top DNS names', d['names'], 10)
    if d['rtts']:
        srt = sorted(d['rtts'])
        w(f"    DNS response time: median {fmt_ms(percentile(srt, .5))}, 95th pct {fmt_ms(percentile(srt, .95))}; unanswered queries: {d['unanswered']}\n")
    counter_block('HTTP methods', S['http']['methods'])
    counter_block('HTTP status classes', S['http']['status'])
    counter_block('HTTP hosts', S['http']['hosts'], 6)
    counter_block('TLS SNI', S['tls']['sni'], 8)
    counter_block('TLS versions negotiated', S['tls']['versions'])
    counter_block('TLS JA3 fingerprints', S['tls']['ja3'], 5)
    counter_block('QUIC SNI', S['tls']['quic_sni'], 6)
    counter_block('STUN/TURN messages', S['stun']['messages'], 10)
    counter_block('STUN/TURN errors', S['stun']['errors'])
    if S['stun']['rtts']:
        srt = sorted(S['stun']['rtts'])
        w(f"    STUN response time: median {fmt_ms(percentile(srt, .5))}, 95th pct {fmt_ms(percentile(srt, .95))}\n")
    if S['rtp']['streams']:
        w('\n  RTP streams\n')
        for s in S['rtp']['streams'][:8]:
            w(f"    {s['src']} -> {s['dst']}  {s['ssrc']}  {s['pt']}  {s['packets']} pkts  lost {s['lost']} ({s['lost_pct']:.1f}%)  jitter {s['jitter_ms']:.2f} ms\n")
    if S['processes']:
        w('\n  TRAFFIC BY PROCESS (from the capture host)\n')
        for r in S['processes'][:12]:
            w(f"    {str(r['name'])[:34]:<34} pid {r['pid']:<7} {r['packets']:>8,} pkts {fmt_size(r['bytes']):>10}   out {fmt_size(r['out'])} / in {fmt_size(r['in'])}\n")
    counter_block('DHCP messages', S['dhcp']['messages'])
    counter_block('ICMP', S['icmp'])
    e = S['expert']
    w(f"\n  EXPERT: errors {e['severity'].get('error', 0)}, warnings {e['severity'].get('warning', 0)}, "
      f"notes {e['severity'].get('note', 0)}, chats {e['severity'].get('chat', 0)}\n")
    for (sev, grp, msg), c in e['messages'][:10]:
        w(f"    {sev.upper():<8} {grp:<14} x{c:<6} {msg[:80]}\n")
    w('\n')


def stats_html(S, title='Fathom statistics report', theme='light', width=560):
    pal = chart_palette(theme)
    e = html.escape
    parts = [f'<!doctype html><meta charset="utf-8"><title>{e(title)}</title><style>body{{font:14px system-ui,sans-serif;margin:24px;background:{pal["bg"]};color:{pal["text"]}}}'
             f'h1{{font-size:22px}}h2{{margin-top:32px;border-bottom:1px solid {pal["grid"]};padding-bottom:4px}}.grid{{display:flex;flex-wrap:wrap;gap:16px}}'
             f'table{{border-collapse:collapse;margin:8px 0}}td,th{{border:1px solid {pal["grid"]};padding:3px 9px;text-align:right}}td:first-child,th:first-child{{text-align:left}}'
             f'th{{background:{pal["panel_alt"]}}}</style>', f'<h1>{e(title)}</h1>']

    def table(headers, rows):
        return '<table><tr>' + ''.join(f'<th>{e(str(h))}</th>' for h in headers) + '</tr>' + ''.join(
            '<tr>' + ''.join(f'<td>{e(str(c))}</td>' for c in r) + '</tr>' for r in rows) + '</table>'
    di = S['direction']
    parts.append('<h2>Overview</h2>' + table(['Metric', 'Value'], [
        ['Packets', f"{S['packets']:,}"], ['Bytes', f"{S['bytes']:,} ({fmt_size(S['bytes'])})"], ['Duration', fmt_dur(S['duration'])],
        ['Average rate', f"{S['pps']:.1f} packets/s, {fmt_bitrate(S['bps'])}"], ['Average / min / max packet size', f"{S['avg_size']:.0f} / {S['min_size']} / {S['max_size']} bytes"],
        ['Inbound / outbound', f"{di['inbound'][0]:,} / {di['outbound'][0]:,} packets"], ['TCP / UDP streams', f"{len(S['tcp']['streams']):,} / {S['udp_streams']:,}"],
        ['Expert', f"{S['expert']['severity'].get('error', 0)} errors, {S['expert']['severity'].get('warning', 0)} warnings, {S['expert']['severity'].get('note', 0)} notes"]]))
    charts = [chart_donut(S['protocols_bytes'].most_common(), width, 240, pal, 'Protocols by bytes', fmt=fmt_size),
              chart_donut([('Inbound', di['inbound'][1]), ('Outbound', di['outbound'][1]), ('Unknown', di['unknown'][1])], width, 240, pal, 'Direction by bytes', fmt=fmt_size),
              chart_columns(list(zip(bucket_labels(LENGTH_BUCKETS), S['length_hist'])), width, 260, pal, 'Packet length distribution (bytes, bucket upper bound)')]
    parts.append('<div class="grid">' + ''.join(c.to_svg() for c in charts) + '</div>')
    return parts, pal, table


def export_stats_html(state, path, theme='light'):
    packets = state.packets
    S = build_statistics(packets, state.analysis, state.meta)
    parts, pal, table = stats_html(S, f'Fathom report \u2014 {state.source_label}', theme)
    e = html.escape
    parts.append('<h2>I/O graphs</h2><div class="grid">')
    for split, ttl in (('protocol', 'Bytes/s by protocol'), ('problems', 'Packets/s and problems')):
        parts.append(chart_io(build_io(packets, None, 'bytes' if split == 'protocol' else 'packets', split), 900, 300, pal, ttl).to_svg())
    parts.append('</div><h2>Protocol hierarchy</h2>' + table(['Protocol', 'Packets', '% packets', 'Bytes', '% bytes'], [
        ['\u00a0\u00a0' * r['depth'] + r['name'], f"{r['packets']:,}", f"{r['pct_packets']:.1f}", f"{r['bytes']:,}", f"{r['pct_bytes']:.1f}"] for r in S['hierarchy']]))
    for kind, name in (('tcp', 'TCP'), ('udp', 'UDP'), ('ipv4', 'IPv4')):
        rows = build_conversations(packets, kind)[:25]
        if rows:
            parts.append(f'<h2>Top {name} conversations</h2>' + table(['A', 'B', 'Packets', 'Bytes', 'A\u2192B bytes', 'B\u2192A bytes', 'Duration'], [
                [r['a'], r['b'], f"{r['packets']:,}", f"{r['bytes']:,}", f"{r['ab_bytes']:,}", f"{r['ba_bytes']:,}", fmt_dur(r['duration'])] for r in rows]))
    top_ip = build_endpoints(packets, 'ip')[:12]
    parts.append('<h2>Top talkers</h2><div class="grid">' + chart_hbars([(r['address'], r['bytes']) for r in top_ip], 560, 300, pal, 'IP endpoints by bytes', fmt_size).to_svg() + '</div>')
    ud = S['udp']
    if ud['packets']:
        parts.append('<h2>UDP</h2><div class="grid">')
        parts.append(chart_donut(ud['proto_bytes'].most_common(), 560, 240, pal, 'UDP bytes by protocol', fmt=fmt_size).to_svg())
        parts.append(chart_hbars([(str(k), v) for k, v in ud['ports'].most_common(10)], 560, 240, pal, 'Busiest UDP ports (by bytes)', fmt_size).to_svg())
        parts.append('</div>' + table(['Stream', 'A', 'B', 'Protocol', 'Packets', 'Bytes', 'A\u2192B bytes', 'B\u2192A bytes', 'Duration'], [
            [r['stream'], r['a'], r['b'], r['proto'], f"{r['packets']:,}", f"{r['bytes']:,}", f"{r['ab_bytes']:,}", f"{r['ba_bytes']:,}", fmt_dur(r['duration'])]
            for r in ud['streams'][:25]]))
    t = S['tcp']
    if t['streams']:
        parts.append('<h2>TCP analysis</h2><div class="grid">')
        parts.append(chart_hbars(list(t['states'].most_common()), 560, 220, pal, 'Stream outcomes').to_svg())
        parts.append(chart_columns(list(zip(bucket_labels(RTT_BUCKETS), t['rtt_hist'])), 560, 240, pal, 'ACK round-trip time distribution (ms, bucket upper bound)').to_svg())
        parts.append(chart_hbars([(str(k), v) for k, v in t['server_ports'].most_common(10)], 560, 240, pal, 'Busiest server ports').to_svg())
        parts.append('</div>' + table(['Stream', 'A', 'B', 'Packets', 'Bytes', 'Duration', 'State', 'iRTT', 'Retrans', 'Dup-ACK', 'Lost'], [
            [r['stream'], r['a'], r['b'], r['packets'], f"{r['bytes']:,}", fmt_dur(r['duration']), r['state'],
             fmt_ms(r['irtt']) if r['irtt'] >= 0 else '-', r['retrans'], r['dup'], r['lost']] for r in sorted(t['streams'], key=lambda r: -(r['retrans'] + r['lost'] + r['dup']))[:30]]))
    sections = [('DNS', [('Query types', S['dns']['qtypes']), ('Response codes', S['dns']['rcodes']), ('Top names', S['dns']['names'])]),
                ('HTTP', [('Methods', S['http']['methods']), ('Status classes', S['http']['status']), ('Hosts', S['http']['hosts'])]),
                ('TLS / QUIC', [('SNI', S['tls']['sni']), ('Versions', S['tls']['versions']), ('QUIC SNI', S['tls']['quic_sni']), ('JA3', S['tls']['ja3'])]),
                ('STUN / TURN', [('Messages', S['stun']['messages']), ('Errors', S['stun']['errors']), ('Servers', S['stun']['servers'])])]
    for title, blocks in sections:
        ch = [chart_hbars(list(c.most_common(10)), 560, 240, pal, n).to_svg() for n, c in blocks if c]
        if ch:
            parts.append(f'<h2>{title}</h2><div class="grid">{"".join(ch)}</div>')
    if S['rtp']['streams']:
        parts.append('<h2>RTP streams</h2>' + table(['From', 'To', 'SSRC', 'Payload', 'Packets', 'Lost', 'Loss %', 'Jitter ms'], [
            [s['src'], s['dst'], s['ssrc'], s['pt'], s['packets'], s['lost'], f"{s['lost_pct']:.1f}", f"{s['jitter_ms']:.2f}"] for s in S['rtp']['streams']]))
    ex = S['expert']
    parts.append('<h2>Expert information</h2><div class="grid">' + chart_hbars([(k, ex['severity'].get(k, 0)) for k in ('error', 'warning', 'note', 'chat')], 560, 160, pal, 'By severity',
                 colors={'error': pal['danger'], 'warning': pal['warn']}).to_svg() + chart_hbars(list(ex['groups'].most_common(10)), 560, 240, pal, 'By group').to_svg() + '</div>' +
                 table(['Severity', 'Group', 'Count', 'Summary'], [[s, g, c, m] for (s, g, m), c in ex['messages']]))
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(parts))
    return path


# ---- Expert Info model (grouped like Wireshark's Expert Information dialog) ------------------------------------------------------

def build_expert_groups(packets):
    groups = collections.OrderedDict()
    for p in packets:
        for sev, grp, msg in p.flat.expert:
            key = (sev, grp, msg)
            g = groups.get(key)
            if g is None:
                g = groups[key] = {'severity': sev, 'group': grp, 'summary': msg, 'packets': [], 'protocols': collections.Counter()}
            g['packets'].append(p.number)
            g['protocols'][p.summary['protocol']] += 1
    rows = list(groups.values())
    for g in rows:
        g['count'] = len(g['packets'])
        g['protocol'] = g['protocols'].most_common(1)[0][0]
    rows.sort(key=lambda g: (-SEV_ORDER[g['severity']], -g['count'], g['group']))
    return rows


# ============================================================================
# PART 9 -- Tkinter GUI (the only section that touches a GUI toolkit directly)
# ============================================================================

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, simpledialog
    import tkinter.font as tkfont
except ImportError:
    tk = ttk = filedialog = messagebox = simpledialog = tkfont = None


HELP_TEXT = """Filter examples (typed live into the Filter box):

  tcp / udp / dns / stun / rtp / rtcp / quic / dhcp / sip / tls / icmp / arp
  ip.addr==8.8.8.8              either side matches (CIDR works: ip.addr==10.0.0.0/8)
  tcp.port==443                 tcp.port in {80 443 8080}
  tcp.flags.syn==1 and not tcp.flags.ack
  tcp.analysis.flags            retransmissions, dup-ACKs, lost segments, keep-alives, zero-window...
  tcp.analysis.retransmission   tcp.stream==3      udp.stream==0
  dns.qry.name contains "google"     dns.flags.rcode != 0
  stun.type==0x0001             stun.att.username contains "abcd"
  rtp.ssrc==0x1234abcd          rtp.p_type==0      rtcp.pt==200
  tls.handshake.type==1         tls.sni contains "example"     tls.handshake.ja3
  quic.long.packet_type==0      quic.sni contains "google"
  http.request.method=="POST"   http.host contains "example"   http.response.code>=400
  dhcp.option.dhcp==1           sip.method=="INVITE"
  expert                        any packet with Expert Info    expert.severity=="warning"
  frame.direction=="outbound"   pcapng packet direction (inbound / outbound)
  frame.proc.name=="Safari"      macOS process that sent/received the packet (pcapng with Apple process data)
  frame.interface_name=="en0"   frame.comment contains "..."   frame.time_delta>1
  tcp.state contains "Reset"    tcp.analysis.fast_retransmission    tcp.analysis.window_full
  stun.att.realm                stun.att.error==401            stun.class==3
  frame contains "password"     search raw bytes
  "some text"                   plain search across all columns

Anything that doesn't parse as an expression falls back to a plain
substring search, so free text always does something reasonable.
"""

SHORTCUTS_TEXT = """Keyboard shortcuts

  Ctrl+O   Open capture file          Ctrl+E   Export filtered rows to CSV
  Ctrl+F   Focus the filter box       Ctrl+T   Statistics
  Ctrl+G   Go to packet number        Ctrl+D   Toggle dark / light theme
  Ctrl+Shift+F  Find in current view  Ctrl+Shift+E  Expert Information
  Ctrl+=   Zoom in                    Ctrl+-   Zoom out       Ctrl+0  Reset zoom
  Ctrl+Q   Quit                       m        Mark / unmark the selected packet

  Click a column heading to sort by it (click again to reverse).
  Right-click a packet for quick filters, Follow Stream, copy and marking.
  Hover a layer in the packet tree to highlight its bytes in the hex view.
"""

_resolved_font_cache = {}


def resolve_font(stack, fallback='TkFixedFont'):
    key = tuple(stack)
    if key in _resolved_font_cache:
        return _resolved_font_cache[key]
    try:
        available = set(tkfont.families())
    except Exception:
        available = set()
    for name in stack:
        if name in available:
            _resolved_font_cache[key] = name
            return name
    _resolved_font_cache[key] = fallback
    return fallback


class Tooltip:
    """Delayed popup for long cell values (fully laid out before showing, to avoid blank popups on macOS)."""

    def __init__(self, widget, colors, mono_font):
        self.widget, self.colors, self.mono_font = widget, colors, mono_font
        self.tip = None
        self.after_id = None
        self.current_key = None

    def set_colors(self, colors):
        self.colors = colors

    def schedule(self, key, text, x, y, delay=450):
        if key == self.current_key and (self.tip or self.after_id):
            return
        self.cancel()
        self.current_key = key
        self.after_id = self.widget.after(delay, lambda: self._show(text, x, y))

    def cancel(self):
        if self.after_id:
            try:
                self.widget.after_cancel(self.after_id)
            except Exception:
                pass
            self.after_id = None
        self.hide()

    def hide(self):
        if self.tip:
            try:
                self.tip.destroy()
            except Exception:
                pass
            self.tip = None
        self.current_key = None

    def _show(self, text, x, y):
        self.after_id = None
        try:
            bg, fg, border = self.colors['panel_alt'], self.colors['text'], self.colors['border']
            tip = tk.Toplevel(self.widget)
            tip.wm_overrideredirect(True)
            try:
                tip.wm_attributes('-topmost', True)
            except Exception:
                pass
            tip.configure(background=border, highlightthickness=0)
            inner = tk.Frame(tip, background=bg, highlightthickness=1, highlightbackground=border, highlightcolor=border)
            inner.pack(padx=1, pady=1)
            tk.Label(inner, text=text, background=bg, foreground=fg, padx=8, pady=5,
                     font=(self.mono_font, 10), justify='left', wraplength=700).pack()
            tip.update_idletasks()
            tip.wm_geometry(f'+{x}+{y}')
            self.tip = tip
        except Exception:
            self.hide()


class FindDialog:
    def __init__(self, parent, colors, on_search, on_navigate, on_close):
        self.on_search, self.on_navigate, self.on_close = on_search, on_navigate, on_close
        self.top = tk.Toplevel(parent)
        self.top.title('Find in view')
        self.top.resizable(False, False)
        self.top.configure(background=colors['panel'])
        self.top.transient(parent)
        row = tk.Frame(self.top, background=colors['panel'])
        row.pack(padx=10, pady=10)
        tk.Label(row, text='Find:', background=colors['panel'], foreground=colors['text']).pack(side='left')
        self.var = tk.StringVar()
        entry = tk.Entry(row, textvariable=self.var, width=28, background=colors['input_bg'], foreground=colors['text'],
                         insertbackground=colors['text'], relief='flat', highlightthickness=1,
                         highlightbackground=colors['border'], highlightcolor=colors['accent'])
        entry.pack(side='left', padx=(6, 6), ipady=3)
        entry.bind('<KeyRelease>', lambda e: self.on_search(self.var.get()))
        entry.bind('<Return>', lambda e: self.on_navigate(1))
        entry.bind('<Shift-Return>', lambda e: self.on_navigate(-1))
        entry.bind('<Escape>', lambda e: self._close())
        self.count_label = tk.Label(row, text='', background=colors['panel'], foreground=colors['text_dim'], width=10)
        self.count_label.pack(side='left', padx=(0, 6))
        ttk.Button(row, text='\u25b2', width=2, command=lambda: self.on_navigate(-1)).pack(side='left')
        ttk.Button(row, text='\u25bc', width=2, command=lambda: self.on_navigate(1)).pack(side='left', padx=(2, 0))
        self.top.protocol('WM_DELETE_WINDOW', self._close)
        self.top.bind('<Escape>', lambda e: self._close())
        entry.focus_set()

    def set_count(self, index, total):
        self.count_label.config(text=(f'{index + 1} / {total}' if total else 'no matches'))

    def _close(self):
        self.on_close()
        self.top.destroy()


class InterfaceDialog:
    def __init__(self, parent, interfaces, colors):
        self.result = None
        self.top = tk.Toplevel(parent)
        self.top.title('Choose network interface')
        self.top.resizable(False, False)
        self.top.configure(background=colors['panel'])
        self.top.transient(parent)
        ttk.Label(self.top, text='Capture live on which interface?', padding=(14, 12, 14, 6)).pack(anchor='w')
        self.var = tk.StringVar(value=interfaces[0] if interfaces else '')
        combo = ttk.Combobox(self.top, textvariable=self.var, values=interfaces, state='readonly', width=32)
        combo.pack(padx=14, pady=(0, 6))
        ttk.Label(self.top, text='BPF capture filter (optional, e.g. "udp port 3478"):', padding=(14, 6, 14, 2)).pack(anchor='w')
        self.filter_var = tk.StringVar(value='')
        ttk.Entry(self.top, textvariable=self.filter_var, width=34).pack(padx=14, pady=(0, 10))
        btns = ttk.Frame(self.top, padding=(14, 0, 14, 14))
        btns.pack(fill='x')
        ttk.Button(btns, text='Cancel', command=self._cancel).pack(side='right')
        ttk.Button(btns, text='Start capture', command=self._ok).pack(side='right', padx=(0, 8))
        self.top.protocol('WM_DELETE_WINDOW', self._cancel)
        self.top.bind('<Return>', lambda e: self._ok())
        self.top.bind('<Escape>', lambda e: self._cancel())
        self.top.grab_set()
        combo.focus_set()

    def _ok(self):
        self.result = (self.var.get() or None, self.filter_var.get().strip() or None)
        self.top.destroy()

    def _cancel(self):
        self.result = None
        self.top.destroy()

    def show(self):
        self.top.wait_window()
        return self.result


_CanvasBase = tk.Canvas if tk else object      # keeps the module importable (for --text / --stats) without Tkinter
_FrameBase = ttk.Frame if ttk else object


class ChartCanvas(_CanvasBase):
    """A canvas that redraws a chart builder(w, h, palette) -> Plot whenever it is resized."""

    def __init__(self, parent, builder, pal, height=230, **kw):
        super().__init__(parent, height=height, background=pal['bg'], highlightthickness=1,
                         highlightbackground=pal['grid'], **kw)
        self.builder, self.pal = builder, pal
        self._job = None
        self.bind('<Configure>', self._schedule)

    def _schedule(self, _e=None):
        if self._job:
            try:
                self.after_cancel(self._job)
            except Exception:
                pass
        self._job = self.after(30, self.redraw)

    def set_builder(self, builder):
        self.builder = builder
        self.redraw()

    def redraw(self):
        self._job = None
        w, h = self.winfo_width(), self.winfo_height()
        if w < 60 or h < 40:
            return
        self.delete('all')
        try:
            self.builder(w, h, self.pal).draw(self)
        except Exception as e:   # never let a chart bug break the window
            self.create_text(10, 10, anchor='nw', text=f'chart error: {e}', fill=self.pal['danger'])


class DataTable(_FrameBase):
    """Sortable table. columns: [(key, title, width, anchor, formatter_or_None)]; rows: list of dicts."""

    def __init__(self, parent, columns, on_activate=None, height=10, stretch_key=None):
        super().__init__(parent)
        self.columns, self.on_activate = columns, on_activate
        keys = [c[0] for c in columns]
        self.tree = ttk.Treeview(self, columns=keys, show='headings', height=height, selectmode='browse')
        for key, title, width, anchor, _fmt in columns:
            self.tree.heading(key, text=title, anchor=(anchor if anchor in ('w', 'e') else 'center'), command=lambda k=key: self.sort_by(k))
            self.tree.column(key, width=width, anchor=anchor, stretch=(key == (keys[-1] if stretch_key is None else stretch_key)))   # stretch_key='' -> no column stretches
        vsb = ttk.Scrollbar(self, orient='vertical', command=self.tree.yview)
        hsb = ttk.Scrollbar(self, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.rows, self._shown = [], []
        self.sort_key, self.reverse = None, False
        self.tree.bind('<Double-1>', self._activate)

    def set_rows(self, rows):
        self.rows = rows
        self._render()

    def sort_by(self, key):
        self.reverse = (not self.reverse) if self.sort_key == key else False
        self.sort_key = key
        self._render()

    def _render(self):
        rows = self.rows
        if self.sort_key:
            k = self.sort_key
            rows = sorted(rows, key=lambda r: (0, 0) if r.get(k) is None else (1, r.get(k)), reverse=self.reverse)
        self.tree.delete(*self.tree.get_children())
        self._shown = rows[:5000]
        for i, r in enumerate(self._shown):
            vals = [(fmt(r.get(key)) if fmt and r.get(key) is not None else ('' if r.get(key) is None else r.get(key)))
                    for key, _t, _w, _a, fmt in self.columns]
            self.tree.insert('', 'end', iid=str(i), values=vals)

    def _activate(self, _e=None):
        sel = self.tree.selection()
        if sel and self.on_activate:
            self.on_activate(self._shown[int(sel[0])])

    def export_csv(self, path):
        with open(path, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow([c[1] for c in self.columns])
            for r in self.rows:
                w.writerow([r.get(c[0], '') for c in self.columns])


class StatsWindow:
    """Tabbed statistics: overview, I/O graph, protocols, conversations, endpoints, packet sizes, TCP, DNS, web, STUN/VoIP, expert, capture."""
    IO_INTERVALS = [('Auto', None), ('1 ms', 0.001), ('10 ms', 0.01), ('100 ms', 0.1), ('500 ms', 0.5), ('1 s', 1), ('2 s', 2),
                    ('5 s', 5), ('10 s', 10), ('30 s', 30), ('1 min', 60), ('5 min', 300), ('10 min', 600), ('1 hour', 3600)]
    IO_METRICS = [('Packets / s', 'packets'), ('Bytes / s', 'bytes'), ('Bits / s', 'bits')]
    IO_SPLITS = [('Total', 'total'), ('By protocol', 'protocol'), ('Inbound vs outbound', 'direction'),
                 ('Problems (expert + TCP analysis)', 'problems')]

    def __init__(self, parent, state, colors, theme, mono_font, ui_font, on_filter, on_timeseq=None, select_tab=None):
        self.state, self.colors, self.theme = state, colors, theme
        self.pal = chart_palette(theme)
        self.mono, self.ui = mono_font, ui_font
        self.on_filter, self.on_timeseq = on_filter, on_timeseq
        self.packets = state.packets
        self.S = build_statistics(state.packets, state.analysis, state.meta)
        top = self.top = tk.Toplevel(parent)
        top.title('Statistics')
        top.geometry('1240x820')
        top.minsize(900, 600)
        top.configure(background=colors['bg'])
        S = self.S
        bar = tk.Frame(top, background=colors['bg'])
        bar.pack(fill='x', padx=10, pady=(8, 4))
        tk.Label(bar, background=colors['bg'], foreground=colors['text'], font=(ui_font, 12, 'bold'),
                 text=f"{S['packets']:,} packets \u00b7 {fmt_size(S['bytes'])} \u00b7 {fmt_dur(S['duration'])} \u00b7 {fmt_bitrate(S['bps'])} average"
                 ).pack(side='left')
        ttk.Button(bar, text='Export HTML report\u2026', style='Toolbar.TButton', command=self._export_report).pack(side='right')
        self.nb = ttk.Notebook(top)
        self.nb.pack(fill='both', expand=True, padx=8, pady=(0, 8))
        self.tabs = {}
        for name, fn in (('Overview', self._tab_overview), ('I/O Graph', self._tab_io), ('Protocols', self._tab_protocols),
                         ('Conversations', self._tab_conversations), ('Endpoints', self._tab_endpoints), ('Processes', self._tab_processes),
                         ('Packet sizes', self._tab_sizes), ('TCP', self._tab_tcp), ('UDP', self._tab_udp), ('DNS', self._tab_dns),
                         ('Web / TLS / QUIC', self._tab_web), ('STUN / RTP / DHCP', self._tab_voip),
                         ('Expert', self._tab_expert), ('Capture', self._tab_capture)):
            frame = ttk.Frame(self.nb)
            self.nb.add(frame, text=name)
            self.tabs[name] = frame
            fn(frame)
        if select_tab in self.tabs:
            self.nb.select(self.tabs[select_tab])

    # ---- helpers ----
    def _chart(self, parent, builder, row, col, rowspan=1, colspan=1, height=230):
        cc = ChartCanvas(parent, builder, self.pal, height=height)
        cc.grid(row=row, column=col, rowspan=rowspan, columnspan=colspan, sticky='nsew', padx=4, pady=4)
        return cc

    @staticmethod
    def _weights(parent, rows, cols):
        for r in range(rows):
            parent.rowconfigure(r, weight=1)
        for c in range(cols):
            parent.columnconfigure(c, weight=1)

    def _bars(self, data, title, fmt=fmt_count, n=10, colors=None):
        items = list(data.most_common(n)) if hasattr(data, 'most_common') else list(data)[:n]
        items = [(str(k), v) for k, v in items]
        return lambda w, h, pal: chart_hbars(items, w, h, pal, title, fmt, colors=colors)

    def _donut(self, items, title, fmt=fmt_count, center=''):
        return lambda w, h, pal: chart_donut(items, w, h, pal, title, center, fmt)

    def _hist(self, buckets, counts, title, unit='ms'):
        items = list(zip(bucket_labels(buckets), counts))
        title = f'{title} [{unit}, bucket upper bound]'
        return lambda w, h, pal: chart_columns(items, w, h, pal, title)

    def _export_report(self):
        path = filedialog.asksaveasfilename(parent=self.top, title='Export statistics report', defaultextension='.html',
                                            initialfile='fathom-report.html', filetypes=[('HTML report', '*.html')])
        if path:
            try:
                export_stats_html(self.state, path, self.theme)
                messagebox.showinfo('Report written', f'Saved {path}', parent=self.top)
            except Exception as e:
                messagebox.showerror('Export failed', str(e), parent=self.top)

    def _export_table(self, table):
        path = filedialog.asksaveasfilename(parent=self.top, title='Export table as CSV', defaultextension='.csv',
                                            initialfile='fathom-table.csv', filetypes=[('CSV', '*.csv')])
        if path:
            table.export_csv(path)

    # ---- tabs ----
    def _tab_overview(self, f):
        S = self.S
        di = S['direction']
        rows = [('Packets', f"{S['packets']:,}"), ('Bytes', f"{S['bytes']:,}  ({fmt_size(S['bytes'])})"),
                ('Capture duration', fmt_dur(S['duration'])), ('Average rate', f"{S['pps']:.1f} packets/s, {fmt_bitrate(S['bps'])}"),
                ('Packet size avg / min / max', f"{S['avg_size']:.0f} / {S['min_size']} / {S['max_size']} bytes"),
                ('Inbound', f"{di['inbound'][0]:,} packets, {fmt_size(di['inbound'][1])}"),
                ('Outbound', f"{di['outbound'][0]:,} packets, {fmt_size(di['outbound'][1])}"),
                ('Direction unknown', f"{di['unknown'][0]:,} packets"),
                ('Broadcast / multicast', f"{S['broadcast']:,} / {S['multicast']:,}"),
                ('Truncated by snaplen', f"{S['truncated']:,}"),
                ('TCP streams', f"{len(S['tcp']['streams']):,}"), ('UDP streams', f"{S['udp_streams']:,}"),
                ('TCP retransmissions', f"{S['tcp']['totals']['retrans']:,}"), ('TCP resets', f"{S['tcp']['totals']['rst']:,}"),
                ('DNS queries', f"{sum(S['dns']['qtypes'].values()):,}  ({S['dns']['unanswered']} unanswered)"),
                ('Expert errors / warnings', f"{S['expert']['severity'].get('error', 0)} / {S['expert']['severity'].get('warning', 0)}"),
                ('Packet comments', str(len(S['comments'])))]
        for name, (pk, by) in S['interfaces'].items():
            rows.append((f'Interface {name}', f'{pk:,} packets, {fmt_size(by)}'))
        t = DataTable(f, [('k', 'Metric', 210, 'w', None), ('v', 'Value', 230, 'w', None)], height=18)
        t.set_rows([{'k': a, 'v': b} for a, b in rows])
        t.grid(row=0, column=0, rowspan=2, sticky='nsew', padx=4, pady=4)
        f.columnconfigure(0, weight=0)
        self._chart(f, self._donut(S['protocols_bytes'].most_common(), 'Protocols by bytes', fmt_size), 0, 1)
        self._chart(f, self._donut([('Inbound', di['inbound'][1]), ('Outbound', di['outbound'][1]), ('Unknown', di['unknown'][1])],
                                   'Traffic direction by bytes', fmt_size), 0, 2)
        ex = S['expert']['severity']
        self._chart(f, self._bars([(k.capitalize(), ex.get(k, 0)) for k in ('error', 'warning', 'note', 'chat')], 'Expert findings',
                                  colors={'Error': self.pal['danger'], 'Warning': self.pal['warn']}), 1, 1)
        self._chart(f, lambda w, h, pal: chart_columns(
            list(zip(bucket_labels(LENGTH_BUCKETS), S['length_hist'])),
            w, h, pal, 'Packet length distribution (bytes, bucket upper bound)'), 1, 2)
        f.rowconfigure(0, weight=1)
        f.rowconfigure(1, weight=1)
        f.columnconfigure(1, weight=1)
        f.columnconfigure(2, weight=1)

    def _tab_io(self, f):
        bar = ttk.Frame(f)
        bar.pack(fill='x', padx=6, pady=6)
        combos = {}
        for label, options, default in (('Interval', self.IO_INTERVALS, 0), ('Y axis', self.IO_METRICS, 1), ('Split by', self.IO_SPLITS, 1)):
            ttk.Label(bar, text=label + ':').pack(side='left', padx=(10, 4))
            cb = ttk.Combobox(bar, values=[o[0] for o in options], state='readonly', width=30 if label == 'Split by' else 12)
            cb.current(default)
            cb.pack(side='left')
            combos[label] = (cb, options)
        cache = {}

        def builder(w, h, pal):
            sel = {k: dict(opts)[cb.get()] for k, (cb, opts) in combos.items()}
            key = (sel['Interval'], sel['Y axis'], sel['Split by'])
            if key not in cache:
                cache[key] = build_io(self.packets, sel['Interval'], sel['Y axis'], sel['Split by'])
            d = cache[key]
            return chart_io(d, w, h, pal, f"I/O graph \u2014 {len(self.packets):,} packets, bin = {d['interval']:g} s")
        cc = ChartCanvas(f, builder, self.pal, height=500)
        cc.pack(fill='both', expand=True, padx=6, pady=(0, 6))
        for cb, _ in combos.values():
            cb.bind('<<ComboboxSelected>>', lambda e: cc.redraw())

    def _tab_protocols(self, f):
        S = self.S
        tree = ttk.Treeview(f, columns=('packets', 'pp', 'bytes', 'pb'), show='tree headings', height=16)
        tree.heading('#0', text='Protocol')
        tree.column('#0', width=300, stretch=False)
        for c, t_, w in (('packets', 'Packets', 90), ('pp', '% Packets', 80), ('bytes', 'Bytes', 100), ('pb', '% Bytes', 80)):
            tree.heading(c, text=t_)
            tree.column(c, width=w, anchor='e', stretch=False)
        for r in S['hierarchy']:
            iid = '/'.join(r['path'])
            parent = '/'.join(r['path'][:-1])
            tree.insert(parent, 'end', iid=iid, text=r['name'], open=True,
                        values=(f"{r['packets']:,}", f"{r['pct_packets']:.1f}", f"{r['bytes']:,}", f"{r['pct_bytes']:.1f}"))
        tree.grid(row=0, column=0, rowspan=2, sticky='nsew', padx=4, pady=4)
        self._chart(f, self._donut(S['protocols_packets'].most_common(), 'Packets by protocol column'), 0, 1)
        self._chart(f, self._bars(S['protocols_bytes'], 'Bytes by protocol column', fmt_size, 12), 1, 1)
        self._weights(f, 2, 2)
        f.columnconfigure(0, weight=2)

    def _tab_conversations(self, f):
        kinds = [('Ethernet', 'eth'), ('IPv4', 'ipv4'), ('IPv6', 'ipv6'), ('TCP', 'tcp'), ('UDP', 'udp')]
        bar = ttk.Frame(f)
        bar.pack(fill='x', padx=6, pady=6)
        ttk.Label(bar, text='Conversation type:').pack(side='left')
        cb = ttk.Combobox(bar, values=[k[0] for k in kinds], state='readonly', width=12)
        cb.current(3)
        cb.pack(side='left', padx=6)
        num = lambda v: f'{v:,}'
        cols = [('a', 'Address A', 190, 'w', None), ('b', 'Address B', 190, 'w', None), ('packets', 'Packets', 70, 'e', num),
                ('bytes', 'Bytes', 90, 'e', num), ('ab_packets', 'A\u2192B pkts', 75, 'e', num), ('ab_bytes', 'A\u2192B bytes', 90, 'e', num),
                ('ba_packets', 'B\u2192A pkts', 75, 'e', num), ('ba_bytes', 'B\u2192A bytes', 90, 'e', num),
                ('start', 'Rel start', 80, 'e', lambda v: f'{v:.3f}'), ('duration', 'Duration', 85, 'e', fmt_dur),
                ('bps_ab', 'bit/s A\u2192B', 125, 'e', fmt_bitrate), ('bps_ba', 'bit/s B\u2192A', 125, 'e', fmt_bitrate),
                ('proto', 'Protocol', 75, 'w', None)]

        def activate(row):
            kind = dict(kinds)[cb.get()]
            if kind in ('tcp', 'udp') and row.get('stream') is not None:
                self.on_filter(f'{kind}.stream=={row["stream"]}')
            elif kind == 'eth':
                self.on_filter(f'eth.addr=={row["a"]} and eth.addr=={row["b"]}')
            else:
                fld = 'ipv6.addr' if kind == 'ipv6' else 'ip.addr'
                ip = lambda s: s.rsplit(':', 1)[0]
                self.on_filter(f'{fld}=={ip(row["a"])} and {fld}=={ip(row["b"])}')
        foot = ttk.Frame(f)
        foot.pack(side='bottom', fill='x')
        table = DataTable(f, cols, on_activate=activate, height=20)
        table.pack(fill='both', expand=True, padx=6)
        ttk.Label(foot, text='Double-click a row to filter the packet list to that conversation.').pack(side='left', padx=8, pady=6)
        ttk.Button(foot, text='Export CSV\u2026', style='Toolbar.TButton', command=lambda: self._export_table(table)).pack(side='right', padx=8, pady=6)

        def load(_e=None):
            table.set_rows(build_conversations(self.packets, dict(kinds)[cb.get()]))
        cb.bind('<<ComboboxSelected>>', load)
        load()

    def _tab_endpoints(self, f):
        kinds = [('IP address', 'ip'), ('Ethernet', 'eth'), ('TCP (address:port)', 'tcp'), ('UDP (address:port)', 'udp')]
        bar = ttk.Frame(f)
        bar.pack(fill='x', padx=6, pady=6)
        ttk.Label(bar, text='Endpoint type:').pack(side='left')
        cb = ttk.Combobox(bar, values=[k[0] for k in kinds], state='readonly', width=20)
        cb.current(0)
        cb.pack(side='left', padx=6)
        num = lambda v: f'{v:,}'
        cols = [('address', 'Endpoint', 240, 'w', None), ('packets', 'Packets', 80, 'e', num), ('bytes', 'Bytes', 100, 'e', num),
                ('tx_packets', 'Tx pkts', 80, 'e', num), ('tx_bytes', 'Tx bytes', 100, 'e', num),
                ('rx_packets', 'Rx pkts', 80, 'e', num), ('rx_bytes', 'Rx bytes', 100, 'e', num)]
        holder = {}

        def activate(row):
            kind = dict(kinds)[cb.get()]
            a = row['address']
            if kind == 'eth':
                self.on_filter(f'eth.addr=={a}')
            elif kind in ('tcp', 'udp'):
                ip, port = a.rsplit(':', 1)
                self.on_filter(f'ip.addr=={ip} and {kind}.port=={port}')
            else:
                self.on_filter(f'ipv6.addr=={a}' if ':' in a else f'ip.addr=={a}')
        foot = ttk.Frame(f)
        foot.pack(side='bottom', fill='x')
        body = ttk.Frame(f)
        body.pack(fill='both', expand=True)
        table = DataTable(body, cols, on_activate=activate, height=16)
        table.grid(row=0, column=0, sticky='nsew', padx=6)
        chart = ChartCanvas(body, lambda w, h, pal: chart_hbars([], w, h, pal), self.pal)
        chart.grid(row=0, column=1, sticky='nsew', padx=6, pady=4)
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)

        def load(_e=None):
            rows = build_endpoints(self.packets, dict(kinds)[cb.get()])
            table.set_rows(rows)
            items = [(r['address'], r['bytes']) for r in rows[:12]]
            chart.set_builder(lambda w, h, pal: chart_hbars(items, w, h, pal, 'Top talkers by bytes', fmt_size))
        cb.bind('<<ComboboxSelected>>', load)
        load()
        ttk.Button(foot, text='Export CSV\u2026', style='Toolbar.TButton', command=lambda: self._export_table(table)).pack(side='right', padx=8, pady=6)

    def _tab_processes(self, f):
        procs = self.S['processes']
        if not procs:
            ttk.Label(f, text='This capture carries no per-packet process information (macOS pcapng captures made with process metadata do).').pack(padx=16, pady=16, anchor='w')
            return
        self._chart(f, self._bars([(f"{r['name']} ({r['pid']})", r['bytes']) for r in procs], 'Bytes by process', fmt_size, 12), 0, 0)
        self._chart(f, self._donut([(f"{r['name']}", r['packets']) for r in procs], 'Packets by process'), 0, 1)
        cols = [('name', 'Process', 220, 'w', None), ('pid', 'PID', 70, 'e', None), ('packets', 'Packets', 80, 'e', lambda v: f'{v:,}'),
                ('bytes', 'Bytes', 100, 'e', lambda v: f'{v:,}'), ('out', 'Sent bytes', 100, 'e', lambda v: f'{v:,}'),
                ('in', 'Received bytes', 110, 'e', lambda v: f'{v:,}')]
        table = DataTable(f, cols, on_activate=lambda r: self.on_filter(f'frame.proc.id=={r["pid"]}'), height=10)
        table.grid(row=1, column=0, columnspan=2, sticky='nsew', padx=4, pady=4)
        table.set_rows(procs)
        self._weights(f, 2, 2)
        f.rowconfigure(1, weight=1)

    def _tab_sizes(self, f):
        S = self.S
        total = max(1, S['packets'])
        self._chart(f, lambda w, h, pal: chart_columns(
            list(zip(bucket_labels(LENGTH_BUCKETS), S['length_hist'])), w, h, pal,
            'Packet length distribution (bytes, bucket upper bound)'), 0, 0, colspan=2, height=300)
        rows = [{'range': (f'{lo} - {hi - 1}' if hi < 10 ** 8 else f'{lo} and greater'), 'count': c, 'pct': 100.0 * c / total}
                for (lo, hi), c in zip(LENGTH_BUCKETS, S['length_hist'])]
        t = DataTable(f, [('range', 'Packet length (bytes)', 170, 'w', None), ('count', 'Packets', 90, 'e', lambda v: f'{v:,}'),
                          ('pct', '% of packets', 100, 'e', lambda v: f'{v:.1f}')], height=11)
        t.set_rows(rows)
        t.grid(row=1, column=0, sticky='nsew', padx=4, pady=4)
        self._chart(f, self._bars([(f'TTL {k}', v) for k, v in S['ttl'].most_common(10)], 'IPv4 TTL values seen'), 1, 1)
        self._weights(f, 2, 2)

    def _tab_tcp(self, f):
        t = self.S['tcp']
        tt = t['totals']
        seg = max(1, tt['segments'])
        self._chart(f, self._bars(t['states'], 'Connection outcomes', n=8), 0, 0)
        self._chart(f, self._hist(RTT_BUCKETS, t['rtt_hist'], f'ACK round-trip time ({len(t["rtts"]):,} samples)'), 0, 1)
        self._chart(f, self._hist(RTT_BUCKETS, t['irtt_hist'], f'Handshake iRTT ({len(t["irtts"]):,} connections)'), 0, 2)
        self._chart(f, self._bars([('Retransmissions', tt['retrans']), ('Duplicate ACKs', tt['dup']), ('Lost-segment gaps', tt['lost']),
                                   ('Zero windows', tt['zerowin']), ('Reset streams', tt['rst'])],
                                  f'TCP problems ({100.0 * tt["retrans"] / seg:.2f}% retransmitted)',
                                  colors={'Retransmissions': self.pal['danger'], 'Lost-segment gaps': self.pal['danger']}), 1, 0)
        self._chart(f, self._bars([(str(k), v) for k, v in t['server_ports'].most_common(10)], 'Busiest server ports'), 1, 1)
        self._chart(f, self._bars([(str(k), v) for k, v in self.S['tcp_dst_ports'].most_common(10)], 'SYN destination ports (scan view)'), 1, 2)
        cols = [('stream', 'Stream', 55, 'e', None), ('a', 'Client / A', 170, 'w', None), ('b', 'Server / B', 170, 'w', None),
                ('packets', 'Pkts', 55, 'e', None), ('bytes', 'Bytes', 80, 'e', lambda v: f'{v:,}'), ('duration', 'Duration', 80, 'e', fmt_dur),
                ('state', 'State', 235, 'w', None), ('irtt', 'iRTT', 80, 'e', lambda v: fmt_ms(v) if v >= 0 else '-'),
                ('rtt_avg', 'RTT avg', 80, 'e', lambda v: fmt_ms(v) if v >= 0 else '-'),
                ('rtt_p95', 'RTT p95', 80, 'e', lambda v: fmt_ms(v) if v >= 0 else '-'), ('retrans', 'Retrans', 60, 'e', None),
                ('dup', 'DupACK', 66, 'e', None), ('lost', 'Lost', 45, 'e', None), ('zerowin', 'ZeroWin', 60, 'e', None)]
        table = DataTable(f, cols, on_activate=lambda r: self.on_filter(f'tcp.stream=={r["stream"]}'), height=9, stretch_key='state')
        table.grid(row=2, column=0, columnspan=3, sticky='nsew', padx=4, pady=4)
        table.set_rows(t['streams'])
        btns = ttk.Frame(f)
        btns.grid(row=3, column=0, columnspan=3, sticky='ew', padx=4, pady=(0, 4))
        ttk.Label(btns, text='Double-click a stream to filter it. Sort by Retrans / Lost to find problem connections.').pack(side='left')
        if self.on_timeseq:
            ttk.Button(btns, text='Time/sequence graph of selected stream\u2026', style='Toolbar.TButton',
                       command=lambda: self._timeseq(table)).pack(side='right', padx=4)
        ttk.Button(btns, text='Export CSV\u2026', style='Toolbar.TButton', command=lambda: self._export_table(table)).pack(side='right')
        self._weights(f, 3, 3)
        f.rowconfigure(2, weight=2)
        f.rowconfigure(3, weight=0)

    def _timeseq(self, table):
        sel = table.tree.selection()
        if sel:
            self.on_timeseq(table._shown[int(sel[0])]['stream'])

    def _empty_note(self, f, text, hint=''):
        ttk.Label(f, text=text, padding=(18, 18, 18, 4), font=(self.ui, 12, 'bold')).pack(anchor='w')
        if hint:
            ttk.Label(f, text=hint, padding=(18, 0, 18, 18), wraplength=900, justify='left').pack(anchor='w')

    def _tab_udp(self, f):
        u = self.S['udp']
        if not u['packets']:
            self._empty_note(f, 'No UDP traffic in this capture.')
            return
        udp_packets = [p for p in self.packets if p.flat.l4 == 'udp' and not p.flat.f.get('icmp.inner')]
        io = build_io(udp_packets, None, 'bytes', 'protocol')
        di = u['dir']
        port_items = [((f"{k} ({WELL_KNOWN_PORTS[k]})" if k in WELL_KNOWN_PORTS else str(k)), v) for k, v in u['ports'].most_common(10)]
        self._chart(f, self._donut(u['proto_bytes'].most_common(), f"UDP bytes by application protocol ({u['packets']:,} datagrams)", fmt_size), 0, 0)
        self._chart(f, self._bars(port_items, 'Busiest UDP ports (lower port of each datagram, by bytes)', fmt_size), 0, 1)
        self._chart(f, lambda w, h, pal: chart_columns(
            list(zip(bucket_labels(LENGTH_BUCKETS), u['size_hist'])), w, h, pal,
            'UDP datagram sizes (bytes, bucket upper bound)'), 0, 2)
        self._chart(f, lambda w, h, pal: chart_io(io, w, h, pal, 'UDP throughput by protocol'), 1, 0, colspan=2)
        self._chart(f, self._donut([('Inbound', di['inbound']), ('Outbound', di['outbound']), ('Unknown', di[None])], 'UDP direction by bytes', fmt_size), 1, 2)
        cols = [('stream', 'Stream', 55, 'e', None), ('a', 'Address A', 175, 'w', None), ('b', 'Address B', 175, 'w', None),
                ('proto', 'Protocol', 70, 'w', None), ('packets', 'Packets', 75, 'e', lambda v: f'{v:,}'),
                ('bytes', 'Bytes', 90, 'e', lambda v: f'{v:,}'), ('ab_bytes', 'A\u2192B bytes', 90, 'e', lambda v: f'{v:,}'),
                ('ba_bytes', 'B\u2192A bytes', 90, 'e', lambda v: f'{v:,}'), ('duration', 'Duration', 85, 'e', fmt_dur),
                ('pps', 'pkts/s', 70, 'e', lambda v: f'{v:.1f}'), ('bps', 'Rate', 130, 'e', fmt_bitrate)]
        table = DataTable(f, cols, on_activate=lambda r: self.on_filter(f'udp.stream=={r["stream"]}'), height=9, stretch_key='')
        table.grid(row=2, column=0, columnspan=3, sticky='nsew', padx=4, pady=4)
        table.set_rows(u['streams'])
        btns = ttk.Frame(f)
        btns.grid(row=3, column=0, columnspan=3, sticky='ew', padx=4, pady=(0, 4))
        ttk.Label(btns, text='Double-click a stream to filter it.').pack(side='left')
        ttk.Button(btns, text='Export CSV\u2026', style='Toolbar.TButton', command=lambda: self._export_table(table)).pack(side='right')
        self._weights(f, 3, 3)
        f.rowconfigure(2, weight=2)
        f.rowconfigure(3, weight=0)

    def _tab_dns(self, f):
        d = self.S['dns']
        if not (sum(d['qtypes'].values()) or sum(d['rcodes'].values())):
            self._empty_note(f, 'No DNS traffic in this capture.',
                             'No queries or answers on port 53, mDNS or LLMNR were found. Your UDP traffic is on the UDP and '
                             'STUN / RTP / DHCP tabs; the Web / TLS / QUIC tab covers HTTPS.')
            return
        self._chart(f, self._bars(d['qtypes'], 'Query types'), 0, 0)
        self._chart(f, self._donut(list(d['rcodes'].most_common()), 'Response codes'), 0, 1)
        rt = [r * 1000 for r in d['rtts']]
        rb = [(0, 1), (1, 5), (5, 10), (10, 25), (25, 50), (50, 100), (100, 250), (250, 500), (500, 1000), (1000, 10 ** 9)]
        self._chart(f, self._hist(rb, _bucket_counts(rt, rb), f'Response time ({len(rt):,} answered, {d["unanswered"]} unanswered)'), 0, 2)
        self._chart(f, self._bars(d['names'], 'Most queried names', n=12), 1, 0, colspan=2)
        self._chart(f, self._bars(d['servers'], 'Servers queried'), 1, 2)
        self._weights(f, 2, 3)

    def _tab_web(self, f):
        h, t = self.S['http'], self.S['tls']
        if not any(sum(c.values()) for c in (h['methods'], h['status'], h['hosts'], t['sni'], t['versions'], t['ciphers'], t['quic_sni'], t['quic_versions'], t['ja3'])):
            self._empty_note(f, 'No HTTP requests, TLS handshakes or QUIC connections were decoded.',
                             'TCP port-443 data that does not start with a valid TLS record is listed as "Continuation Data" (see the TCP tab for the streams).')
            return
        specs = [self._bars(h['methods'], 'HTTP request methods'), self._bars(h['status'], 'HTTP status classes'), self._bars(h['hosts'], 'HTTP hosts'),
                 self._bars(t['sni'], 'TLS server names (SNI)'), self._bars(t['versions'], 'TLS versions negotiated'),
                 self._bars(t['ciphers'], 'TLS cipher suites selected', n=6), self._bars(t['quic_sni'], 'QUIC server names'),
                 self._bars(t['quic_versions'], 'QUIC versions'), self._bars([(k[:12] + '\u2026', v) for k, v in t['ja3'].most_common(8)], 'TLS client JA3 fingerprints')]
        for i, spec in enumerate(specs):
            self._chart(f, spec, i // 3, i % 3, height=200)
        self._weights(f, 3, 3)

    def _tab_voip(self, f):
        s, r, dh = self.S['stun'], self.S['rtp'], self.S['dhcp']
        if not (sum(s['messages'].values()) or r['streams'] or sum(dh['messages'].values())):
            self._empty_note(f, 'No STUN/TURN, RTP or DHCP traffic in this capture.')
            return
        self._chart(f, self._bars(s['messages'], 'STUN / TURN messages', n=10), 0, 0)
        self._chart(f, self._bars(s['errors'], 'STUN / TURN errors', colors=None), 0, 1)
        rt = [x * 1000 for x in s['rtts']]
        rb = [(0, 1), (1, 5), (5, 10), (10, 25), (25, 50), (50, 100), (100, 250), (250, 500), (500, 1000), (1000, 10 ** 9)]
        self._chart(f, self._hist(rb, _bucket_counts(rt, rb), f'STUN response time ({len(rt)} matched)'), 0, 2)
        self._chart(f, self._bars(s['servers'], 'STUN / TURN servers contacted'), 1, 0)
        self._chart(f, self._bars(r['payload_types'], 'RTP payload types'), 1, 1)
        self._chart(f, self._bars(dh['messages'], 'DHCP messages'), 1, 2)
        cols = [('src', 'From', 160, 'w', None), ('dst', 'To', 160, 'w', None), ('ssrc', 'SSRC', 95, 'w', None), ('pt', 'Payload', 150, 'w', None),
                ('packets', 'Packets', 70, 'e', None), ('lost', 'Lost', 60, 'e', None), ('lost_pct', 'Loss %', 65, 'e', lambda v: f'{v:.1f}'),
                ('jitter_ms', 'Jitter ms', 75, 'e', lambda v: f'{v:.2f}'), ('duration', 'Duration', 80, 'e', fmt_dur)]
        table = DataTable(f, cols, height=6)
        table.grid(row=2, column=0, columnspan=3, sticky='nsew', padx=4, pady=4)
        table.set_rows(r['streams'])
        self._weights(f, 3, 3)
        f.rowconfigure(2, weight=1)

    def _tab_expert(self, f):
        ex = self.S['expert']
        self._chart(f, self._bars([(k.capitalize(), ex['severity'].get(k, 0)) for k in ('error', 'warning', 'note', 'chat')], 'By severity',
                                  colors={'Error': self.pal['danger'], 'Warning': self.pal['warn']}), 0, 0, height=200)
        self._chart(f, self._bars(ex['groups'], 'By group', n=12), 0, 1, height=200)
        cols = [('severity', 'Severity', 75, 'w', lambda v: v.capitalize()), ('group', 'Group', 110, 'w', None), ('count', 'Count', 60, 'e', None),
                ('summary', 'Summary', 700, 'w', None)]
        table = DataTable(f, cols, height=12)
        table.grid(row=1, column=0, columnspan=2, sticky='nsew', padx=4, pady=4)
        table.set_rows([{'severity': s, 'group': g, 'count': c, 'summary': m} for (s, g, m), c in ex['messages']])
        self._weights(f, 2, 2)
        f.rowconfigure(1, weight=2)

    def _tab_capture(self, f):
        S, meta = self.S, self.S['meta'] or {}
        rows = [('File', self.state.source_label), ('Format', meta.get('format', '?')),
                ('First packet', format_local_time(S['first_time'], 0)[:-13] if S['packets'] else '-'),
                ('Last packet', format_local_time(S['last_time'], 0)[:-13] if S['packets'] else '-'),
                ('Elapsed', fmt_dur(S['duration'])), ('Packets', f"{S['packets']:,}")]
        for sec in meta.get('sections', []):
            for label, key in (('Hardware', 'hardware'), ('OS', 'os'), ('Capture application', 'application'), ('File comment', 'comment')):
                if sec.get(key):
                    rows.append((f'Section {sec["index"]}: {label}', sec[key]))
        for it in meta.get('interfaces', []):
            tag = f'Interface {it["id"]}' + (f' ({it["name"]})' if it.get('name') else '')
            rows.append((tag, f'link type {it["link_type"]} ({LINK_NAMES.get(it["link_type"], "?")}), snap length {it["snaplen"]}, timestamp resolution {it["tsresol"]}'))
            for label, key in (('Description', 'description'), ('Capture filter', 'filter'), ('OS', 'os'), ('Hardware', 'hardware'), ('MAC', 'mac')):
                if it.get(key):
                    rows.append((f'  {label}', it[key]))
            if it.get('speed'):
                rows.append(('  Speed', fmt_bitrate(it['speed'])))
        for st in meta.get('if_stats', []):
            rows.append((f'Statistics, interface {st["iface"]}', f'received {st["recv"]}, dropped by capture system {st["drop"]}'
                         + (f', comment: {st["comment"]}' if st.get('comment') else '')))
        for sct in meta.get('secrets', []):
            rows.append(('Embedded decryption secrets', f'{sct["type"]}, {sct["bytes"]} bytes (present in file; Fathom does not decrypt TLS)'))
        if meta.get('name_resolution'):
            rows.append(('Name resolution records', f'{len(meta["name_resolution"])} (e.g. {meta["name_resolution"][0][0]} = {meta["name_resolution"][0][1]})'))
        for w_ in self.state.warnings:
            rows.append(('\u26a0 Warning', w_))
        for no, c in S['comments'][:50]:
            rows.append((f'Packet {no} comment', c))
        t = DataTable(f, [('k', 'Property', 240, 'w', None), ('v', 'Value', 800, 'w', None)], height=24)
        t.set_rows([{'k': a, 'v': b} for a, b in rows])
        t.pack(fill='both', expand=True, padx=6, pady=6)


class ExpertWindow:
    """Expert Information grouped like Wireshark: one row per distinct finding with a packet count; expand to see packets."""

    def __init__(self, parent, packets, colors, theme, mono_font, ui_font, on_goto, on_filter):
        self.on_goto, self.on_filter, self.packets = on_goto, on_filter, packets
        self.by_no = {p.number: p for p in packets}
        self.groups = build_expert_groups(packets)
        self.colors = colors
        top = self.top = tk.Toplevel(parent)
        top.title('Expert Information')
        top.geometry('1100x620')
        top.minsize(760, 400)
        top.configure(background=colors['bg'])
        counts = collections.Counter()
        for g in self.groups:
            counts[g['severity']] += g['count']
        head = tk.Frame(top, background=colors['bg'])
        head.pack(fill='x', padx=10, pady=(10, 4))
        tk.Label(head, text=f'{sum(counts.values()):,} findings in {len(self.groups)} groups', background=colors['bg'],
                 foreground=colors['text'], font=(ui_font, 11, 'bold')).pack(side='left')
        sevcol = {'error': colors['danger'], 'warning': colors['warn'], 'note': colors['text'], 'chat': colors['text_dim']}
        self.vars = {}
        ctl = tk.Frame(top, background=colors['bg'])
        ctl.pack(fill='x', padx=10, pady=(0, 6))
        for sev in ('error', 'warning', 'note', 'chat'):
            self.vars[sev] = tk.BooleanVar(value=True)
            tk.Checkbutton(ctl, text=f'{sev.capitalize()}s ({counts.get(sev, 0):,})', variable=self.vars[sev], command=self.refresh,
                           background=colors['bg'], foreground=sevcol[sev], selectcolor=colors['panel_alt'], activebackground=colors['bg'],
                           activeforeground=sevcol[sev], font=(ui_font, 10, 'bold')).pack(side='left', padx=(0, 12))
        tk.Label(ctl, text='Group:', background=colors['bg'], foreground=colors['text_dim']).pack(side='left', padx=(10, 4))
        self.group_cb = ttk.Combobox(ctl, values=['All groups'] + sorted({g['group'] for g in self.groups}), state='readonly', width=16)
        self.group_cb.current(0)
        self.group_cb.pack(side='left')
        self.group_cb.bind('<<ComboboxSelected>>', lambda e: self.refresh())
        tk.Label(ctl, text='Search:', background=colors['bg'], foreground=colors['text_dim']).pack(side='left', padx=(12, 4))
        self.search = tk.StringVar()
        ent = tk.Entry(ctl, textvariable=self.search, width=28, background=colors['input_bg'], foreground=colors['text'],
                       insertbackground=colors['text'], relief='flat', highlightthickness=1, highlightbackground=colors['border'])
        ent.pack(side='left', ipady=2)
        ent.bind('<KeyRelease>', lambda e: self.refresh())
        ttk.Button(ctl, text='Apply as filter', style='Toolbar.TButton', command=self._apply_filter).pack(side='right', padx=(6, 0))
        ttk.Button(ctl, text='Export CSV\u2026', style='Toolbar.TButton', command=self._export).pack(side='right')

        fr = tk.Frame(top, background=colors['bg'])
        fr.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        self.tree = ttk.Treeview(fr, columns=('summary', 'group', 'protocol', 'count'), show='tree headings')
        self.tree.heading('#0', text='Severity / packet')
        self.tree.column('#0', width=190, stretch=False)
        for c, t_, w, anc, st in (('summary', 'Summary', 560, 'w', True), ('group', 'Group', 110, 'w', False),
                                  ('protocol', 'Protocol', 80, 'w', False), ('count', 'Count', 60, 'e', False)):
            self.tree.heading(c, text=t_)
            self.tree.column(c, width=w, anchor=anc, stretch=st)
        sc = ttk.Scrollbar(fr, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=sc.set)
        self.tree.pack(side='left', fill='both', expand=True)
        sc.pack(side='right', fill='y')
        for sev, col in sevcol.items():
            self.tree.tag_configure(sev, foreground=col)
        self.tree.bind('<Double-1>', self._activate)
        self.tree.bind('<Return>', self._activate)
        self.refresh()

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        grp, q = self.group_cb.get(), self.search.get().strip().lower()
        for i, g in enumerate(self.groups):
            if not self.vars[g['severity']].get() or (grp != 'All groups' and g['group'] != grp):
                continue
            if q and q not in g['summary'].lower() and q not in g['group'].lower():
                continue
            node = self.tree.insert('', 'end', iid=f'g{i}', text=g['severity'].capitalize(),
                                    values=(g['summary'], g['group'], g['protocol'], f"{g['count']:,}"), tags=(g['severity'],))
            for n in g['packets'][:300]:
                p = self.by_no.get(n)
                self.tree.insert(node, 'end', iid=f'g{i}p{n}', text=f'Packet {n}',
                                 values=((p.summary['info'][:140] if p else ''), '', (p.summary['protocol'] if p else ''), ''))
            if g['count'] > 300:
                self.tree.insert(node, 'end', text='\u2026', values=(f'{g["count"] - 300:,} more packets (use Apply as filter)', '', '', ''))

    def _selected(self):
        sel = self.tree.selection()
        if not sel:
            return None, None
        iid = sel[0]
        if 'p' in iid[1:]:
            gi, pn = iid[1:].split('p')
            return self.groups[int(gi)], int(pn)
        return (self.groups[int(iid[1:])] if iid.startswith('g') else None), None

    def _activate(self, _e=None):
        g, pn = self._selected()
        if pn:
            self.on_goto(pn)

    def _apply_filter(self):
        g, pn = self._selected()
        if pn:
            self.on_filter(f'frame.number=={pn}')
        elif g:
            txt = g['summary'].replace('"', '')[:40]
            self.on_filter(f'expert.message contains "{txt}"')

    def _export(self):
        path = filedialog.asksaveasfilename(parent=self.top, title='Export expert info', defaultextension='.csv',
                                            initialfile='fathom-expert.csv', filetypes=[('CSV', '*.csv')])
        if not path:
            return
        with open(path, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['Severity', 'Group', 'Summary', 'Protocol', 'Count', 'Packets'])
            for g in self.groups:
                w.writerow([g['severity'], g['group'], g['summary'], g['protocol'], g['count'], ' '.join(map(str, g['packets'][:2000]))])


class TimeSeqWindow:
    def __init__(self, parent, st, colors, theme):
        top = tk.Toplevel(parent)
        top.title(f'TCP stream {st["id"]} \u2014 time / sequence graph')
        top.geometry('960x560')
        top.configure(background=colors['bg'])
        pal = chart_palette(theme)
        ChartCanvas(top, lambda w, h, p: chart_timeseq(st, w, h, p), pal, height=500).pack(fill='both', expand=True, padx=8, pady=8)


class FollowStreamWindow:
    def __init__(self, parent, title, st, chunks, colors, mono_font, ui_font):
        top = tk.Toplevel(parent)
        top.title(title)
        top.geometry('860x600')
        top.configure(background=colors['bg'])
        self.chunks, self.colors, self.mono_font = chunks, colors, mono_font
        a, b = st['a'], st['b']
        total = [sum(len(c) for d, c in chunks if d == 0), sum(len(c) for d, c in chunks if d == 1)]
        bar = tk.Frame(top, background=colors['bg'])
        bar.pack(fill='x', padx=10, pady=8)
        tk.Label(bar, text=f'{a[0]}:{a[1]} \u2192 {b[0]}:{b[1]}: {total[0]:,} bytes   |   {b[0]}:{b[1]} \u2192 {a[0]}:{a[1]}: {total[1]:,} bytes',
                 background=colors['bg'], foreground=colors['text'], font=(ui_font, 10, 'bold')).pack(side='left')
        self.mode = tk.StringVar(value='ascii')
        for label_, val in (('ASCII', 'ascii'), ('Hex', 'hex')):
            ttk.Radiobutton(bar, text=label_, value=val, variable=self.mode, command=self._render).pack(side='right', padx=4)
        fr = tk.Frame(top, background=colors['bg'])
        fr.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        self.text = tk.Text(fr, wrap='word', font=(mono_font, 10), background=colors['panel'], foreground=colors['text'],
                            borderwidth=0, highlightthickness=0)
        sc = ttk.Scrollbar(fr, orient='vertical', command=self.text.yview)
        self.text.configure(yscrollcommand=sc.set)
        self.text.pack(side='left', fill='both', expand=True)
        sc.pack(side='right', fill='y')
        self.text.tag_configure('c0', foreground=colors['danger'])
        self.text.tag_configure('c1', foreground='#4C9FE0' if colors['bg'] < '#808080' else '#1D6FB8')
        self._render()

    def _render(self):
        self.text.configure(state='normal')
        self.text.delete('1.0', 'end')
        for d, data in self.chunks:
            if self.mode.get() == 'hex':
                for i in range(0, len(data), 16):
                    row = data[i:i + 16]
                    self.text.insert('end', f'{i:06x}  {row.hex(" "):<47}  {"".join(chr(c) if 32 <= c < 127 else "." for c in row)}\n', f'c{d}')
            else:
                self.text.insert('end', ''.join(chr(c) if 32 <= c < 127 or c in (9, 10, 13) else '.' for c in data) + '\n', f'c{d}')
        self.text.configure(state='disabled')


class FathomApp:
    ROW_HEADERS = {'no': 'No.', 'time': 'Time', 'src': 'Source', 'dst': 'Destination',
                   'proto': 'Protocol', 'dir': 'Dir', 'len': 'Len', 'info': 'Info'}
    ROW_WIDTHS = {'accent': 10, 'no': 55, 'time': 95, 'src': 170, 'dst': 170, 'proto': 75, 'dir': 48, 'len': 60, 'info': 520}

    def __init__(self, root, state):
        self.root, self.state = root, state
        self.selected_pkt = None
        self.item_to_pkt = {}
        self._filter_after_id = None
        self.sort_column, self.sort_reverse = None, False
        self.font_size = 10
        self.mono_font = resolve_font(MONOSPACE_STACK) if tkfont else 'Courier'
        self.ui_font = resolve_font(UI_FONT_STACK, fallback='TkDefaultFont') if tkfont else 'Helvetica'
        self.autoscroll_var = tk.BooleanVar(value=True)
        self.show_marked_only_var = tk.BooleanVar(value=False)
        self.show_absolute_time_var = tk.BooleanVar(value=False)
        self.recent_files = load_recent_files()
        self.tooltip = None
        self._find_dialog = None
        self._find_matches, self._find_index = [], -1
        self._hex_layer_ranges = {}
        self._hovered_layer = None
        self._hovered_row = None
        self._build_ui()
        self._apply_theme()
        if state.packets:
            self._refresh_table_full()
        self._update_capture_button()
        if self.state.live:
            self.root.after(300, self._poll_live)

    # ---- construction ----
    def _build_ui(self):
        root = self.root
        root.title(f'Fathom \u2014 packet inspector  v{FATHOM_VERSION.split()[0]}')
        root.geometry('1300x800')
        root.minsize(900, 600)
        self.style = ttk.Style()
        for theme in ('clam', 'default'):
            if theme in self.style.theme_names():
                try:
                    self.style.theme_use(theme)
                    break
                except Exception:
                    continue
        self._build_menu()

        self.toolbar = tk.Frame(root)
        self.toolbar.pack(side='top', fill='x')
        pad = dict(padx=(10, 0), pady=9)
        self.btn_open = ttk.Button(self.toolbar, text='Open\u2026', style='Toolbar.TButton', command=self.action_open)
        self.btn_open.pack(side='left', **pad)
        self.capture_btn = ttk.Button(self.toolbar, text='Start Capture', style='Primary.TButton', command=self.action_toggle_capture)
        self.capture_btn.pack(side='left', **pad)
        self.autoscroll_chk = ttk.Checkbutton(self.toolbar, text='Auto-scroll', variable=self.autoscroll_var, style='Toolbar.TCheckbutton')
        self.autoscroll_chk.pack(side='left', padx=(14, 0), pady=9)
        self.btn_export = ttk.Button(self.toolbar, text='Export CSV\u2026', style='Toolbar.TButton', command=self.action_export)
        self.btn_export.pack(side='left', **pad)
        self.btn_stats = ttk.Button(self.toolbar, text='Statistics', style='Toolbar.TButton', command=self.action_stats)
        self.btn_stats.pack(side='left', **pad)
        self.btn_expert = ttk.Button(self.toolbar, text='Expert Info', style='Toolbar.TButton', command=self.action_expert)
        self.btn_expert.pack(side='left', **pad)
        self.theme_btn = ttk.Button(self.toolbar, text='\u2600 Light', width=8, style='Toolbar.TButton', command=self.action_toggle_theme)
        self.theme_btn.pack(side='right', padx=(0, 10), pady=9)
        self.source_label = tk.Label(self.toolbar, text=self.state.source_label, font=(self.mono_font, 10))
        self.source_label.pack(side='right', padx=(0, 14))

        self.filterbar = tk.Frame(root)
        self.filterbar.pack(side='top', fill='x')
        self.filter_icon = tk.Label(self.filterbar, text='\u25b8', font=(self.mono_font, 11))
        self.filter_icon.pack(side='left', padx=(12, 6), pady=7)
        self.filter_var = tk.StringVar()
        self.filter_entry = tk.Entry(self.filterbar, textvariable=self.filter_var, font=(self.mono_font, 11),
                                     relief='flat', borderwidth=0, highlightthickness=1)
        self.filter_entry.pack(side='left', fill='x', expand=True, pady=7, ipady=4)
        self.filter_entry.bind('<KeyRelease>', self._on_filter_changed)
        self.filter_count_label = tk.Label(self.filterbar, text='', font=(self.mono_font, 10), anchor='e')
        self.filter_count_label.pack(side='left', padx=(10, 14))

        main_pane = ttk.PanedWindow(root, orient='vertical')
        main_pane.pack(side='top', fill='both', expand=True)
        table_frame = tk.Frame(main_pane)
        columns = ('accent', 'no', 'time', 'src', 'dst', 'proto', 'dir', 'len', 'info')
        self.tree = ttk.Treeview(table_frame, columns=columns, show='headings', selectmode='browse')
        self.tree.heading('accent', text='')
        self.tree.column('accent', width=self.ROW_WIDTHS['accent'], minwidth=8, anchor='center', stretch=False)
        for col in columns[1:]:
            self.tree.heading(col, text=self.ROW_HEADERS[col], anchor=('e' if col == 'len' else ('center' if col == 'dir' else 'w')),
                              command=lambda c=col: self.action_sort_by(c))
            self.tree.column(col, width=self.ROW_WIDTHS[col], anchor=('e' if col == 'len' else ('center' if col == 'dir' else 'w')), stretch=(col == 'info'))
        vsb = ttk.Scrollbar(table_frame, orient='vertical', command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        hsb.pack(side='bottom', fill='x')
        self.tree.pack(side='left', fill='both', expand=True)
        vsb.pack(side='right', fill='y')
        self.tree.bind('<<TreeviewSelect>>', self._on_row_selected)
        self.tree.bind('<Motion>', self._on_tree_motion)
        self.tree.bind('<Leave>', self._on_tree_leave)
        self.tree.bind('<Button-3>', self._show_context_menu)
        self.tree.bind('<Button-2>', self._show_context_menu)
        self.tree.bind('<Control-Button-1>', self._show_context_menu)
        self.tree.bind('m', self._toggle_mark_selected)
        main_pane.add(table_frame, weight=3)

        detail_pane = ttk.PanedWindow(main_pane, orient='horizontal')
        detail_frame = tk.Frame(detail_pane)
        self.detail_tree = ttk.Treeview(detail_frame, show='tree')
        self.detail_tree.column('#0', width=520, stretch=True)
        dvsb = ttk.Scrollbar(detail_frame, orient='vertical', command=self.detail_tree.yview)
        self.detail_tree.configure(yscrollcommand=dvsb.set)
        self.detail_tree.pack(side='left', fill='both', expand=True)
        dvsb.pack(side='right', fill='y')
        self.detail_tree.bind('<Motion>', self._on_detail_motion)
        self.detail_tree.bind('<Leave>', lambda e: self._clear_hex_hover())
        detail_pane.add(detail_frame, weight=2)

        hex_frame = tk.Frame(detail_pane)
        self.hex_text = tk.Text(hex_frame, wrap='none', font=(self.mono_font, 11), borderwidth=0, highlightthickness=0)
        hvsb = ttk.Scrollbar(hex_frame, orient='vertical', command=self.hex_text.yview)
        self.hex_text.configure(yscrollcommand=hvsb.set, state='disabled')
        self.hex_text.pack(side='left', fill='both', expand=True)
        hvsb.pack(side='right', fill='y')
        detail_pane.add(hex_frame, weight=1)
        main_pane.add(detail_pane, weight=2)
        self._main_pane, self._detail_pane, self._table_frame = main_pane, detail_pane, table_frame

        self.status_bar = tk.Frame(root)
        self.status_bar.pack(side='bottom', fill='x')
        self.status_left = tk.Label(self.status_bar, text=('Ready' if self.state.packets or self.state.live else 'Open a capture file to begin (Ctrl+O)'), anchor='w', font=(self.ui_font, 10), padx=10, pady=3)
        self.status_left.pack(side='left', fill='x', expand=True)
        self.status_right = tk.Label(self.status_bar, text='', anchor='e', font=(self.ui_font, 10), padx=10, pady=3)
        self.status_right.pack(side='right')

        self.tooltip = Tooltip(self.tree, theme_colors(self.state.theme), self.mono_font)
        self._show_detail(None)
        self._update_count_label()

        for seq, fn in (('<Control-o>', self.action_open), ('<Control-e>', self.action_export), ('<Control-t>', self.action_stats),
                        ('<Control-g>', self.action_goto_packet), ('<Control-G>', self.action_goto_packet),
                        ('<Control-F>', self.action_find), ('<Control-E>', self.action_expert),
                        ('<Control-d>', self.action_toggle_theme)):
            root.bind(seq, lambda e, fn=fn: fn())
        root.bind('<Control-q>', lambda e: root.quit())
        root.bind('<Control-f>', lambda e: self.filter_entry.focus_set())
        root.bind('<Control-equal>', lambda e: self.action_zoom(1))
        root.bind('<Control-plus>', lambda e: self.action_zoom(1))
        root.bind('<Control-minus>', lambda e: self.action_zoom(-1))
        root.bind('<Control-0>', lambda e: self.action_zoom(0))

    def _build_menu(self):
        root = self.root
        menubar = tk.Menu(root)
        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label='Open capture\u2026', command=self.action_open, accelerator='Ctrl+O')
        self.recent_menu = tk.Menu(file_menu, tearoff=False)
        file_menu.add_cascade(label='Open Recent', menu=self.recent_menu)
        self._refresh_recent_menu()
        file_menu.add_separator()
        file_menu.add_command(label='Export filtered as CSV\u2026', command=self.action_export, accelerator='Ctrl+E')
        file_menu.add_command(label='Export filtered as pcap\u2026', command=self.action_export_pcap)
        file_menu.add_command(label='Export filtered as JSON (all decoded fields)\u2026', command=self.action_export_json)
        file_menu.add_command(label='Export statistics report (HTML with charts)\u2026', command=self.action_export_report)
        file_menu.add_separator()
        file_menu.add_command(label='Quit', command=root.quit, accelerator='Ctrl+Q')
        menubar.add_cascade(label='File', menu=file_menu)

        capture_menu = tk.Menu(menubar, tearoff=False)
        capture_menu.add_command(label='Start / stop capture\u2026', command=self.action_toggle_capture)
        menubar.add_cascade(label='Capture', menu=capture_menu)

        view_menu = tk.Menu(menubar, tearoff=False)
        view_menu.add_command(label='Toggle dark / light theme', command=self.action_toggle_theme, accelerator='Ctrl+D')
        view_menu.add_command(label='Zoom in', command=lambda: self.action_zoom(1), accelerator='Ctrl+=')
        view_menu.add_command(label='Zoom out', command=lambda: self.action_zoom(-1), accelerator='Ctrl+-')
        view_menu.add_command(label='Reset zoom', command=lambda: self.action_zoom(0), accelerator='Ctrl+0')
        view_menu.add_separator()
        view_menu.add_checkbutton(label='Show only marked packets', variable=self.show_marked_only_var, command=self._apply_filter_now)
        view_menu.add_checkbutton(label='Show absolute time', variable=self.show_absolute_time_var, command=self._on_time_format_changed)
        menubar.add_cascade(label='View', menu=view_menu)

        go_menu = tk.Menu(menubar, tearoff=False)
        go_menu.add_command(label='Find in view\u2026', command=self.action_find, accelerator='Ctrl+Shift+F')
        go_menu.add_command(label='Go to packet\u2026', command=self.action_goto_packet, accelerator='Ctrl+G')
        menubar.add_cascade(label='Go', menu=go_menu)

        analyze_menu = tk.Menu(menubar, tearoff=False)
        analyze_menu.add_command(label='Expert Information\u2026', command=self.action_expert, accelerator='Ctrl+Shift+E')
        analyze_menu.add_command(label='Statistics (charts, conversations, TCP, DNS, STUN, RTP\u2026)\u2026', command=self.action_stats, accelerator='Ctrl+T')
        analyze_menu.add_command(label='Capture properties (interfaces, comments, drops)\u2026', command=lambda: self.action_stats('Capture'))
        analyze_menu.add_command(label='I/O graph\u2026', command=lambda: self.action_stats('I/O Graph'))
        analyze_menu.add_command(label='TCP stream graph of selected packet\u2026', command=self.action_timeseq)
        analyze_menu.add_separator()
        analyze_menu.add_command(label='Follow TCP stream of selected packet\u2026', command=self.action_follow_stream)
        analyze_menu.add_command(label='Filter: selected packet\'s stream', command=self.action_filter_stream)
        analyze_menu.add_command(label='Filter: inbound packets only', command=lambda: self._set_filter('frame.direction=="inbound"'))
        analyze_menu.add_command(label='Filter: outbound packets only', command=lambda: self._set_filter('frame.direction=="outbound"'))
        analyze_menu.add_separator()
        analyze_menu.add_command(label='Show only problems (tcp.analysis.flags or expert)', command=lambda: self._set_filter('tcp.analysis.flags or expert'))
        menubar.add_cascade(label='Analyze', menu=analyze_menu)

        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(label='Filter syntax\u2026', command=self.action_help)
        help_menu.add_command(label='Keyboard shortcuts\u2026', command=self.action_shortcuts)
        menubar.add_cascade(label='Help', menu=help_menu)
        root.config(menu=menubar)
        self.menubar = menubar

    # ---- theming ----
    def _apply_theme(self):
        c = theme_colors(self.state.theme)
        s = self.style
        self.root.configure(background=c['bg'])
        s.configure('.', background=c['panel'], foreground=c['text'], font=(self.ui_font, 10))
        s.configure('TFrame', background=c['panel'])
        s.configure('TLabel', background=c['panel'], foreground=c['text'])
        s.configure('TRadiobutton', background=c['bg'], foreground=c['text'])
        s.configure('TNotebook', background=c['bg'], borderwidth=0)
        s.configure('TNotebook.Tab', background=c['panel_alt'], foreground=c['text_dim'], padding=(12, 5), borderwidth=0)
        s.map('TNotebook.Tab', background=[('selected', c['panel'])], foreground=[('selected', c['text'])])
        s.configure('Toolbar.TButton', background=c['panel_alt'], foreground=c['text'], bordercolor=c['border'],
                    focusthickness=0, padding=(10, 5), relief='flat')
        s.map('Toolbar.TButton', background=[('active', c['hover'])])
        s.configure('Primary.TButton', background=c['accent'], foreground=c['statusbar_text'], bordercolor=c['accent'],
                    focusthickness=0, padding=(10, 5), relief='flat')
        s.map('Primary.TButton', background=[('active', c['accent_hover'])])
        s.configure('Toolbar.TCheckbutton', background=c['panel'], foreground=c['text'])
        s.map('Toolbar.TCheckbutton', background=[('active', c['panel'])])
        # Dropdowns: the 'clam' theme paints read-only boxes and the highlighted selection in its own pale colours, so give every state a colour
        s.configure('TCombobox', fieldbackground=c['input_bg'], foreground=c['text'], background=c['panel_alt'], arrowcolor=c['text'],
                    bordercolor=c['border'], lightcolor=c['panel_alt'], darkcolor=c['panel_alt'],
                    selectbackground=c['selected'], selectforeground=c['text'])
        s.map('TCombobox',
              fieldbackground=[('readonly', c['input_bg']), ('focus', c['input_bg']), ('disabled', c['panel_alt'])],
              foreground=[('readonly', c['text']), ('focus', c['text']), ('disabled', c['text_faint'])],
              background=[('active', c['hover']), ('pressed', c['hover'])],
              selectbackground=[('readonly', c['selected']), ('focus', c['selected'])],
              selectforeground=[('readonly', c['text']), ('focus', c['text'])],
              arrowcolor=[('disabled', c['text_faint'])])
        s.configure('TEntry', fieldbackground=c['input_bg'], foreground=c['text'], insertcolor=c['text'], bordercolor=c['border'])
        s.map('TEntry', fieldbackground=[('focus', c['input_bg']), ('readonly', c['input_bg'])], foreground=[('focus', c['text'])])
        for opt, val in (('background', c['input_bg']), ('foreground', c['text']), ('selectBackground', c['selected']), ('selectForeground', c['text'])):
            self.root.option_add(f'*TCombobox*Listbox.{opt}', val)       # the pop-up list of choices
        s.configure('TScrollbar', background=c['panel_alt'], troughcolor=c['bg'], bordercolor=c['border'], arrowcolor=c['text_dim'])
        s.configure('TPanedwindow', background=c['bg'])
        s.configure('Sash', sashthickness=6)
        s.configure('Treeview', background=c['bg'], fieldbackground=c['bg'], foreground=c['text'], borderwidth=0,
                    rowheight=int(self.font_size * 2.3), font=(self.mono_font, self.font_size))
        s.configure('Treeview.Heading', background=c['panel'], foreground=c['text_dim'], borderwidth=1, relief='flat',
                    font=(self.ui_font, self.font_size - 1, 'bold'))
        s.map('Treeview.Heading', background=[('active', c['hover'])])
        s.map('Treeview', background=[('selected', c['selected'])])

        for key, color in PROTO_COLORS.get(self.state.theme, PROTO_COLORS['dark']).items():
            self.tree.tag_configure('p_' + key, foreground=color)
        self.tree.tag_configure('sev_error', foreground=c['danger'])
        self.tree.tag_configure('sev_warn', foreground=c['warn'])
        self.tree.tag_configure('even', background=c['bg'])
        self.tree.tag_configure('odd', background=c['zebra'])
        self.tree.tag_configure('marked', background=('#4a3f1f' if self.state.theme == 'dark' else '#fff3cd'))
        self.tree.tag_configure('rowhover', background=c['hover'])
        for i in range(6):
            color = layer_color(i, self.state.theme)
            self.detail_tree.tag_configure(f'layer{i}', foreground=color)
            self.hex_text.tag_configure(f'hexlayer{i}', foreground=color)
        self.hex_text.tag_configure('hexfaint', foreground=c['text_faint'])
        self.hex_text.tag_configure('hexhover', background=c['selected'])
        self.toolbar.configure(background=c['panel'])
        self.filterbar.configure(background=c['panel'])
        self.filter_icon.configure(background=c['panel'], foreground=c['text_faint'])
        self.filter_entry.configure(background=c['input_bg'], foreground=c['text'], insertbackground=c['text'],
                                    highlightbackground=c['border'], highlightcolor=c['accent'])
        self.filter_count_label.configure(background=c['panel'], foreground=c['text_dim'])
        self.source_label.configure(background=c['panel'], foreground=c['text_dim'])
        self.hex_text.configure(background=c['bg'], foreground=c['text'], insertbackground=c['text'])
        self._table_frame.configure(background=c['bg'])
        self.status_bar.configure(background=c['accent'])
        self.status_left.configure(background=c['accent'], foreground=c['statusbar_text'])
        self.status_right.configure(background=c['accent'], foreground=c['statusbar_text'])
        self.theme_btn.configure(text=('\u2600 Light' if self.state.theme == 'dark' else '\u263e Dark'))
        if self.tooltip:
            self.tooltip.set_colors(c)
        self._update_status_right()

    # ---- table rendering ----
    def _current_displayed_packets(self):
        source = self.state.filtered
        if self.show_marked_only_var.get():
            source = [p for p in source if p.summary['no'] in self.state.marked]
        if self.sort_column:
            source = sort_packets(source, self.sort_column, self.sort_reverse)
        return source

    def _refresh_table_full(self):
        source = self._current_displayed_packets()
        self.tree.delete(*self.tree.get_children())
        self.item_to_pkt.clear()
        self._hovered_row = None
        for i, p in enumerate(source):
            self._insert_row(p, index=i, see=False)
        self._update_count_label()
        self._update_sort_indicators()

    def _row_tags(self, p, index):
        sev = packet_severity(p)
        fg = 'sev_error' if sev == 'error' else ('sev_warn' if sev == 'warning' else 'p_' + proto_key(p.summary['protocol']))
        tags = [fg, 'odd' if index % 2 else 'even']
        if p.summary['no'] in self.state.marked:
            tags.append('marked')
        return tuple(tags)

    def _insert_row(self, p, index=None, see=True):
        s = p.summary
        iid = str(s['no'])
        if index is None:
            index = len(self.tree.get_children())
        values = ('\u2503', s['no'], display_time(p, absolute=self.show_absolute_time_var.get()), s['src'], s['dst'],
                  s['protocol'], {'in': '\u2193 in', 'out': '\u2191 out'}.get(s.get('dir'), ''), s['length'], s['info'])
        self.tree.insert('', 'end', iid=iid, values=values, tags=self._row_tags(p, index))
        self.item_to_pkt[iid] = p
        if see and self.autoscroll_var.get() and self.selected_pkt is None:
            self.tree.see(iid)

    def _on_time_format_changed(self):
        self._refresh_table_full()

    def _update_count_label(self):
        shown = len(self.tree.get_children())
        text = f"{shown:,} of {len(self.state.packets):,} packets"
        if self.state.filter_mode == 'plain' and self.state.filter_text.strip():
            text += '  \u00b7 plain text'
        if self.show_marked_only_var.get():
            text += '  \u00b7 marked only'
        self.filter_count_label.config(text=text)
        self.source_label.config(text=self.state.source_label)

    def _update_sort_indicators(self):
        for col in SORT_COLUMNS:
            label = self.ROW_HEADERS[col]
            if col == self.sort_column:
                label += (' \u25bc' if self.sort_reverse else ' \u25b2')
            self.tree.heading(col, text=label)

    def _set_status(self, text, error=False):
        c = theme_colors(self.state.theme)
        self.status_left.config(text=text, foreground=c['statusbar_text'])

    def _update_status_right(self):
        theme_word = 'Dark' if self.state.theme == 'dark' else 'Light'
        capture_word = 'Capturing' if self.state.capturing else ('Live' if self.state.live else None)
        self.status_right.config(text='  \u2022  '.join(p for p in (capture_word, theme_word) if p))

    def _expert_summary(self):
        rows = collect_expert(self.state.packets)
        e = sum(1 for r in rows if r['severity'] == 'error')
        w = sum(1 for r in rows if r['severity'] == 'warning')
        return e, w

    # ---- detail / hex panes ----
    def _on_row_selected(self, _event=None):
        sel = self.tree.selection()
        pkt = self.item_to_pkt.get(sel[0]) if sel else None
        self.selected_pkt = pkt
        self._show_detail(pkt)

    def _insert_fields(self, parent, fields, tags):
        for fld in fields:
            label, value = fld[0], fld[1]
            node = self.detail_tree.insert(parent, 'end', text=field_text(label, value), tags=tags)
            if len(fld) > 2 and fld[2]:
                self._insert_fields(node, fld[2], tags)

    def _show_detail(self, pkt):
        self.detail_tree.delete(*self.detail_tree.get_children())
        self._hovered_layer = None
        if not pkt:
            self.detail_tree.insert('', 'end', text='(select a packet above to inspect it)')
            self._show_hex(None)
            return
        for i, layer in enumerate(pkt.layers):
            tags = (f'layer{i % 6}', f'layerfull{i}')
            parent = self.detail_tree.insert('', 'end', text=layer['name'] + layer.get('summary', ''), open=(i != 0), tags=tags)
            self._insert_fields(parent, layer['fields'], tags)
        self._show_hex(pkt)

    def _show_hex(self, pkt):
        self.hex_text.configure(state='normal')
        self.hex_text.delete('1.0', 'end')
        self._hex_layer_ranges = {}
        self._hovered_layer = None
        if pkt:
            for line in build_hex_lines(pkt.raw, pkt.layers):
                self._insert_colored(line['offset'] + '  ', None, faint=True)
                for text, li in line['hex']:
                    self._insert_colored(text, li)
                self._insert_colored(' ', None)
                for text, li in line['ascii']:
                    self._insert_colored(text, li)
                self.hex_text.insert('end', '\n')
        self.hex_text.configure(state='disabled')

    def _insert_colored(self, text, layer_idx, faint=False):
        if not text:
            return
        start = self.hex_text.index('end-1c')
        self.hex_text.insert('end', text)
        end = self.hex_text.index('end-1c')
        if layer_idx is None:
            if faint:
                self.hex_text.tag_add('hexfaint', start, end)
            return
        self.hex_text.tag_add(f'hexlayer{layer_idx % 6}', start, end)
        self._hex_layer_ranges.setdefault(layer_idx, []).append((start, end))

    def _on_detail_motion(self, event):
        item = self.detail_tree.identify_row(event.y)
        if not item:
            self._clear_hex_hover()
            return
        layer_idx = None
        for t in self.detail_tree.item(item, 'tags'):
            if t.startswith('layerfull'):
                try:
                    layer_idx = int(t[len('layerfull'):])
                except ValueError:
                    pass
        if layer_idx == self._hovered_layer:
            return
        self._clear_hex_hover()
        if layer_idx is not None and layer_idx in self._hex_layer_ranges:
            for start, end in self._hex_layer_ranges[layer_idx]:
                self.hex_text.tag_add('hexhover', start, end)
            self.hex_text.tag_raise('hexhover')
            self._hovered_layer = layer_idx

    def _clear_hex_hover(self):
        if self._hovered_layer is not None:
            self.hex_text.tag_remove('hexhover', '1.0', 'end')
            self._hovered_layer = None

    # ---- tooltips / hover ----
    def _on_tree_motion(self, event):
        row = self.tree.identify_row(event.y)
        if row != self._hovered_row:
            self._set_row_hover(self._hovered_row, False)
            self._set_row_hover(row, True)
            self._hovered_row = row
        col = self.tree.identify_column(event.x)
        if not row or not col:
            self.tooltip.cancel()
            return
        try:
            col_index = int(col.replace('#', '')) - 1
        except ValueError:
            self.tooltip.cancel()
            return
        columns = self.tree['columns']
        if not (0 <= col_index < len(columns)) or columns[col_index] not in ('src', 'dst', 'info'):
            self.tooltip.cancel()
            return
        colname = columns[col_index]
        value = self.tree.set(row, colname)
        if not value:
            self.tooltip.cancel()
            return
        self.tooltip.schedule((row, colname), value, self.tree.winfo_rootx() + event.x + 14, self.tree.winfo_rooty() + event.y + 18)

    def _on_tree_leave(self, _event=None):
        if self.tooltip:
            self.tooltip.cancel()
        self._set_row_hover(self._hovered_row, False)
        self._hovered_row = None

    def _set_row_hover(self, iid, hovering):
        if not iid or not self.tree.exists(iid):
            return
        current = [t for t in self.tree.item(iid, 'tags') if t not in ('rowhover', 'odd', 'even')]
        if hovering:
            current.append('rowhover')
        else:
            current.append('odd' if self.tree.index(iid) % 2 else 'even')
        self.tree.item(iid, tags=tuple(current))

    # ---- context menu / marking ----
    def _show_context_menu(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.tree.selection_set(row)
        pkt = self.item_to_pkt.get(row)
        if not pkt:
            return
        c = theme_colors(self.state.theme)
        menu = tk.Menu(self.root, tearoff=False, background=c['panel_alt'], foreground=c['text'],
                       activebackground=c['hover'], activeforeground=c['text'])
        s = pkt.summary
        menu.add_command(label=f"Filter to protocol: {s['protocol']}", command=lambda: self._set_filter(quick_filter_for_protocol(pkt)))
        for lbl, flt in ((f"Filter to source: {s['src']}", quick_filter_for_source(pkt)),
                         (f"Filter to destination: {s['dst']}", quick_filter_for_destination(pkt)),
                         ('Filter to this conversation', quick_filter_for_conversation(pkt)),
                         ('Filter to this stream', quick_filter_for_stream(pkt))):
            if flt:
                menu.add_command(label=lbl, command=lambda f=flt: self._set_filter(f))
        if pkt.flat.f.get('frame.proc.id') is not None:
            menu.add_command(label=f"Filter to process: {pkt.flat.f.get('frame.proc.name')} ({pkt.flat.f['frame.proc.id']})",
                             command=lambda: self._set_filter(f"frame.proc.id=={pkt.flat.f['frame.proc.id']}"))
        if pkt.flat.direction:
            menu.add_command(label=f'Filter to {pkt.flat.direction} packets', command=lambda: self._set_filter(f'frame.direction=="{pkt.flat.direction}"'))
        if pkt.flat.tcp and pkt.flat.stream is not None:
            menu.add_command(label='Follow TCP stream\u2026', command=self.action_follow_stream)
            menu.add_command(label='TCP stream graph\u2026', command=self.action_timeseq)
        menu.add_separator()
        menu.add_command(label='Copy Info', command=lambda: self._copy_to_clipboard(s['info']))
        menu.add_command(label='Copy Source', command=lambda: self._copy_to_clipboard(str(s['src'])))
        menu.add_command(label='Copy Destination', command=lambda: self._copy_to_clipboard(str(s['dst'])))
        menu.add_separator()
        menu.add_command(label=('Unmark packet' if s['no'] in self.state.marked else 'Mark packet'), command=lambda: self._toggle_mark(pkt))
        menu.add_command(label='Go to packet\u2026', command=self.action_goto_packet)
        menu.tk_popup(event.x_root, event.y_root)

    def _toggle_mark_selected(self, _event=None):
        if self.selected_pkt:
            self._toggle_mark(self.selected_pkt)

    def _toggle_mark(self, pkt):
        now_marked = toggle_mark(self.state, pkt.summary['no'])
        iid = str(pkt.summary['no'])
        if self.tree.exists(iid):
            tags = list(self.tree.item(iid, 'tags'))
            if now_marked and 'marked' not in tags:
                tags.append('marked')
            elif not now_marked and 'marked' in tags:
                tags.remove('marked')
            self.tree.item(iid, tags=tuple(tags))
        self._set_status(f"Packet {pkt.summary['no']} {'marked' if now_marked else 'unmarked'}.")
        if self.show_marked_only_var.get():
            self._refresh_table_full()

    def _copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._set_status(f'Copied: {text}')

    def _set_filter(self, text):
        self.filter_var.set(text)
        self._apply_filter_now()

    # ---- filter ----
    def _on_filter_changed(self, _event=None):
        if self._filter_after_id:
            self.root.after_cancel(self._filter_after_id)
        self._filter_after_id = self.root.after(150, self._apply_filter_now)

    def _apply_filter_now(self):
        self.state.filter_text = self.filter_var.get()
        apply_filter(self.state)
        self._refresh_table_full()

    # ---- recent files ----
    def _add_recent(self, path):
        self.recent_files = add_recent_file(self.recent_files, path)
        self._refresh_recent_menu()

    def _refresh_recent_menu(self):
        self.recent_menu.delete(0, 'end')
        if not self.recent_files:
            self.recent_menu.add_command(label='(no recent files)', state='disabled')
            return
        for path in self.recent_files:
            self.recent_menu.add_command(label=os.path.basename(path), command=lambda p=path: self._open_path(p))

    # ---- actions ----
    def _after_load(self, label_text):
        self.filter_var.set('')
        self.state.filter_text = ''
        apply_filter(self.state)
        self.selected_pkt = None
        self.sort_column = None
        self.show_marked_only_var.set(False)
        self._refresh_table_full()
        self._show_detail(None)
        e, w = self._expert_summary()
        self._update_expert_button()
        extra = f' \u00b7 {e} error(s), {w} warning(s) \u2014 see Analyze \u2192 Expert Information' if (e or w) else ''
        warn = f' \u00b7 \u26a0 {self.state.warnings[0]}' if self.state.warnings else ''
        self._set_status(label_text + extra + warn)

    def _open_path(self, path):
        try:
            n = load_file_into_state(self.state, path)
            self._add_recent(path)
            self._after_load(f'Loaded {n:,} packets from {os.path.basename(path)}')
        except Exception as e:
            messagebox.showerror('Could not open file', str(e))
            self._set_status(f'Could not open {path}: {e}', error=True)

    def action_open(self):
        path = filedialog.askopenfilename(title='Open capture file', filetypes=[
            ('Capture files', '*.pcap *.pcapng *.cap *.dmp *.gz'), ('All files', '*.*')])
        if path:
            self._open_path(path)

    def _export(self, kind, ext, fn, filetypes):
        if not self.state.filtered:
            messagebox.showinfo('Nothing to export', 'There are no packets in the current view to export.')
            return
        path = filedialog.asksaveasfilename(title=f'Export filtered packets as {kind}', defaultextension=f'.{ext}',
                                            initialfile=default_export_filename(ext), filetypes=filetypes)
        if not path:
            return
        try:
            fn(self.state, path)
            self._set_status(f'Exported {len(self.state.filtered):,} packets to {path}')
        except Exception as e:
            messagebox.showerror('Export failed', str(e))

    def action_export(self):
        self._export('CSV', 'csv', export_csv_to_path, [('CSV files', '*.csv')])

    def action_export_pcap(self):
        self._export('pcap', 'pcap', export_pcap_to_path, [('pcap files', '*.pcap'), ('All files', '*.*')])

    def action_export_json(self):
        self._export('JSON', 'json', export_json_to_path, [('JSON files', '*.json')])

    def _filter_from_window(self, text):
        self._set_filter(text)
        try:
            self.root.lift()
        except Exception:
            pass

    def action_stats(self, tab=None):
        if not self.state.packets:
            messagebox.showinfo('Statistics', 'Open a capture first.')
            return
        Plot.font_family = self.ui_font
        StatsWindow(self.root, self.state, theme_colors(self.state.theme), self.state.theme, self.mono_font, self.ui_font,
                    self._filter_from_window, self._open_timeseq, tab if isinstance(tab, str) else None)

    def action_expert(self):
        ExpertWindow(self.root, self.state.packets, theme_colors(self.state.theme), self.state.theme,
                     self.mono_font, self.ui_font, self._goto_number, self._filter_from_window)

    def _open_timeseq(self, stream_id):
        Plot.font_family = self.ui_font
        TimeSeqWindow(self.root, self.state.analysis.stream_list[stream_id], theme_colors(self.state.theme), self.state.theme)

    def action_timeseq(self):
        p = self.selected_pkt
        if not p or not p.flat.tcp or p.flat.stream is None:
            messagebox.showinfo('TCP stream graph', 'Select a TCP packet first.')
            return
        self._open_timeseq(p.flat.stream)

    def action_export_report(self):
        if not self.state.packets:
            messagebox.showinfo('Report', 'Open a capture first.')
            return
        path = filedialog.asksaveasfilename(title='Export statistics report', defaultextension='.html',
                                            initialfile='fathom-report.html', filetypes=[('HTML report', '*.html')])
        if path:
            try:
                Plot.font_family = self.ui_font
                export_stats_html(self.state, path, 'light')
                self._set_status(f'Report written to {path}')
            except Exception as e:
                messagebox.showerror('Report failed', str(e))

    def _update_expert_button(self):
        e, w = self._expert_summary()
        self.btn_expert.config(text=f'Expert Info ({e}E {w}W)' if (e or w) else 'Expert Info')

    def action_help(self):
        messagebox.showinfo('Filter syntax', HELP_TEXT)

    def action_shortcuts(self):
        messagebox.showinfo('Keyboard shortcuts', SHORTCUTS_TEXT)

    def _goto_number(self, number):
        iid = str(number)
        if iid in self.item_to_pkt:
            self.tree.selection_set(iid)
            self.tree.see(iid)
            self.tree.focus(iid)
        else:
            messagebox.showinfo('Not visible', f'Packet {number} exists but is hidden by the current filter.')

    def action_goto_packet(self):
        if not self.state.packets:
            return
        val = simpledialog.askinteger('Go to packet', 'Packet number:', parent=self.root, minvalue=1, maxvalue=len(self.state.packets))
        if val:
            self._goto_number(val)

    def action_follow_stream(self):
        p = self.selected_pkt
        if not p or not p.flat.tcp or p.flat.stream is None:
            messagebox.showinfo('Follow stream', 'Select a TCP packet first.')
            return
        st, chunks = follow_stream_text(self.state.analysis, None, p.flat.stream)
        FollowStreamWindow(self.root, f'Follow TCP stream {p.flat.stream}', st, chunks, theme_colors(self.state.theme),
                           self.mono_font, self.ui_font)

    def action_filter_stream(self):
        p = self.selected_pkt
        flt = quick_filter_for_stream(p) if p else ''
        if flt:
            self._set_filter(flt)

    def action_find(self):
        if self._find_dialog:
            self._find_dialog.top.lift()
            self._find_dialog.top.focus_force()
            return
        self._find_dialog = FindDialog(self.root, theme_colors(self.state.theme), self._on_find_search,
                                       self._on_find_navigate, self._on_find_close)

    def _on_find_search(self, query):
        self._find_matches = find_matches(self._current_displayed_packets(), query)
        self._find_index = 0 if self._find_matches else -1
        if self._find_dialog:
            self._find_dialog.set_count(self._find_index, len(self._find_matches))
        if self._find_matches:
            self._select_find_match()

    def _on_find_navigate(self, direction):
        if not self._find_matches:
            return
        self._find_index = (self._find_index + direction) % len(self._find_matches)
        if self._find_dialog:
            self._find_dialog.set_count(self._find_index, len(self._find_matches))
        self._select_find_match()

    def _select_find_match(self):
        pkt = self._current_displayed_packets()[self._find_matches[self._find_index]]
        iid = str(pkt.summary['no'])
        if self.tree.exists(iid):
            self.tree.selection_set(iid)
            self.tree.see(iid)
            self.tree.focus(iid)

    def _on_find_close(self):
        self._find_dialog = None
        self._find_matches, self._find_index = [], -1

    def action_sort_by(self, col):
        if self.sort_column == col:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column, self.sort_reverse = col, False
        self._refresh_table_full()

    def action_toggle_theme(self):
        self.state.theme = 'light' if self.state.theme == 'dark' else 'dark'
        self._apply_theme()
        self._refresh_table_full()
        self._show_detail(self.selected_pkt)

    def action_zoom(self, direction):
        self.font_size = 10 if direction == 0 else max(8, min(18, self.font_size + direction))
        self.hex_text.configure(font=(self.mono_font, self.font_size))
        self.style.configure('Treeview', font=(self.mono_font, self.font_size), rowheight=int(self.font_size * 2.3))
        self.filter_entry.configure(font=(self.mono_font, self.font_size + 1))

    def _stop_capture(self):
        self.state.live.stop()
        self.state.capturing = False
        finish_live(self.state)
        self._refresh_table_full()
        self._set_status('Capture stopped.')
        self._update_capture_button()

    def action_toggle_capture(self):
        if self.state.live and self.state.capturing:
            self._stop_capture()
            return
        if not self.state.live:
            if not is_scapy_available():
                messagebox.showerror('scapy required', 'Live capture requires scapy.\n\nInstall it with:\n\n    pip install scapy')
                return
            try:
                interfaces = list_interfaces()
            except Exception as e:
                messagebox.showerror('Could not list interfaces', str(e))
                return
            choice = InterfaceDialog(self.root, interfaces, theme_colors(self.state.theme)).show()
            if not choice or not choice[0]:
                return
            iface, bpf = choice
            self.state.live = LiveCapture(iface=iface, bpf_filter=bpf)
            self.state.source_label = f'live: {iface}'
        try:
            self.state.live.start()
            self.state.capturing = True
            self._set_status(f'Capturing on {self.state.source_label.replace("live: ", "")}\u2026')
            self.root.after(300, self._poll_live)
        except Exception as e:
            messagebox.showerror('Could not start capture', str(e))
            self.state.capturing = False
        self._update_capture_button()
        self._update_count_label()

    def _update_capture_button(self):
        if hasattr(self, 'capture_btn'):
            self.capture_btn.config(text=('Stop Capture' if self.state.capturing else 'Start Capture'))
        if hasattr(self, 'status_right'):
            self._update_status_right()

    def _poll_live(self):
        if self.state.live and self.state.capturing:
            items, error, done = self.state.live.poll()
            if items:
                prev_len = len(self.state.filtered)
                ingest_live_packets(self.state, items)
                for p in self.state.filtered[prev_len:]:
                    self._insert_row(p)
                self._update_count_label()
            if error:
                self.state.capturing = False
                finish_live(self.state)
                self._refresh_table_full()
                self._set_status(f'Capture error: {error}', error=True)
                self._update_capture_button()
            elif done:
                self.state.capturing = False
                finish_live(self.state)
                self._refresh_table_full()
                self._set_status('Capture stopped.')
                self._update_capture_button()
        if self.state.live and self.state.capturing:
            self.root.after(300, self._poll_live)


def launch_gui(state):
    root = tk.Tk()
    FathomApp(root, state)

    def _on_close():
        if state.live and state.capturing:
            state.live.stop()
        root.destroy()

    root.protocol('WM_DELETE_WINDOW', _on_close)
    root.mainloop()


# ============================================================================
# PART 10 -- command-line entry point
# ============================================================================

def _tkinter_install_hint():
    if sys.platform == 'darwin':
        return ("Install it with Homebrew:\n    brew install python-tk\n"
                "(if you installed Python from python.org instead of Homebrew, Tkinter\n"
                "should already be included \u2014 try reinstalling Python from python.org)")
    if sys.platform.startswith('linux'):
        return ("Install it with your package manager, e.g.:\n"
                "    sudo apt install python3-tk        # Debian/Ubuntu\n"
                "    sudo dnf install python3-tkinter   # Fedora\n"
                "    sudo pacman -S tk                  # Arch")
    return "Install Python's Tkinter package for your platform."


def build_arg_parser():
    p = argparse.ArgumentParser(prog=os.path.basename(sys.argv[0]) or 'fathom.py', description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--version', action='version', version=f'Fathom {FATHOM_VERSION}')
    p.add_argument('file', nargs='?', help='a .pcap / .pcapng (optionally .gz) file to open')
    p.add_argument('--live', metavar='INTERFACE', help='capture live from this network interface (needs scapy + sudo)')
    p.add_argument('--capture-filter', metavar='BPF', default=None, help='BPF capture filter for --live, e.g. "udp port 3478"')
    p.add_argument('--count', type=int, default=0, help='stop --live capture after N packets (0 = unlimited)')
    p.add_argument('--save', metavar='PATH', default=None, help='also write --live packets to this .pcap file as they arrive')
    p.add_argument('--list-interfaces', action='store_true', help='list available network interfaces and exit')
    p.add_argument('--theme', choices=['dark', 'light'], default='dark', help='starting theme (default: dark)')
    p.add_argument('--text', action='store_true', help='no GUI: print a Wireshark-style packet list to stdout')
    p.add_argument('-v', '--verbose', action='store_true', help='with --text: also print the full decoded tree of every packet')
    p.add_argument('-Y', '--filter', metavar='EXPR', default='', help='display filter, e.g. "stun or rtp" (GUI start-up filter, or for --text/--json)')
    p.add_argument('--json', metavar='PATH', default=None, help='no GUI: write every decoded field of the (filtered) packets to a JSON file')
    p.add_argument('--pcapng-info', action='store_true', help='no GUI: list every pcapng block/option kind in the file (Apple process data, unknown options)')
    p.add_argument('--stats', action='store_true', help='no GUI: print capture statistics (protocols, conversations, TCP/DNS/HTTP/TLS/STUN/RTP, expert)')
    p.add_argument('--stats-html', metavar='PATH', default=None, help='no GUI: write an HTML report with SVG charts')
    p.add_argument('--expert', action='store_true', help='no GUI: print Expert Information (errors / warnings / notes)')
    return p


def main(argv=None):
    args = build_arg_parser().parse_args(argv)

    if args.list_interfaces:
        try:
            for name in list_interfaces():
                print(name)
        except LiveCaptureError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        return 0

    state = AppState(export_dir=os.getcwd())
    state.theme = args.theme
    headless = args.text or args.json or args.expert or args.stats or args.stats_html or args.pcapng_info

    if args.file and args.live:
        print("Error: pass either a file or --live, not both.", file=sys.stderr)
        return 1

    log = sys.stderr if headless else sys.stdout
    if args.file:
        print(f"Parsing {args.file} \u2026", file=log)
        try:
            n = load_file_into_state(state, args.file)
        except Exception as e:
            print(f"Could not open {args.file}: {e}", file=sys.stderr)
            return 1
        print(f"Loaded {n} packets.", file=log)
        for w in state.warnings:
            print(f"Warning: {w}", file=sys.stderr)

    if args.filter:
        state.filter_text = args.filter
        apply_filter(state)
        if state.filter_mode == 'plain':
            print(f"Note: '{args.filter}' is not a valid display filter; used as a plain text search.", file=sys.stderr)

    if headless:
        if not args.file:
            print("Error: --text / --json / --expert / --stats / --pcapng-info need a capture file.", file=sys.stderr)
            return 1
        if args.text:
            print_packet_list(state, verbose=args.verbose)
        if args.pcapng_info:
            print_pcapng_info(state)
        if args.expert:
            print_expert(state)
        if args.stats:
            print_statistics(build_statistics(state.packets, state.analysis, state.meta))
        if args.stats_html:
            export_stats_html(state, args.stats_html)
            print(f"Wrote statistics report to {args.stats_html}", file=sys.stderr)
        if args.json:
            export_json_to_path(state, args.json)
            print(f"Wrote {len(state.filtered)} packets to {args.json}", file=sys.stderr)
        return 0

    if args.live:
        if not is_scapy_available():
            print("Error: --live requires scapy.  Install it with:  pip install scapy", file=sys.stderr)
            return 1
        if hasattr(os, 'geteuid') and os.geteuid() != 0:
            print("Note: live capture usually needs root \u2014 if it fails to open the interface, try again with sudo.")
        state.live = LiveCapture(iface=args.live, bpf_filter=args.capture_filter, count=args.count)
        state.source_label = f"live: {args.live}"
        if args.save:
            state.save_pcap_path = args.save
        try:
            state.live.start()
            state.capturing = True
        except Exception as e:
            print(f"Could not start capture: {e}", file=sys.stderr)
            return 1

    try:
        import tkinter  # noqa: F401
    except ImportError:
        print("Error: this app needs Tkinter, which isn't installed for this Python.\n", file=sys.stderr)
        print(_tkinter_install_hint(), file=sys.stderr)
        print("\nTip: you can still analyse without a GUI:  python3 fathom.py FILE --text -v", file=sys.stderr)
        return 1

    try:
        launch_gui(state)
    except tkinter.TclError as e:
        print(f"Error: could not open a graphical window ({e}).", file=sys.stderr)
        print("If you're on a remote/SSH session, this app needs a local display "
              "(e.g. `ssh -X` for X11 forwarding), or use --text for terminal output.", file=sys.stderr)
        return 1
    finally:
        if state.live and state.capturing:
            state.live.stop()
    return 0


if __name__ == '__main__':
    sys.exit(main())