#!/usr/bin/env python3
"""
pcapsum — Deep PCAP/PCAPNG analysis tool for CTF players.

Usage:
    pcapsum <file>                Full analysis
    pcapsum -q <file>             Quick mode
    pcapsum -f <file>             Flag hunt only
    pcapsum -e http <file>        Extract HTTP objects
    pcapsum -s 0 <file>           Follow TCP stream 0
    pcapsum -j <file>             JSON output

Requires: tshark (Wireshark CLI) in PATH.
No dependencies — pure Python 3.8+ stdlib.
"""

__version__ = "4.1"

import argparse
import base64
import hashlib
import json
import math
import os
import re
import shutil
import string
import struct
import subprocess
import sys
import threading
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Fix Unicode output on Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ═══════════════════════════════════════════════════════════════════════════════
# Colors
# ═══════════════════════════════════════════════════════════════════════════════

NO_COLOR = False

def _a(code):
    return f"\033[{code}m" if not NO_COLOR else ""

RST  = lambda: _a("0")
BOLD = lambda: _a("1")
DIM  = lambda: _a("2")
ITAL = lambda: _a("3")
ULINE= lambda: _a("4")
RED  = lambda: _a("31")
GRN  = lambda: _a("32")
YEL  = lambda: _a("33")
BLU  = lambda: _a("34")
MAG  = lambda: _a("35")
CYN  = lambda: _a("36")
WHT  = lambda: _a("37")
BRED = lambda: _a("1;31")
BGRN = lambda: _a("1;32")
BYEL = lambda: _a("1;33")
BBLU = lambda: _a("1;34")
BMAG = lambda: _a("1;35")
BCYN = lambda: _a("1;36")
BG_RED = lambda: _a("41")
BG_GRN = lambda: _a("42")
BG_YEL = lambda: _a("43")

# ═══════════════════════════════════════════════════════════════════════════════
# Output helpers
# ═══════════════════════════════════════════════════════════════════════════════

W = 70

def o(msg=""): print(msg)
def nl(): print()

def banner(title, char="━"):
    line = char * W
    o(f"{BCYN()}{line}{RST()}")
    o(f"{BCYN()}  {title}{RST()}")
    o(f"{BCYN()}{line}{RST()}")

def h1(title):
    o(f"\n{BOLD()}{BCYN()}┌{'─'*(W-2)}┐{RST()}")
    o(f"{BOLD()}{BCYN()}│ {title:<{W-3}}│{RST()}")
    o(f"{BOLD()}{BCYN()}└{'─'*(W-2)}┘{RST()}")

def h2(title, count=None):
    tag = f" ({count})" if count is not None else ""
    o(f"\n{BCYN()}▸ {title}{tag}{RST()}")

def h3(title):
    o(f"\n  {BOLD()}{title}{RST()}")

def kv(k, v, indent=2):
    pad = " " * indent
    o(f"{pad}{BOLD()}{k}:{RST()} {v}")

def dim(msg, indent=4):
    pad = " " * indent
    o(f"{pad}{DIM()}{msg}{RST()}")

def alert(msg):
    o(f"  {BRED()}⚠ {msg}{RST()}")

def found(msg):
    o(f"  {BGRN()}✓ {msg}{RST()}")

def info(msg):
    o(f"  {BCYN()}ℹ {msg}{RST()}")

def warn(msg):
    o(f"  {BYEL()}⚡ {msg}{RST()}")

def err(msg):
    o(f"  {BRED()}✗ {msg}{RST()}")

def table(rows, headers, max_rows=80):
    if not rows: return
    ansi_re = re.compile(r'\033\[[0-9;]*m')
    def _vis(s): return ansi_re.sub("", str(s))

    widths = [len(h) for h in headers]
    for row in rows[:max_rows]:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = min(max(widths[i], len(_vis(cell))), 60)

    hdr = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    o(f"    {BOLD()}{hdr}{RST()}")
    o(f"    {'  '.join('─' * w for w in widths)}")
    for row in rows[:max_rows]:
        cells = []
        for i, c in enumerate(row):
            s = str(c)
            vis_len = len(_vis(s))
            if i < len(widths):
                pad = widths[i] - vis_len
                s = s + " " * max(pad, 0)
            cells.append(s)
        o(f"    {'  '.join(cells)}")
    if len(rows) > max_rows:
        dim(f"... {len(rows) - max_rows} more rows", 4)

# Multiple flag patterns for different CTF competitions
FLAG_PATTERNS = [
    re.compile(r'[A-Za-z0-9_]{2,15}\{[^\}]{1,120}\}'),             # Standard: CTF{...}, flag{...}, KEY{...}
    re.compile(r'(?:flag|FLAG|ctf|CTF)\s*[:=]\s*["\']?([^\s"\']{4,80})', re.I),  # flag=xxx, flag: xxx
    re.compile(r'(?:flag|FLAG|ctf|CTF)\s*(?:is|was)\s*[:=]?\s*["\']?([^\s"\']{4,60})', re.I),  # "flag is xxx"
]

# Common CTF flag prefixes for more targeted searching
CTF_PREFIXES = [
    "flag", "FLAG", "ctf", "CTF", "key", "KEY", "secret", "SECRET",
    "picoCTF", "HTB", "THM", "DUCTF", "CCTF", "TUCTF", "UIUCTF",
    "justCTF", "corctf", "LITCTF", "BCACTF", "TJCTF", "ACTF",
    "lactf", "dice", "DEAD", "RITSEC", "UMASS", "MetaCTF",
]

def _is_plausible_flag(s):
    """Filter out binary-data false positives from flag regex matches."""
    printable = sum(1 for c in s if 32 <= ord(c) <= 126)
    if printable < len(s) * 0.85:
        return False
    bad = sum(1 for c in s if ord(c) < 32 or ord(c) > 126)
    if bad > max(2, len(s) * 0.1):
        return False
    return True

def flag_hunt(text):
    """Search text for flags using multiple patterns."""
    if not text: return []
    text = str(text)
    flags = set()
    for pat in FLAG_PATTERNS:
        for m in pat.finditer(text):
            f = m.group(0) if '{' in m.group(0) else m.group(1) if m.lastindex else m.group(0)
            if _is_plausible_flag(f):
                flags.add(f)
    # Also try base64 decoding chunks to find hidden flags
    b64_re = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
    for m in b64_re.finditer(text):
        try:
            decoded = base64.b64decode(m.group(0)).decode("utf-8", errors="ignore")
            for pat in FLAG_PATTERNS:
                for fm in pat.finditer(decoded):
                    f = fm.group(0) if '{' in fm.group(0) else fm.group(1) if fm.lastindex else fm.group(0)
                    if _is_plausible_flag(f):
                        flags.add(f"[b64] {f}")
        except Exception:
            pass
    for f in sorted(flags):
        o(f"  {BGRN()}🚩 FLAG: {f}{RST()}")
    return list(flags)


def _try_decode_data(data_hex):
    """Try multiple decodings on hex data: raw, base64, ROT13, XOR single-byte."""
    results = {}
    if not data_hex:
        return results
    clean = data_hex.replace(":", "").replace(" ", "")
    try:
        raw = bytes.fromhex(clean)
    except Exception:
        return results
    # UTF-8 decode
    text = raw.decode("utf-8", errors="ignore")
    if text.strip():
        results["raw"] = text
    # Base64 decode
    b64_re = re.compile(r'[A-Za-z0-9+/]{16,}={0,2}')
    for m in b64_re.finditer(text):
        try:
            decoded = base64.b64decode(m.group(0)).decode("utf-8", errors="ignore")
            if decoded.strip() and any(32 <= ord(c) <= 126 for c in decoded):
                results["base64"] = decoded[:500]
        except Exception:
            pass
    # ROT13
    rot13 = text.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
    for pat in FLAG_PATTERNS:
        if pat.search(rot13):
            results["rot13"] = rot13[:500]
            break
    # XOR single-byte (check common keys)
    for xor_key in range(1, 256):
        xored = bytes(b ^ xor_key for b in raw[:200])
        try:
            xtext = xored.decode("utf-8", errors="ignore")
            for pat in FLAG_PATTERNS:
                if pat.search(xtext):
                    results[f"xor_{xor_key:#04x}"] = xtext[:500]
                    break
        except Exception:
            pass
        if len(results) > 5:
            break
    return results


def human_size(n):
    for u, t in [("GB",1<<30),("MB",1<<20),("KB",1<<10)]:
        if n >= t: return f"{n/t:.1f} {u}"
    return f"{n} B"

def short_time(ts):
    if not ts: return ""
    if " " in ts:
        parts = ts.split()
        ts = parts[-2] if len(parts) >= 3 else parts[-1]
    if "." in ts: ts = ts.split(".")[0]
    return ts

def hex_decode(data):
    if not data: return data
    clean = data.strip().replace("\n","").replace("\r","").replace(" ","").replace(":","")
    if all(c in "0123456789abcdefABCDEF" for c in clean) and len(clean) >= 4:
        try: return bytes.fromhex(clean).decode("utf-8", errors="replace")
        except Exception: pass
    return data

# ═══════════════════════════════════════════════════════════════════════════════
# USB HID Keyboard Decoder (common CTF challenge)
# ═══════════════════════════════════════════════════════════════════════════════

USB_HID_KEYMAP = {
    0x04: ('a','A'), 0x05: ('b','B'), 0x06: ('c','C'), 0x07: ('d','D'),
    0x08: ('e','E'), 0x09: ('f','F'), 0x0A: ('g','G'), 0x0B: ('h','H'),
    0x0C: ('i','I'), 0x0D: ('j','J'), 0x0E: ('k','K'), 0x0F: ('l','L'),
    0x10: ('m','M'), 0x11: ('n','N'), 0x12: ('o','O'), 0x13: ('p','P'),
    0x14: ('q','Q'), 0x15: ('r','R'), 0x16: ('s','S'), 0x17: ('t','T'),
    0x18: ('u','U'), 0x19: ('v','V'), 0x1A: ('w','W'), 0x1B: ('x','X'),
    0x1C: ('y','Y'), 0x1D: ('z','Z'),
    0x1E: ('1','!'), 0x1F: ('2','@'), 0x20: ('3','#'), 0x21: ('4','$'),
    0x22: ('5','%'), 0x23: ('6','^'), 0x24: ('7','&'), 0x25: ('8','*'),
    0x26: ('9','('), 0x27: ('0',')'),
    0x28: ('\n','\n'), 0x29: ('[ESC]','[ESC]'), 0x2A: ('[BKSP]','[BKSP]'),
    0x2B: ('\t','\t'), 0x2C: (' ',' '),
    0x2D: ('-','_'), 0x2E: ('=','+'), 0x2F: ('[','{'), 0x30: (']','}'),
    0x31: ('\\','|'), 0x33: (';',':'), 0x34: ("'",'"'), 0x35: ('`','~'),
    0x36: (',','<'), 0x37: ('.','>'), 0x38: ('/','?'),
    0x39: ('[CAPS]','[CAPS]'),
    0x4F: ('[RIGHT]','[RIGHT]'), 0x50: ('[LEFT]','[LEFT]'),
    0x51: ('[DOWN]','[DOWN]'), 0x52: ('[UP]','[UP]'),
}

def decode_usb_hid(events):
    """Decode USB HID keyboard events into typed text."""
    result = []
    caps_lock = False
    for evt in events:
        raw = evt.strip().replace("|", "").replace(" ", "")
        # Remove colons for colon-separated format
        clean = raw.replace(":", "")
        if len(clean) < 4:
            continue
        try:
            data = bytes.fromhex(clean)
        except ValueError:
            continue
        # Standard USB HID keyboard report: [modifier, reserved, key1, key2, ...]
        # Sometimes only the key data portion (capdata) is present
        if len(data) >= 8:
            modifier = data[0]
            keycode = data[2]
        elif len(data) >= 3:
            modifier = data[0]
            keycode = data[2]
        elif len(data) >= 1:
            # Single byte - try as keycode
            modifier = 0
            keycode = data[0]
        else:
            continue
        if keycode == 0:
            continue
        shift = bool(modifier & 0x22)  # Left or Right Shift
        if keycode == 0x39:  # Caps Lock toggle
            caps_lock = not caps_lock
            continue
        if keycode in USB_HID_KEYMAP:
            lower, upper = USB_HID_KEYMAP[keycode]
            if keycode == 0x2A:  # Backspace
                if result:
                    result.pop()
                continue
            use_upper = shift ^ caps_lock if keycode <= 0x1D else shift
            result.append(upper if use_upper else lower)
        elif keycode >= 0x3A and keycode <= 0x45:
            result.append(f'[F{keycode - 0x39}]')
    return "".join(result)


def decode_usb_mouse(events):
    """Decode USB HID mouse events into coordinates. Returns list of (x,y,button) tuples."""
    coords = []
    x, y = 0, 0
    for evt in events:
        raw = evt.strip().replace("|", "").replace(" ", "").replace(":", "")
        if len(raw) < 6:
            continue
        try:
            data = bytes.fromhex(raw)
        except ValueError:
            continue
        if len(data) < 3:
            continue
        # Mouse report: [buttons, x_disp(signed), y_disp(signed), wheel]
        buttons = data[0]
        dx = struct.unpack('b', bytes([data[1]]))[0]
        dy = struct.unpack('b', bytes([data[2]]))[0]
        x += dx
        y += dy
        coords.append((x, y, buttons))
    return coords


def render_mouse_ascii(coords, width=80, height=30):
    """Render mouse coordinates as ASCII art (for terminal display)."""
    if not coords:
        return ""
    # Filter to only button-press points (drawing)
    drawn = [(x, y) for x, y, b in coords if b & 1]
    if not drawn:
        # If nothing drawn with button, use all points
        drawn = [(x, y) for x, y, _ in coords]
    if not drawn:
        return ""
    xs = [p[0] for p in drawn]
    ys = [p[1] for p in drawn]
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)
    range_x = max_x - min_x or 1
    range_y = max_y - min_y or 1
    grid = [[' '] * width for _ in range(height)]
    for px, py in drawn:
        col = int((px - min_x) / range_x * (width - 1))
        row = int((py - min_y) / range_y * (height - 1))
        col = max(0, min(width - 1, col))
        row = max(0, min(height - 1, row))
        grid[row][col] = '#'
    return "\n".join("".join(row) for row in grid)


# ═══════════════════════════════════════════════════════════════════════════════
# MAC Vendor OUI Lookup (top ~100 vendors for quick identification)
# ═══════════════════════════════════════════════════════════════════════════════

MAC_OUI = {
    "00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware",
    "00:1c:14": "VMware", "00:0f:4b": "Oracle VBox", "08:00:27": "Oracle VBox",
    "52:54:00": "QEMU/KVM", "00:16:3e": "Xen",
    "00:15:5d": "Hyper-V", "00:1a:11": "Google", "42:01:0a": "Google Cloud",
    "02:42:ac": "Docker", "02:42:": "Docker",
    "aa:bb:cc": "Test/CTF", "de:ad:be": "Test/CTF", "ca:fe:ba": "Test/CTF",
    "00:00:00": "Xerox", "ff:ff:ff": "Broadcast",
    "00:14:22": "Dell", "00:1e:c9": "Dell", "00:26:b9": "Dell",
    "3c:d9:2b": "HP", "00:1e:0b": "HP", "00:25:b3": "HP",
    "00:1c:42": "Parallels", "00:03:ff": "Microsoft",
    "00:0d:3a": "Microsoft Azure",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "00:1a:a0": "Dell", "f0:1f:af": "Dell",
    "00:25:00": "Apple", "a8:86:dd": "Apple", "14:7d:da": "Apple",
    "ac:de:48": "Apple", "00:1e:52": "Apple",
    "00:21:5a": "HP", "9c:b6:54": "HP",
    "00:1b:21": "Intel", "00:1e:67": "Intel", "68:05:ca": "Intel",
    "00:24:d7": "Intel", "a0:36:9f": "Intel",
    "00:18:8b": "Dell", "00:1a:6b": "Cisco",
    "00:1b:2a": "Cisco", "00:26:0b": "Cisco",
    "00:0c:85": "Cisco", "00:40:96": "Cisco",
}

def mac_vendor(mac):
    """Lookup MAC vendor from OUI prefix."""
    if not mac:
        return ""
    m = mac.lower().replace("-", ":").strip()
    # Try 8-char prefix first, then 6-char
    for prefix_len in [8, 6, 5]:
        prefix = m[:prefix_len]
        if prefix in MAC_OUI:
            return MAC_OUI[prefix]
    return ""


# ═══════════════════════════════════════════════════════════════════════════════
# Known Malicious Signatures Database
# ═══════════════════════════════════════════════════════════════════════════════

KNOWN_JA3 = {
    # Cobalt Strike
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike (default Java HTTPS)",
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike (stager)",
    "b742b407517bac9536a77a7b0fee28e9": "Cobalt Strike 4.2+",
    # Metasploit
    "5d65ea3fb1d4aa7d826733f2f2f7b9f0": "Metasploit Meterpreter",
    # Trickbot
    "e7d705a3286e19ea42f587b344ee6865": "Trickbot",
    # Emotet
    "4d7a28d6f2263ed61de88ca66eb011e3": "Emotet",
    # Dridex
    "51c64c77e60f3980eea90869b68c58a8": "Dridex",
}

KNOWN_JA3S = {
    "ae4edc6faf64d08308082ad26be60767": "Cobalt Strike (teamserver)",
    "e35df3e00ca4ef31d42b34bebaa2f86e": "Cobalt Strike 4.x",
    "fd4bc6cea4877646ccd62f0792ec0b62": "Cobalt Strike 4.x (alt)",
}

# Default C2 certificate patterns
C2_CERT_PATTERNS = [
    (r"O\s*=\s*Cobaltstrike", "Cobalt Strike default cert"),
    (r"CN\s*=\s*Major Cobalt Strike", "Cobalt Strike default cert"),
    (r"O\s*=\s*Rapid7", "Metasploit default cert"),
    (r"CN\s*=\s*localhost", "Self-signed localhost (C2 suspect)"),
    (r"CN\s*=\s*Mythic", "Mythic C2 default cert"),
    (r"O\s*=\s*YOURORGANIZATION", "Default/template cert"),
    (r"CN\s*=\s*test", "Test certificate (suspicious)"),
]

# Reverse shell payload signatures (regex patterns for stream content)
REVSHELL_PATTERNS = [
    (re.compile(r'/bin/(?:ba)?sh\s+-i', re.I), "Bash reverse shell"),
    (re.compile(r'import\s+socket\s*,\s*subprocess\s*,\s*os', re.I), "Python reverse shell"),
    (re.compile(r'socket\(AF_INET\s*,\s*SOCK_STREAM', re.I), "Python/C socket shell"),
    (re.compile(r'exec\s*\(\s*["\']?/bin/sh', re.I), "Exec /bin/sh"),
    (re.compile(r'New-Object\s+System\.Net\.Sockets\.TCPClient', re.I), "PowerShell reverse shell"),
    (re.compile(r'fsockopen\s*\(', re.I), "PHP reverse shell"),
    (re.compile(r'TCPSocket\.new\s*\(', re.I), "Ruby reverse shell"),
    (re.compile(r'socket\s*\(\s*S\s*,\s*PF_INET\s*,\s*SOCK_STREAM', re.I), "Perl reverse shell"),
    (re.compile(r'ncat\s+-e\s+/bin/', re.I), "Ncat reverse shell"),
    (re.compile(r'rm\s+/tmp/f\s*;\s*mkfifo\s+/tmp/f', re.I), "mkfifo reverse shell"),
    (re.compile(r'msfvenom|meterpreter|metasploit', re.I), "Metasploit reference"),
    (re.compile(r'powershell\s.*-[eE](?:nc|ncodedcommand)\s+[A-Za-z0-9+/=]{20,}', re.I), "PowerShell encoded command"),
    (re.compile(r'Invoke-Expression.*DownloadString', re.I), "PowerShell download cradle"),
    (re.compile(r'IEX\s*\(\s*New-Object', re.I), "PowerShell IEX cradle"),
]

# PowerShell specific patterns
POWERSHELL_PATTERNS = [
    (re.compile(r'powershell(?:\.exe)?\s+.*-[eE](?:nc|ncodedcommand)\s+([A-Za-z0-9+/=]{20,})', re.I), "EncodedCommand"),
    (re.compile(r'IEX\s*\(\s*\(?\s*New-Object\s+(?:Net\.WebClient|System\.Net\.WebClient)\s*\)\.Download(?:String|Data)\s*\(\s*["\']([^"\']+)', re.I), "Download cradle"),
    (re.compile(r'Invoke-(?:Mimikatz|Shellcode|ReflectivePE|Expression|WebRequest|RestMethod)', re.I), "Offensive PS cmdlet"),
    (re.compile(r'-(?:nop|noni|noprof|w\s+hidden|sta|windowstyle\s+hidden)', re.I), "Hidden PS flags"),
    (re.compile(r'\[Convert\]::FromBase64String', re.I), "PS base64 decode"),
    (re.compile(r'Add-Type\s+-TypeDefinition.*DllImport', re.I), "PS P/Invoke"),
    (re.compile(r'(?:AmsiUtils|amsiInitFailed|Bypass)', re.I), "AMSI bypass"),
]

# Mining pool domains
MINING_POOLS = [
    "pool.minexmr.com", "xmrpool.eu", "nanopool.org", "f2pool.com",
    "coinhive.com", "supportxmr.com", "hashvault.pro", "minergate.com",
    "dwarfpool.com", "nicehash.com", "ethermine.org", "2miners.com",
    "herominers.com", "unmineable.com", "moneroocean.stream",
    "pool.hashvault.pro", "monerohash.com",
]

# Known default credentials
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "P@ssw0rd"), ("admin", "123456"), ("root", "toor"),
    ("root", "root"), ("root", "password"), ("user", "user"),
    ("user", "password"), ("test", "test"), ("test", "test123"),
    ("guest", "guest"), ("administrator", "password"),
    ("administrator", "P@ssw0rd"), ("pi", "raspberry"),
    ("tomcat", "tomcat"), ("tomcat", "s3cret"), ("postgres", "postgres"),
    ("sa", "sa"), ("sa", "password"), ("ftp", "ftp"),
    ("cisco", "cisco"), ("ubnt", "ubnt"), ("mysql", "mysql"),
    ("oracle", "oracle"), ("admin", "1234"), ("admin", "12345"),
]

# File magic signatures for embedded file detection
FILE_SIGNATURES = [
    (b'\x4d\x5a', "PE32 executable"),
    (b'\x7fELF', "ELF binary"),
    (b'\xfd\x37\x7a\x58\x5a', "XZ archive"),
    (b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a', "PNG image"),
    (b'\xff\xd8\xff', "JPEG image"),
    (b'\x47\x49\x46\x38', "GIF image"),
    (b'\x25\x50\x44\x46', "PDF document"),
    (b'\xd0\xcf\x11\xe0', "MS Office (OLE)"),
    (b'\x52\x61\x72\x21', "RAR archive"),
    (b'\x37\x7a\xbc\xaf', "7-Zip archive"),
    (b'\xca\xfe\xba\xbe', "Java class / Mach-O fat"),
    (b'\xfe\xed\xfa\xce', "Mach-O 32-bit"),
    (b'\xfe\xed\xfa\xcf', "Mach-O 64-bit"),
    (b'\x23\x21', "Script (shebang)"),
    (b'PK', "ZIP/Office XML"),
    (b'SQLite format 3', "SQLite database"),
    (b'\x00\x00\x00\x1c\x66\x74\x79\x70', "MP4/MOV video"),
    (b'\x00\x00\x01\x00', "ICO icon"),
    (b'\x52\x49\x46\x46', "RIFF (WAV/AVI)"),
    (b'OggS', "OGG audio"),
    (b'\x1a\x45\xdf\xa3', "MKV/WebM video"),
]

def detect_file_signatures(data_bytes):
    """Check binary data for known file signatures."""
    found_sigs = []
    for sig, name in FILE_SIGNATURES:
        idx = data_bytes.find(sig)
        if idx != -1 and idx < len(data_bytes) - len(sig):
            found_sigs.append({"signature": name, "offset": idx, "hex": data_bytes[idx:idx+16].hex()})
    return found_sigs


# ═══════════════════════════════════════════════════════════════════════════════
# C2 Framework Signatures
# ═══════════════════════════════════════════════════════════════════════════════

C2_SIGNATURES = {
    "cobalt_strike": {
        "user_agents": [
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; BOIE9;ENUS)",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)",
        ],
        "uri_patterns": [
            r'/pixel\.gif', r'/submit\.php', r'/__utm\.gif',
            r'/ga\.js', r'/dpixel', r'/ptj', r'/fwlink',
            r'/updates?\.js', r'/jquery-\d+\.\d+\.\d+\.min\.js',
            r'/beacon\.js', r'/ca$', r'/push$',
        ],
        "named_pipes": ["\\\\\.\\pipe\\msagent_", "\\\\\.\\pipe\\MSSE-"],
        "beacon_indicators": [
            b'\x00\x00\xbe\xef',  # Cobalt Strike beacon magic
            b'\x00\x00\x00\x30',  # Config block marker
        ],
    },
    "metasploit": {
        "uri_patterns": [
            r'/[A-Za-z0-9_-]{4,8}$',  # Short random URI (Meterpreter)
        ],
        "payloads": [
            b'\xfc\xe8',  # Shellcode stub (x86)
            b'\xfc\x48\x83',  # Shellcode stub (x64)
        ],
        "ports": [4444, 4443, 8443, 5555, 1337, 31337, 6666, 6667, 9999],
    },
    "sliver": {
        "uri_patterns": [
            r'/[a-z]{8,12}\.woff', r'/[a-z]{8,12}\.js',
            r'/[a-z]{8,12}/[a-z]{8,12}',
        ],
    },
    "empire": {
        "uri_patterns": [
            r'/admin/get\.php', r'/news\.php', r'/login/process\.php',
        ],
        "user_agents": [
            "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
        ],
    },
    "covenant": {
        "uri_patterns": [r'/en-us/test\.html', r'/en-us/docs\.html'],
    },
}


def _detect_c2_in_http(http_traffic, http_posts=None):
    """Score HTTP traffic for C2 framework indicators."""
    c2_hits = defaultdict(lambda: {"score": 0, "indicators": [], "evidence": []})

    for line in http_traffic:
        p_ = line.split("|")
        if len(p_) < 10:
            continue
        uri = p_[6].strip() if len(p_) > 6 else ""
        ua = p_[9].strip() if len(p_) > 9 else ""
        host = p_[5].strip() if len(p_) > 5 else ""
        src = p_[2].strip() if len(p_) > 2 else ""
        dst = p_[3].strip() if len(p_) > 3 else ""

        for framework, sigs in C2_SIGNATURES.items():
            # Check user agents
            for known_ua in sigs.get("user_agents", []):
                if ua == known_ua:
                    c2_hits[framework]["score"] += 30
                    c2_hits[framework]["indicators"].append(f"Known {framework} UA")
                    c2_hits[framework]["evidence"].append(f"UA match: {ua[:60]}")

            # Check URI patterns
            for pat in sigs.get("uri_patterns", []):
                if re.search(pat, uri):
                    c2_hits[framework]["score"] += 15
                    c2_hits[framework]["indicators"].append(f"URI: {uri[:40]}")
                    c2_hits[framework]["evidence"].append(f"{src}->{dst} {uri[:60]}")

    # Filter to only significant matches
    return {k: v for k, v in c2_hits.items() if v["score"] >= 15}

# ═══════════════════════════════════════════════════════════════════════════════
# AES decryption (optional — for Havoc C2 traffic decryption)
# ═══════════════════════════════════════════════════════════════════════════════

_HAS_CRYPTO = False
_CRYPTO_LIB = None

try:
    from Crypto.Cipher import AES as _AES
    from Crypto.Util.Padding import unpad as _unpad
    _HAS_CRYPTO = True
    _CRYPTO_LIB = "pycryptodome"
except ImportError:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher
        from cryptography.hazmat.primitives.ciphers import algorithms as _alg
        from cryptography.hazmat.primitives.ciphers import modes as _modes
        from cryptography.hazmat.primitives import padding as _sym_padding
        _HAS_CRYPTO = True
        _CRYPTO_LIB = "cryptography"
    except ImportError:
        pass


def _aes_cbc_decrypt(data, key, iv):
    """AES-256-CBC decrypt. Returns bytes or None."""
    if not _HAS_CRYPTO or len(key) != 32 or len(iv) != 16:
        return None
    if not data or len(data) % 16 != 0:
        return None
    try:
        if _CRYPTO_LIB == "pycryptodome":
            cipher = _AES.new(key, _AES.MODE_CBC, iv)
            padded = cipher.decrypt(data)
            try:
                return _unpad(padded, _AES.block_size)
            except ValueError:
                return padded
        else:
            cipher = _Cipher(_alg.AES(key), _modes.CBC(iv))
            dec = cipher.decryptor()
            padded = dec.update(data) + dec.finalize()
            try:
                unpadder = _sym_padding.PKCS7(128).unpadder()
                return unpadder.update(padded) + unpadder.finalize()
            except Exception:
                return padded
    except Exception:
        return None


def _parse_havoc_checkin(payload, magic):
    """Parse Havoc agent checkin: 4B magic | 4B agent_id | 4B timestamp | blob."""
    if len(payload) < 12:
        return None
    if payload[:4] != magic:
        return None
    agent_id = struct.unpack(">I", payload[4:8])[0]
    timestamp = struct.unpack(">I", payload[8:12])[0]
    blob = payload[12:]
    result = {
        "agent_id": f"0x{agent_id:08x}",
        "timestamp": timestamp,
        "blob_size": len(blob),
        "blob_hex": blob[:64].hex(),
    }
    # Try to extract config from blob if large enough (sleep, jitter, etc.)
    if len(blob) >= 24:
        try:
            # Common Havoc metadata layout after decryption placeholder:
            # If unencrypted or after decryption: sleep(4) | jitter(4) | ...
            result["blob_header_hex"] = blob[:24].hex()
        except Exception:
            pass
    return result


def _parse_havoc_command(plaintext):
    """Parse decrypted Havoc command: 4B task_type | 4B length | data."""
    if len(plaintext) < 8:
        return None
    TASK_TYPES = {
        0: "NOP", 1: "CHECKIN", 2: "GET_JOB", 3: "NO_JOB",
        10: "SHELL", 11: "UPLOAD", 12: "DOWNLOAD", 13: "EXIT",
        14: "SLEEP", 15: "INJECT", 16: "SPAWN",
        20: "PROC_LIST", 21: "DIR_LIST", 22: "SCREENSHOT",
        30: "TOKEN_STEAL", 31: "TOKEN_MAKE", 32: "SOCKS_PROXY",
    }
    try:
        task_type = struct.unpack(">I", plaintext[:4])[0]
        data_len = struct.unpack(">I", plaintext[4:8])[0]
        data = plaintext[8:8 + min(data_len, len(plaintext) - 8)]
        task_name = TASK_TYPES.get(task_type, f"UNKNOWN({task_type})")
        try:
            data_text = data.decode("utf-8", errors="replace")
        except Exception:
            data_text = data.hex()[:200]
        return {
            "task_type": task_type,
            "task_name": task_name,
            "data_len": data_len,
            "data": data_text[:500],
        }
    except Exception:
        return None


def _detect_exfil_patterns(text):
    """Check if decrypted text looks like exfiltrated data."""
    indicators = []
    for pat, desc in [
        (r'(?:uid=\d+|root:|/bin/(?:ba)?sh)', "Unix shell output"),
        (r'(?:Volume Serial|Directory of|C:\\)', "Windows shell output"),
        (r'(?:BEGIN (?:RSA|CERTIFICATE|PGP))', "Crypto key/cert"),
        (r'(?:password|passwd|secret|token|api.?key)\s*[:=]', "Credential leak"),
        (r'(?:SELECT|INSERT|UPDATE|DELETE)\s+', "SQL output"),
    ]:
        if re.search(pat, text, re.I):
            indicators.append(desc)
    return indicators


# ═══════════════════════════════════════════════════════════════════════════════
# tshark interface
# ═══════════════════════════════════════════════════════════════════════════════

TSHARK = None
TIMEOUT = 120
VERBOSE = False
_WARNED = set()  # deduplicate tshark warnings

def find_tshark():
    global TSHARK
    TSHARK = shutil.which("tshark")
    if not TSHARK:
        for candidate in [r"C:\Program Files\Wireshark\tshark.exe",
                          r"C:\Program Files (x86)\Wireshark\tshark.exe",
                          "/usr/bin/tshark", "/usr/local/bin/tshark"]:
            if os.path.isfile(candidate):
                TSHARK = candidate; break
    if not TSHARK:
        if sys.platform == "win32":
            err("tshark not found. Install Wireshark from https://www.wireshark.org/download.html")
            err("Make sure to check 'TShark' during installation, then restart your terminal.")
        else:
            err("tshark not found. Install Wireshark: apt install tshark")
        sys.exit(1)

def _t(args, timeout=None):
    if timeout is None: timeout = TIMEOUT
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout,
                           text=True, errors="replace")
        # tshark often returns non-zero exit codes for warnings (truncated
        # packets, unknown protocols, etc.) while still producing valid
        # output on stdout.  Return stdout whenever it has content.
        if r.stdout and r.stdout.strip():
            if VERBOSE and r.returncode != 0 and r.stderr:
                msg = r.stderr.strip().split('\n')[0][:120]
                if msg not in _WARNED:
                    _WARNED.add(msg)
                    warn(f"tshark: {msg}")
            return r.stdout.strip()
        if VERBOSE and r.returncode != 0 and r.stderr:
            msg = r.stderr.strip().split('\n')[0][:120]
            if msg not in _WARNED:
                _WARNED.add(msg)
                warn(f"tshark: {msg}")
        return ""
    except subprocess.TimeoutExpired:
        if VERBOSE: warn(f"timeout: {' '.join(args[:5])}")
        return ""
    except FileNotFoundError:
        return ""

def tshark_fields(pcap, display_filter, fields, sep="|", limit=300):
    cmd = [TSHARK, "-r", pcap]
    if display_filter:
        cmd.extend(["-Y", display_filter])
    cmd.extend(["-T", "fields"])
    for f in fields:
        cmd.extend(["-e", f])
    cmd.extend(["-E", f"separator={sep}"])
    out = _t(cmd)
    return out.splitlines()[:limit] if out else []

def tshark_stat(pcap, stat):
    return _t([TSHARK, "-r", pcap, "-q", "-z", stat])

def tshark_follow(pcap, proto, stream_id, max_chars=800):
    out = _t([TSHARK, "-r", pcap, "-q", "-z",
              f"follow,{proto},ascii,{stream_id}"], timeout=15)
    return out[:max_chars] if out else ""

def tshark_count(pcap, display_filter):
    out = _t([TSHARK, "-r", pcap, "-Y", display_filter,
              "-T", "fields", "-e", "frame.number"])
    return len(out.splitlines()) if out else 0

# ═══════════════════════════════════════════════════════════════════════════════
# Extraction modules
# ═══════════════════════════════════════════════════════════════════════════════

def extract_overview(f, d):
    d["io_stats"] = tshark_stat(f, "io,stat,0")
    d["protocol_hierarchy"] = tshark_stat(f, "io,phs")
    lens = tshark_fields(f, "", ["frame.len"], limit=100000)
    lengths = []
    for l in lens:
        try: lengths.append(int(l.strip()))
        except ValueError: pass
    if lengths:
        d["packet_count"] = len(lengths)
        d["pkt_len_min"] = min(lengths)
        d["pkt_len_max"] = max(lengths)
        d["pkt_len_avg"] = round(sum(lengths) / len(lengths), 1)
        d["_frame_lengths"] = lengths  # cached for stego detection
    first = _t([TSHARK, "-r", f, "-T", "fields",
                "-e", "frame.time", "-e", "frame.time_epoch", "-c", "1"])
    if first and "\t" in first:
        parts = first.split("\t")
        d["capture_start"] = parts[0].strip()
    # Capture time analysis (first and last packet)
    last = _t([TSHARK, "-r", f, "-T", "fields",
               "-e", "frame.time", "-e", "frame.time_epoch",
               "-Y", "frame"], timeout=30)
    if last:
        last_lines = last.strip().splitlines()
        if last_lines:
            last_parts = last_lines[-1].split("\t")
            if len(last_parts) >= 2:
                d["capture_end"] = last_parts[0].strip()
                try:
                    if first and "\t" in first:
                        start_epoch = float(first.split("\t")[1].strip())
                        end_epoch = float(last_parts[1].strip())
                        duration = end_epoch - start_epoch
                        d["capture_duration"] = round(duration, 2)
                        d["_start_epoch"] = start_epoch
                        d["_end_epoch"] = end_epoch
                except (ValueError, IndexError):
                    pass

def extract_conversations(f, d):
    d["ip_endpoints"] = tshark_stat(f, "endpoints,ip")
    d["ip_conversations"] = tshark_stat(f, "conv,ip")
    d["tcp_conversations"] = tshark_stat(f, "conv,tcp")
    d["udp_conversations"] = tshark_stat(f, "conv,udp")

def extract_http(f, d):
    d["http_traffic"] = tshark_fields(f, "http.request || http.response", [
        "frame.number", "frame.time", "ip.src", "ip.dst",
        "http.request.method", "http.host", "http.request.uri",
        "http.response.code", "http.content_type", "http.user_agent",
        "http.set_cookie", "http.cookie", "http.content_length",
        "http.server", "http.referer",
    ])
    body = _t([TSHARK, "-r", f, "-Y", "http.file_data",
               "-T", "fields", "-e", "http.file_data"])
    d["http_file_data"] = body[:5000] if body else ""
    posts = tshark_fields(f, 'http.request.method == "POST"', [
        "frame.number", "frame.time", "ip.src", "ip.dst",
        "http.request.uri", "urlencoded-form.key", "urlencoded-form.value",
        "http.file_data", "data.data", "http.content_type",
    ])
    if posts:
        parsed = []
        for line in posts[:30]:
            p_ = line.split("|")
            parsed.append({
                "frame": p_[0].strip() if len(p_) > 0 else "",
                "time": p_[1].strip() if len(p_) > 1 else "",
                "src": p_[2].strip() if len(p_) > 2 else "",
                "dst": p_[3].strip() if len(p_) > 3 else "",
                "uri": p_[4].strip() if len(p_) > 4 else "",
                "form_keys": p_[5].strip() if len(p_) > 5 else "",
                "form_values": p_[6].strip() if len(p_) > 6 else "",
                "body": p_[7].strip() if len(p_) > 7 else "",
                "raw": p_[8].strip() if len(p_) > 8 else "",
                "ctype": p_[9].strip() if len(p_) > 9 else "",
            })
        d["http_posts"] = parsed
    objects = tshark_fields(f, "http.content_type && http.response", [
        "frame.number", "http.content_type", "http.content_length",
        "http.request.uri", "http.response.code", "http.server",
    ])
    if objects:
        parsed = []
        for line in objects[:60]:
            p_ = line.split("|")
            if len(p_) >= 2 and p_[1].strip():
                parsed.append({
                    "frame": p_[0].strip(), "ctype": p_[1].strip(),
                    "size": p_[2].strip() if len(p_) > 2 else "",
                    "uri": p_[3].strip() if len(p_) > 3 else "",
                    "status": p_[4].strip() if len(p_) > 4 else "",
                    "server": p_[5].strip() if len(p_) > 5 else "",
                })
        d["http_objects"] = parsed

def extract_dns(f, d):
    lines = tshark_fields(f, "dns", [
        "dns.qry.name", "dns.qry.type", "dns.a", "dns.aaaa",
        "dns.txt", "dns.cname", "dns.mx.mail_exchange", "dns.ns",
        "dns.flags.rcode",
    ])
    d["dns_queries"] = lines
    if lines:
        names = [l.split("|")[0] for l in lines if l.split("|")[0]]
        long = [n for n in set(names) if any(len(p) > 20 for p in n.split("."))]
        if long: d["dns_exfil_suspects"] = sorted(long)[:30]
        hex_chars = set(string.hexdigits)
        hex_subs = []
        b64_subs = []
        for n in set(names):
            parts = n.split(".")
            if len(parts) >= 3 and len(parts[0]) > 10 and all(c in hex_chars for c in parts[0]):
                hex_subs.append(n)
            # Detect base64-encoded subdomains
            if len(parts) >= 3 and len(parts[0]) > 10:
                b64_chars = set(string.ascii_letters + string.digits + "+/=-_")
                if all(c in b64_chars for c in parts[0]):
                    b64_subs.append(n)
        if hex_subs: d["dns_hex_subdomains"] = sorted(hex_subs)[:20]
        if b64_subs and not hex_subs: d["dns_b64_subdomains"] = sorted(b64_subs)[:20]

        # DNS Tunnel Data Reassembly
        if hex_subs or b64_subs:
            tunnel_data = []
            # Group by base domain to reassemble tunneled data
            tunnel_groups = defaultdict(list)
            for n in names:
                parts = n.split(".")
                if len(parts) >= 3:
                    subdomain = parts[0]
                    base = ".".join(parts[-2:])
                    if len(subdomain) > 10:
                        tunnel_groups[base].append(subdomain)

            for base_domain, subdomains in tunnel_groups.items():
                if len(subdomains) < 3:
                    continue
                # Try hex decode
                hex_concat = "".join(subdomains)
                if all(c in hex_chars for c in hex_concat):
                    try:
                        decoded = bytes.fromhex(hex_concat).decode("utf-8", errors="ignore")
                        if decoded.strip() and any(32 <= ord(c) <= 126 for c in decoded[:50]):
                            tunnel_data.append({
                                "domain": base_domain,
                                "encoding": "hex",
                                "chunks": len(subdomains),
                                "decoded": decoded[:1000],
                            })
                    except Exception:
                        pass
                else:
                    # Try base64 decode
                    b64_concat = "".join(subdomains)
                    b64_concat += "=" * (4 - len(b64_concat) % 4) if len(b64_concat) % 4 else ""
                    try:
                        decoded = base64.b64decode(b64_concat.replace("-", "+").replace("_", "/")).decode("utf-8", errors="ignore")
                        if decoded.strip() and any(32 <= ord(c) <= 126 for c in decoded[:50]):
                            tunnel_data.append({
                                "domain": base_domain,
                                "encoding": "base64",
                                "chunks": len(subdomains),
                                "decoded": decoded[:1000],
                            })
                    except Exception:
                        pass

                    # Try base32 decode (used by iodine and other tools)
                    if not tunnel_data or tunnel_data[-1].get("domain") != base_domain:
                        b32_concat = "".join(subdomains).upper()
                        b32_concat += "=" * (8 - len(b32_concat) % 8) if len(b32_concat) % 8 else ""
                        try:
                            decoded = base64.b32decode(b32_concat).decode("utf-8", errors="ignore")
                            if decoded.strip() and any(32 <= ord(c) <= 126 for c in decoded[:50]):
                                tunnel_data.append({
                                    "domain": base_domain,
                                    "encoding": "base32",
                                    "chunks": len(subdomains),
                                    "decoded": decoded[:1000],
                                })
                        except Exception:
                            pass

            if tunnel_data:
                d["dns_tunnel_decoded"] = tunnel_data

        # Detect DNS tunneling tools
        dns_tool_indicators = {
            "dnscat2": [r"dnscat", r"\.cname\.", r"\.mx\."],
            "iodine": [r"\.i\.", r"topdns", r"pirate"],
        }
        for tool, patterns in dns_tool_indicators.items():
            for n in set(names):
                for pat in patterns:
                    if re.search(pat, n, re.I):
                        d.setdefault("dns_tool_suspects", []).append(f"{tool}: {n}")
                        break

        # DNS TXT record data (often used for exfil)
        txt_records = []
        for l in lines:
            p_ = l.split("|")
            txt = p_[4].strip() if len(p_) > 4 else ""
            if txt and len(txt) > 10:
                txt_records.append(txt)
        if txt_records:
            d["dns_txt_records"] = txt_records[:30]

        errors = [l for l in lines if l.split("|")[-1].strip() not in ("", "0", "No error")]
        if errors: d["dns_errors"] = len(errors)
        domains = set()
        for n in names:
            parts = n.split(".")
            if len(parts) >= 2: domains.add(".".join(parts[-2:]))
        d["dns_unique_domains"] = sorted(domains)[:50]

def extract_ftp(f, d):
    d["ftp_traffic"] = tshark_fields(f, "ftp.request.command || ftp.response", [
        "frame.number", "ip.src", "ip.dst",
        "ftp.request.command", "ftp.request.arg",
        "ftp.response.code", "ftp.response.arg",
    ])
    data = tshark_fields(f, "ftp-data", ["frame.number","ip.src","ip.dst","frame.len"], limit=50)
    if data: d["ftp_data"] = data

    # Extract FTP credentials (pair USER + PASS commands)
    ftp_lines = d.get("ftp_traffic", [])
    if ftp_lines:
        creds = []
        current_user = None
        current_src = None
        for line in ftp_lines:
            p_ = line.split("|")
            cmd = p_[3].strip() if len(p_) > 3 else ""
            arg = p_[4].strip() if len(p_) > 4 else ""
            src = p_[1].strip() if len(p_) > 1 else ""
            dst = p_[2].strip() if len(p_) > 2 else ""
            frame = p_[0].strip() if len(p_) > 0 else ""
            if cmd == "USER":
                current_user = arg
                current_src = src
            elif cmd == "PASS" and current_user:
                creds.append({
                    "frame": frame, "src": current_src or src, "dst": dst,
                    "user": current_user, "pass": arg,
                })
                current_user = None
        if creds:
            d["ftp_credentials"] = creds

def extract_smtp(f, d):
    d["smtp_email"] = tshark_fields(f, "smtp || imf", [
        "smtp.req.parameter", "smtp.data.fragment",
        "imf.from", "imf.to", "imf.subject", "imf.date", "imf.message_id",
    ])

def extract_smb(f, d):
    # SMB2 tree connects (share access)
    tree = tshark_fields(f, "smb2.cmd == 3", [
        "frame.number", "frame.time", "ip.src", "ip.dst",
        "smb2.tree", "smb2.share_type",
    ], limit=100)
    if tree:
        shares = []
        for line in tree:
            p_ = line.split("|")
            entry = {
                "frame": p_[0].strip() if len(p_) > 0 else "",
                "time": p_[1].strip() if len(p_) > 1 else "",
                "src": p_[2].strip() if len(p_) > 2 else "",
                "dst": p_[3].strip() if len(p_) > 3 else "",
                "share": p_[4].strip() if len(p_) > 4 else "",
                "type": p_[5].strip() if len(p_) > 5 else "",
            }
            if entry["share"]:
                shares.append(entry)
        if shares: d["smb2_shares"] = shares

    # SMB2 file operations
    files = tshark_fields(f, "smb2.filename", [
        "frame.number", "ip.src", "ip.dst",
        "smb2.filename", "smb2.cmd",
    ], limit=200)
    if files:
        file_list = []
        for line in files:
            p_ = line.split("|")
            fname = p_[3].strip() if len(p_) > 3 else ""
            if fname and fname not in (".", ""):
                file_list.append({
                    "frame": p_[0].strip() if len(p_) > 0 else "",
                    "src": p_[1].strip() if len(p_) > 1 else "",
                    "dst": p_[2].strip() if len(p_) > 2 else "",
                    "file": fname,
                    "cmd": p_[4].strip() if len(p_) > 4 else "",
                })
        if file_list: d["smb2_files"] = file_list[:80]

    # Legacy SMB1 files
    lines = tshark_fields(f, "smb.file", [
        "smb.file", "ip.src", "ip.dst",
    ])
    if lines:
        d["smb_files"] = list(set(l.strip() for l in lines if l.strip().replace("|","")))[:50]

    # SMB NTLM auth
    ntlm = tshark_fields(f, "ntlmssp.auth.username", [
        "frame.number", "ip.src", "ip.dst",
        "ntlmssp.auth.username", "ntlmssp.auth.domain",
        "ntlmssp.auth.hostname",
    ], limit=50)
    if ntlm:
        auths = []
        for line in ntlm:
            p_ = line.split("|")
            user = p_[3].strip() if len(p_) > 3 else ""
            domain = p_[4].strip() if len(p_) > 4 else ""
            host = p_[5].strip() if len(p_) > 5 else ""
            if user:
                auths.append({
                    "frame": p_[0].strip(), "src": p_[1].strip(),
                    "dst": p_[2].strip(), "user": user,
                    "domain": domain, "host": host,
                })
        if auths: d["smb_ntlm_auth"] = auths

    # EternalBlue / MS17-010 detection
    # SMBv1 Trans2 SESSION_SETUP with large payloads
    smb1_count = tshark_count(f, "smb.cmd == 0x25")  # SMB_COM_TRANSACTION
    if smb1_count > 0:
        d["smb1_trans_count"] = smb1_count
        # Check for IPC$ tree connect (common in exploit chain)
        ipc = tshark_fields(f, 'smb.path contains "IPC$"', [
            "frame.number", "ip.src", "ip.dst",
        ], limit=20)
        if ipc:
            d["smb_ipc_access"] = [l.strip() for l in ipc if l.strip().replace("|","")]
        # Large transaction payloads (EternalBlue uses >4000 byte Trans2)
        large_trans = tshark_fields(f, "smb.cmd == 0x25 && frame.len > 1000", [
            "frame.number", "frame.len", "ip.src", "ip.dst",
        ], limit=50)
        if large_trans and len(large_trans) > 3:
            d["eternalblue_suspect"] = True
            d["eternalblue_packets"] = len(large_trans)
            # Extract source IPs
            eblue_sources = set()
            for l in large_trans:
                p_ = l.split("|")
                if len(p_) > 2:
                    eblue_sources.add(p_[2].strip())
            d["eternalblue_sources"] = sorted(eblue_sources)

def extract_tls(f, d):
    sni = tshark_fields(f, "tls.handshake.type == 1 || tls.handshake.type == 11", [
        "tls.handshake.extensions_server_name",
        "x509sat.uTF8String", "x509sat.printableString", "ip.src", "ip.dst",
    ])
    if sni:
        d["tls_sni_certs"] = list(set(s.strip() for s in sni if s.strip().replace("|","")))[:40]
    ver = tshark_fields(f, "tls.handshake.type == 2", [
        "tls.handshake.version", "tls.handshake.ciphersuite",
    ])
    if ver:
        versions, ciphers = {}, set()
        for line in ver:
            p_ = line.split("|")
            v = p_[0].strip() if p_ else ""
            c = p_[1].strip() if len(p_) > 1 else ""
            if v: versions[v] = versions.get(v, 0) + 1
            if c: ciphers.add(c)
        d["tls_versions"] = versions
        if ciphers: d["tls_ciphers"] = sorted(ciphers)

    # JA3 fingerprints with known malware matching
    ja3 = tshark_fields(f, "tls.handshake.type == 1", ["tls.handshake.ja3", "ip.src"])
    if ja3:
        ja3_map = {}
        ja3_malicious = []
        for line in ja3:
            p_ = line.split("|")
            h = p_[0].strip() if p_ else ""
            src = p_[1].strip() if len(p_) > 1 else ""
            if h:
                ja3_map.setdefault(h, set()).add(src)
                if h in KNOWN_JA3:
                    ja3_malicious.append({"hash": h, "src": src, "match": KNOWN_JA3[h]})
        if ja3_map: d["ja3_fingerprints"] = {k: sorted(v) for k,v in ja3_map.items()}
        if ja3_malicious: d["ja3_malicious"] = ja3_malicious

    # JA3S fingerprints (server-side)
    ja3s = tshark_fields(f, "tls.handshake.type == 2", ["tls.handshake.ja3s", "ip.src"])
    if ja3s:
        ja3s_map = {}
        ja3s_malicious = []
        for line in ja3s:
            p_ = line.split("|")
            h = p_[0].strip() if p_ else ""
            src = p_[1].strip() if len(p_) > 1 else ""
            if h:
                ja3s_map.setdefault(h, set()).add(src)
                if h in KNOWN_JA3S:
                    ja3s_malicious.append({"hash": h, "src": src, "match": KNOWN_JA3S[h]})
        if ja3s_map: d["ja3s_fingerprints"] = {k: sorted(v) for k,v in ja3s_map.items()}
        if ja3s_malicious: d["ja3s_malicious"] = ja3s_malicious

    # TLS Certificate anomaly detection
    certs = tshark_fields(f, "tls.handshake.type == 11", [
        "frame.number", "ip.src", "ip.dst",
        "x509af.issuer.rdnSequence", "x509af.subject.rdnSequence",
        "x509af.utcTime", "x509ce.dNSName",
        "x509sat.uTF8String", "x509sat.printableString",
    ], limit=100)
    if certs:
        cert_anomalies = []
        for line in certs:
            p_ = line.split("|")
            issuer = p_[3].strip() if len(p_) > 3 else ""
            subject = p_[4].strip() if len(p_) > 4 else ""
            times = p_[5].strip() if len(p_) > 5 else ""
            dns_name = p_[6].strip() if len(p_) > 6 else ""
            utf8 = p_[7].strip() if len(p_) > 7 else ""
            printable = p_[8].strip() if len(p_) > 8 else ""
            cert_text = f"{issuer} {subject} {utf8} {printable}"
            anomalies = []

            # Self-signed detection
            if issuer and subject and issuer == subject:
                anomalies.append("Self-signed")

            # Known C2 cert patterns
            for pat, desc in C2_CERT_PATTERNS:
                if re.search(pat, cert_text, re.I):
                    anomalies.append(desc)

            if anomalies:
                cert_anomalies.append({
                    "frame": p_[0].strip() if p_ else "",
                    "src": p_[1].strip() if len(p_) > 1 else "",
                    "dst": p_[2].strip() if len(p_) > 2 else "",
                    "subject": (subject or utf8 or printable)[:60],
                    "anomalies": anomalies,
                })
        if cert_anomalies:
            d["tls_cert_anomalies"] = cert_anomalies[:20]

def extract_credentials(f, d):
    creds = tshark_fields(f, "ntlmssp || kerberos.CNameString || http.authorization", [
        "ntlmssp.auth.username", "ntlmssp.auth.domain",
        "kerberos.CNameString", "http.authorization", "ip.src", "ip.dst",
    ])
    if creds:
        clean = [l.strip() for l in creds if l.strip().replace("|","")]
        d["credentials"] = clean[:30]

    # Decode HTTP Basic Auth credentials
    basic_auth = tshark_fields(f, "http.authorization", [
        "frame.number", "ip.src", "ip.dst", "http.host",
        "http.authorization", "http.request.uri",
    ])
    if basic_auth:
        decoded_creds = []
        for line in basic_auth:
            p_ = line.split("|")
            auth = p_[4].strip() if len(p_) > 4 else ""
            if auth.lower().startswith("basic "):
                b64_part = auth.split(" ", 1)[1]
                try:
                    decoded = base64.b64decode(b64_part).decode("utf-8", errors="replace")
                    if ":" in decoded:
                        user, passwd = decoded.split(":", 1)
                        decoded_creds.append({
                            "frame": p_[0].strip() if p_ else "",
                            "src": p_[1].strip() if len(p_) > 1 else "",
                            "dst": p_[2].strip() if len(p_) > 2 else "",
                            "host": p_[3].strip() if len(p_) > 3 else "",
                            "user": user, "pass": passwd,
                            "uri": p_[5].strip() if len(p_) > 5 else "",
                        })
                except Exception:
                    pass
        if decoded_creds:
            d["http_basic_auth"] = decoded_creds

    # Extract HTTP form login credentials (POST with username/password fields)
    form_creds = tshark_fields(f, 'http.request.method == "POST"', [
        "frame.number", "ip.src", "ip.dst", "http.host",
        "http.request.uri", "urlencoded-form.key", "urlencoded-form.value",
    ])
    if form_creds:
        login_posts = []
        cred_keys = {"user", "username", "login", "email", "passwd", "password",
                      "pass", "pwd", "secret", "token", "api_key", "apikey",
                      "auth", "credential", "pin", "otp"}
        for line in form_creds:
            p_ = line.split("|")
            keys = (p_[5].strip() if len(p_) > 5 else "").lower()
            values = p_[6].strip() if len(p_) > 6 else ""
            if any(ck in keys for ck in cred_keys):
                login_posts.append({
                    "frame": p_[0].strip(), "src": p_[1].strip(),
                    "dst": p_[2].strip(), "host": p_[3].strip() if len(p_) > 3 else "",
                    "uri": p_[4].strip() if len(p_) > 4 else "",
                    "keys": keys, "values": values,
                })
        if login_posts:
            d["http_form_logins"] = login_posts[:20]

    # NTLM hash extraction (for hashcat)
    ntlm_resp = tshark_fields(f, "ntlmssp.auth.ntresponse", [
        "frame.number", "ip.src", "ip.dst",
        "ntlmssp.auth.username", "ntlmssp.auth.domain",
        "ntlmssp.auth.ntresponse", "ntlmssp.ntlmserverchallenge",
    ])
    if ntlm_resp:
        hashes = []
        for line in ntlm_resp:
            p_ = line.split("|")
            user = p_[3].strip() if len(p_) > 3 else ""
            domain = p_[4].strip() if len(p_) > 4 else ""
            response = p_[5].strip().replace(":", "") if len(p_) > 5 else ""
            challenge = p_[6].strip().replace(":", "") if len(p_) > 6 else ""
            if user and response:
                # NTLMv2 hash format for hashcat -m 5600
                hashes.append({
                    "user": user, "domain": domain,
                    "challenge": challenge, "response": response[:64],
                    "hashcat_format": f"{user}::{domain}:{challenge}:{response[:32]}:{response[32:]}" if challenge else "",
                })
        if hashes:
            d["ntlm_hashes"] = hashes[:10]

    telnet = _t([TSHARK, "-r", f, "-Y", "telnet.data", "-T", "fields", "-e", "telnet.data"])
    if telnet: d["telnet_data"] = telnet[:2000]

def extract_icmp(f, d):
    lines = tshark_fields(f, "icmp.type == 8", ["data.data", "frame.len", "ip.src", "ip.dst"])
    if lines:
        payloads = [l.split("|")[0].strip() for l in lines if l.split("|")[0].strip()]
        d["icmp_payloads"] = len(payloads)
        concat = "".join(p.replace(":", "") for p in payloads)
        try: d["icmp_decoded"] = bytes.fromhex(concat).decode("utf-8", errors="ignore")[:500]
        except Exception: pass
        lens = []
        for l in lines:
            p_ = l.split("|")
            try: lens.append(int(p_[1].strip()) if len(p_) > 1 else 0)
            except ValueError: pass
        if lens and all(32 <= l <= 126 for l in lens[:20]):
            try: d["icmp_len_decoded"] = "".join(chr(l) for l in lens)[:200]
            except Exception: pass

        # ICMP tunnel detection: large or unusual payloads
        large_icmp = [l for l in lines if len(l.split("|")[0].strip().replace(":", "")) > 96]  # >48 bytes payload
        if len(large_icmp) > 5:
            d["icmp_tunnel_suspect"] = True
            d["icmp_tunnel_packets"] = len(large_icmp)

        # Single-byte-per-packet extraction (common CTF trick)
        if payloads:
            single_bytes = []
            for p in payloads:
                clean = p.replace(":", "")
                if len(clean) == 2:  # Single byte payload
                    try:
                        single_bytes.append(int(clean, 16))
                    except ValueError:
                        pass
            if single_bytes and len(single_bytes) >= 5:
                try:
                    d["icmp_single_byte_decoded"] = "".join(chr(b) for b in single_bytes if 20 <= b <= 126)[:200]
                except Exception:
                    pass

        # Track ICMP conversation pairs for exfil detection
        icmp_pairs = Counter()
        for l in lines:
            p_ = l.split("|")
            src = p_[2].strip() if len(p_) > 2 else ""
            dst = p_[3].strip() if len(p_) > 3 else ""
            if src and dst:
                icmp_pairs[f"{src}->{dst}"] += 1
        if icmp_pairs:
            d["icmp_conversations"] = dict(icmp_pairs.most_common(10))

def extract_usb(f, d):
    lines = tshark_fields(f, "usb.capdata || usbhid.data", ["usb.capdata", "usbhid.data", "frame.len"])
    if lines:
        all_events = [l.strip() for l in lines if l.strip().replace("|","") != "00:00:00:00:00:00:00:00" and l.strip().replace("|","")]
        if not all_events:
            return
        # Classify events into keyboard vs mouse by data length and content
        keyboard_events = []
        mouse_events = []
        for evt in all_events:
            parts = evt.split("|")
            raw = (parts[0].strip() or parts[1].strip() if len(parts) > 1 else parts[0].strip())
            clean = raw.replace(":", "").replace(" ", "")
            if not clean or len(clean) < 4:
                continue
            try:
                data = bytes.fromhex(clean[:16])
            except ValueError:
                continue
            byte_len = len(data)
            if byte_len == 8:
                # Standard HID keyboard: modifier(1) + reserved(1) + keys(6)
                # Key check: modifier in valid range, reserved=0, key code in valid range
                if data[1] == 0 and (data[0] <= 0x07 or data[0] == 0) and data[2] <= 0x65:
                    keyboard_events.append(evt)
                else:
                    # Could be mouse with padding — check displacement
                    dx = struct.unpack('b', bytes([data[1]]))[0] if byte_len > 1 else 0
                    dy = struct.unpack('b', bytes([data[2]]))[0] if byte_len > 2 else 0
                    if data[0] <= 0x07 and (dx != 0 or dy != 0):
                        mouse_events.append(evt)
                    else:
                        keyboard_events.append(evt)  # fallback to keyboard
            elif 3 <= byte_len <= 5:
                # 3-5 byte reports are almost always mouse (buttons, x, y, [wheel], [misc])
                mouse_events.append(evt)
            elif byte_len <= 2:
                continue  # too short, skip
            else:
                keyboard_events.append(evt)  # fallback

        d["usb_hid_events"] = len(all_events)
        d["usb_hid_raw"] = all_events[:60]
        # Store classified events for extract_usb_mouse to reuse
        d["_usb_keyboard_events"] = keyboard_events
        d["_usb_mouse_events"] = mouse_events

        # Decode keyboard events
        if keyboard_events and len(keyboard_events) >= 2:
            decoded = decode_usb_hid(keyboard_events)
            if decoded and len(decoded) >= 2:
                d["usb_hid_decoded"] = decoded

def extract_dhcp(f, d):
    lines = tshark_fields(f, "dhcp", [
        "dhcp.option.hostname", "dhcp.option.requested_ip_address",
        "dhcp.ip.your", "dhcp.option.dhcp_server_id",
        "dhcp.option.domain_name", "dhcp.hw.mac_addr", "dhcp.option.vendor_class_id",
    ])
    if lines:
        entries = []
        for line in lines[:50]:
            p_ = line.split("|")
            if any(x.strip() for x in p_):
                entries.append({
                    "hostname": p_[0].strip() if len(p_) > 0 else "",
                    "req_ip": p_[1].strip() if len(p_) > 1 else "",
                    "assigned_ip": p_[2].strip() if len(p_) > 2 else "",
                    "server": p_[3].strip() if len(p_) > 3 else "",
                    "domain": p_[4].strip() if len(p_) > 4 else "",
                    "mac": p_[5].strip() if len(p_) > 5 else "",
                    "vendor": p_[6].strip() if len(p_) > 6 else "",
                })
        if entries: d["dhcp_leases"] = entries

def extract_arp(f, d):
    lines = tshark_fields(f, "arp", [
        "arp.opcode", "arp.src.hw_mac", "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
    ])
    if lines:
        d["arp_count"] = len(lines)
        ip_macs = {}
        for line in lines:
            p_ = line.split("|")
            if len(p_) >= 3:
                mac, ip = p_[1].strip(), p_[2].strip()
                if ip and mac: ip_macs.setdefault(ip, set()).add(mac)
        conflicts = {ip: list(macs) for ip, macs in ip_macs.items() if len(macs) > 1}
        if conflicts: d["arp_spoofing"] = conflicts

def extract_ssh(f, d):
    lines = tshark_fields(f, "ssh.protocol", ["ip.src", "ip.dst", "ssh.protocol"])
    if lines: d["ssh_banners"] = list(set(lines))[:20]

def extract_irc(f, d):
    lines = tshark_fields(f, "irc.request || irc.response", [
        "ip.src", "ip.dst", "irc.request", "irc.response",
    ])
    if lines: d["irc_messages"] = lines[:100]

def extract_tftp(f, d):
    lines = tshark_fields(f, "tftp", [
        "ip.src", "ip.dst", "tftp.opcode", "tftp.source_file", "tftp.destination_file",
    ])
    if lines: d["tftp_transfers"] = lines[:50]

def extract_kerberos(f, d):
    # Kerberos message type mapping
    KRB_TYPES = {
        "10": "AS-REQ", "11": "AS-REP", "12": "TGS-REQ", "13": "TGS-REP",
        "14": "AP-REQ", "15": "AP-REP", "30": "KRB-ERROR",
    }
    lines = tshark_fields(f, "kerberos", [
        "frame.number", "frame.time", "ip.src", "ip.dst",
        "kerberos.CNameString", "kerberos.SNameString",
        "kerberos.realm", "kerberos.msg_type", "kerberos.error_code",
        "kerberos.cipher", "kerberos.etype",
    ], limit=500)
    if lines:
        entries = []
        etypes = set()
        for line in lines:
            p_ = line.split("|")
            msg_type = p_[7].strip() if len(p_) > 7 else ""
            entry = {
                "frame": p_[0].strip() if len(p_) > 0 else "",
                "time": p_[1].strip() if len(p_) > 1 else "",
                "src": p_[2].strip() if len(p_) > 2 else "",
                "dst": p_[3].strip() if len(p_) > 3 else "",
                "cname": p_[4].strip() if len(p_) > 4 else "",
                "sname": p_[5].strip() if len(p_) > 5 else "",
                "realm": p_[6].strip() if len(p_) > 6 else "",
                "msg_type": KRB_TYPES.get(msg_type, msg_type),
                "error": p_[8].strip() if len(p_) > 8 else "",
                "etype": p_[10].strip() if len(p_) > 10 else "",
            }
            if any(v for k, v in entry.items() if k not in ("frame","time")):
                entries.append(entry)
            etype = entry["etype"]
            if etype: etypes.update(etype.split(","))
        if entries: d["kerberos_traffic"] = entries[:60]
        if etypes: d["kerberos_etypes"] = sorted(etypes)

        # Detect Kerberoasting: TGS-REQ with RC4 etype (23) for service accounts
        tgs_reqs = [e for e in entries if e["msg_type"] in ("TGS-REQ", "12")]
        rc4_tgs = [e for e in tgs_reqs if "23" in e.get("etype", "")]
        if rc4_tgs: d["kerberoasting_suspects"] = rc4_tgs[:15]

        # Detect AS-REP Roasting: AS-REP with RC4 (etype 23)
        as_reps = [e for e in entries if e["msg_type"] in ("AS-REP", "11")]
        rc4_asrep = [e for e in as_reps if "23" in e.get("etype", "")]
        if rc4_asrep: d["asrep_roast_suspects"] = rc4_asrep[:15]

        # Errors
        errors = [e for e in entries if e["error"] and e["error"] != "0"]
        if errors: d["kerberos_errors"] = errors[:20]

    # Extract Kerberos cipher blobs for hashcat cracking
    # TGS-REP cipher data -> $krb5tgs$ format (hashcat -m 13100)
    tgs_cipher = tshark_fields(f, "kerberos.msg_type == 13", [
        "frame.number", "kerberos.CNameString", "kerberos.SNameString",
        "kerberos.realm", "kerberos.etype", "kerberos.cipher",
    ], limit=50)
    if tgs_cipher:
        krb_hashes = []
        for line in tgs_cipher:
            p_ = line.split("|")
            etype = p_[4].strip() if len(p_) > 4 else ""
            cipher = p_[5].strip().replace(":", "") if len(p_) > 5 else ""
            cname = p_[1].strip() if len(p_) > 1 else ""
            sname = p_[2].strip() if len(p_) > 2 else ""
            realm = p_[3].strip() if len(p_) > 3 else ""
            if cipher and len(cipher) >= 64:
                # etype 23 = RC4 -> hashcat -m 13100
                # etype 17 = AES128 -> hashcat -m 19600
                # etype 18 = AES256 -> hashcat -m 19700
                if "23" in etype:
                    # $krb5tgs$23$*user$realm$spn*$checksum$edata2
                    checksum = cipher[:32]
                    edata2 = cipher[32:]
                    hashcat_str = f"$krb5tgs$23$*{cname}${realm}${sname}*${checksum}${edata2}"
                    krb_hashes.append({
                        "frame": p_[0].strip(), "type": "TGS-REP RC4",
                        "user": cname, "spn": sname, "realm": realm,
                        "hashcat_mode": 13100,
                        "hash": hashcat_str[:500],
                    })
                elif "18" in etype:
                    checksum = cipher[:24]
                    edata2 = cipher[24:]
                    hashcat_str = f"$krb5tgs$18${sname}${realm}$*{cname}*${checksum}${edata2}"
                    krb_hashes.append({
                        "frame": p_[0].strip(), "type": "TGS-REP AES256",
                        "user": cname, "spn": sname, "realm": realm,
                        "hashcat_mode": 19700,
                        "hash": hashcat_str[:500],
                    })
                elif "17" in etype:
                    checksum = cipher[:24]
                    edata2 = cipher[24:]
                    hashcat_str = f"$krb5tgs$17${sname}${realm}$*{cname}*${checksum}${edata2}"
                    krb_hashes.append({
                        "frame": p_[0].strip(), "type": "TGS-REP AES128",
                        "user": cname, "spn": sname, "realm": realm,
                        "hashcat_mode": 19600,
                        "hash": hashcat_str[:500],
                    })
        if krb_hashes:
            d["kerberos_hashes"] = krb_hashes[:20]

    # AS-REP cipher data -> $krb5asrep$ format (hashcat -m 18200)
    asrep_cipher = tshark_fields(f, "kerberos.msg_type == 11", [
        "frame.number", "kerberos.CNameString", "kerberos.realm",
        "kerberos.etype", "kerberos.cipher",
    ], limit=50)
    if asrep_cipher:
        asrep_hashes = []
        for line in asrep_cipher:
            p_ = line.split("|")
            etype = p_[3].strip() if len(p_) > 3 else ""
            cipher = p_[4].strip().replace(":", "") if len(p_) > 4 else ""
            cname = p_[1].strip() if len(p_) > 1 else ""
            realm = p_[2].strip() if len(p_) > 2 else ""
            if cipher and len(cipher) >= 64 and "23" in etype:
                checksum = cipher[:32]
                edata2 = cipher[32:]
                hashcat_str = f"$krb5asrep$23${cname}@{realm}:{checksum}${edata2}"
                asrep_hashes.append({
                    "frame": p_[0].strip(), "type": "AS-REP RC4",
                    "user": cname, "realm": realm,
                    "hashcat_mode": 18200,
                    "hash": hashcat_str[:500],
                })
        if asrep_hashes:
            d["asrep_hashes"] = asrep_hashes[:20]

def extract_dcerpc(f, d):
    """Extract DCE/RPC traffic — DRSUAPI (DCSync), LSARPC, SRVSVC, EPM."""
    lines = tshark_fields(f, "dcerpc", [
        "frame.number", "frame.time", "ip.src", "ip.dst",
        "dcerpc.dg_if_id", "dcerpc.op",
        "dcerpc.cn_bind_abstract_syntax",
    ], limit=300)
    if lines:
        entries = []
        for line in lines:
            p_ = line.split("|")
            entries.append({
                "frame": p_[0].strip() if len(p_) > 0 else "",
                "time": p_[1].strip() if len(p_) > 1 else "",
                "src": p_[2].strip() if len(p_) > 2 else "",
                "dst": p_[3].strip() if len(p_) > 3 else "",
                "iface": p_[4].strip() if len(p_) > 4 else "",
                "op": p_[5].strip() if len(p_) > 5 else "",
                "bind": p_[6].strip() if len(p_) > 6 else "",
            })
        if entries: d["dcerpc_traffic"] = entries[:80]

    # DRSUAPI (DCSync attack indicator)
    drsu = tshark_fields(f, "drsuapi", [
        "frame.number", "frame.time", "ip.src", "ip.dst",
        "drsuapi.opnum",
    ], limit=50)
    if drsu:
        DRSU_OPS = {"0": "DsBind", "1": "DsUnbind", "2": "DsReplicaSync",
                     "3": "DsGetNCChanges", "4": "DsReplicaUpdateRefs",
                     "12": "DsCrackNames", "13": "DsWriteAccountSpn"}
        ops = []
        for line in drsu:
            p_ = line.split("|")
            opnum = p_[4].strip() if len(p_) > 4 else ""
            ops.append({
                "frame": p_[0].strip(), "time": p_[1].strip(),
                "src": p_[2].strip(), "dst": p_[3].strip(),
                "op": DRSU_OPS.get(opnum, f"op{opnum}"), "opnum": opnum,
            })
        d["drsuapi_traffic"] = ops
        # DsGetNCChanges (opnum 3) = DCSync
        dcsync = [o_ for o_ in ops if o_["opnum"] == "3"]
        if dcsync: d["dcsync_detected"] = dcsync

    # LSARPC
    lsa = tshark_fields(f, "lsarpc", [
        "frame.number", "ip.src", "ip.dst", "lsarpc.opnum",
    ], limit=50)
    if lsa: d["lsarpc_traffic"] = lsa[:30]

    # SRVSVC (share enumeration)
    srv = tshark_fields(f, "srvsvc", [
        "frame.number", "ip.src", "ip.dst", "srvsvc.opnum",
    ], limit=50)
    if srv: d["srvsvc_traffic"] = srv[:30]

def extract_rdp(f, d):
    """Detect RDP connections."""
    lines = tshark_fields(f, "rdp || tcp.port == 3389", [
        "frame.number", "frame.time", "ip.src", "ip.dst",
        "tcp.dstport", "rdp.neg_type",
    ], limit=50)
    if lines:
        conns = set()
        for line in lines:
            p_ = line.split("|")
            src = p_[2].strip() if len(p_) > 2 else ""
            dst = p_[3].strip() if len(p_) > 3 else ""
            if src and dst:
                conns.add(f"{src}->{dst}")
        if conns: d["rdp_connections"] = sorted(conns)

def extract_ssdp(f, d):
    """Extract SSDP (Simple Service Discovery Protocol) traffic."""
    lines = tshark_fields(f, "ssdp", [
        "ip.src", "http.request.method", "http.server", "http.location",
    ], limit=100)
    if lines:
        devices = set()
        for line in lines:
            p_ = line.split("|")
            server = p_[2].strip() if len(p_) > 2 else ""
            loc = p_[3].strip() if len(p_) > 3 else ""
            if server: devices.add(server)
            if loc: devices.add(loc)
        if devices: d["ssdp_devices"] = sorted(devices)[:30]

def extract_quic(f, d):
    """Extract QUIC connection info."""
    lines = tshark_fields(f, "quic", [
        "ip.src", "ip.dst", "quic.version",
    ], limit=200)
    if lines:
        conns = {}
        for line in lines:
            p_ = line.split("|")
            src = p_[0].strip() if len(p_) > 0 else ""
            dst = p_[1].strip() if len(p_) > 1 else ""
            ver = p_[2].strip() if len(p_) > 2 else ""
            key = f"{src}->{dst}"
            conns.setdefault(key, {"count": 0, "versions": set()})
            conns[key]["count"] += 1
            if ver: conns[key]["versions"].add(ver)
        d["quic_connections"] = {k: {"count": v["count"], "versions": sorted(v["versions"])}
                                  for k, v in sorted(conns.items(), key=lambda x: -x[1]["count"])[:20]}

def extract_ntp(f, d):
    """Extract NTP traffic."""
    lines = tshark_fields(f, "ntp", [
        "ip.src", "ip.dst", "ntp.stratum",
    ], limit=50)
    if lines:
        servers = set()
        for line in lines:
            p_ = line.split("|")
            dst = p_[1].strip() if len(p_) > 1 else ""
            stratum = p_[2].strip() if len(p_) > 2 else ""
            if dst: servers.add(f"{dst} (stratum:{stratum})" if stratum else dst)
        if servers: d["ntp_servers"] = sorted(servers)

def extract_cldap(f, d):
    """Extract Connectionless LDAP (CLDAP) — Active Directory domain discovery."""
    lines = tshark_fields(f, "cldap", [
        "frame.number", "ip.src", "ip.dst",
        "ldap.filter", "ldap.baseObject",
    ], limit=50)
    if lines:
        entries = [l.strip() for l in lines if l.strip().replace("|","")]
        if entries: d["cldap_traffic"] = entries[:30]

def extract_lldp(f, d):
    """Extract LLDP (Link Layer Discovery Protocol) device info."""
    lines = tshark_fields(f, "lldp", [
        "lldp.chassis.id", "lldp.port.id", "lldp.port.desc",
        "lldp.tlv.system.name", "lldp.tlv.system.desc",
    ], limit=30)
    if lines:
        devices = set()
        for line in lines:
            p_ = line.split("|")
            sysname = p_[3].strip() if len(p_) > 3 else ""
            chassis = p_[0].strip() if len(p_) > 0 else ""
            if sysname: devices.add(sysname)
            elif chassis: devices.add(chassis)
        if devices: d["lldp_devices"] = sorted(devices)

def extract_mqtt(f, d):
    lines = tshark_fields(f, "mqtt", [
        "mqtt.topic", "mqtt.msg", "mqtt.clientid", "mqtt.username", "mqtt.passwd",
    ])
    if lines:
        entries = [l.strip() for l in lines if l.strip().replace("|","")]
        if entries: d["mqtt_messages"] = entries[:50]

def extract_snmp(f, d):
    lines = tshark_fields(f, "snmp", ["snmp.community", "snmp.name"])
    if lines:
        communities = set()
        for line in lines:
            p_ = line.split("|")
            if p_[0].strip(): communities.add(p_[0].strip())
        if communities: d["snmp_communities"] = sorted(communities)

def extract_syslog(f, d):
    lines = tshark_fields(f, "syslog.msg && udp.port == 514", ["syslog.msg"])
    if lines:
        msgs = [l.strip() for l in lines if l.strip()]
        if msgs: d["syslog_messages"] = msgs[:50]

def extract_llmnr(f, d):
    """Extract LLMNR (Link-Local Multicast Name Resolution) traffic — udp port 5355."""
    lines = tshark_fields(f, "llmnr", [
        "frame.number", "frame.time", "ip.src", "ip.dst",
        "dns.qry.name", "dns.flags.response", "dns.a", "dns.aaaa",
    ])
    if lines:
        queries, responses = [], []
        for line in lines:
            p_ = line.split("|")
            entry = {
                "frame": p_[0].strip() if len(p_) > 0 else "",
                "time": p_[1].strip() if len(p_) > 1 else "",
                "src": p_[2].strip() if len(p_) > 2 else "",
                "dst": p_[3].strip() if len(p_) > 3 else "",
                "name": p_[4].strip() if len(p_) > 4 else "",
                "is_response": p_[5].strip() if len(p_) > 5 else "",
                "answer_a": p_[6].strip() if len(p_) > 6 else "",
                "answer_aaaa": p_[7].strip() if len(p_) > 7 else "",
            }
            if entry["is_response"] == "1":
                responses.append(entry)
            else:
                queries.append(entry)
        if queries: d["llmnr_queries"] = queries[:100]
        if responses: d["llmnr_responses"] = responses[:100]
        # Detect LLMNR poisoning: multiple IPs responding to the same query name
        name_responders = {}
        for r in responses:
            name = r.get("name", "")
            src = r.get("src", "")
            if name and src:
                name_responders.setdefault(name, set()).add(src)
        poisoned = {n: sorted(ips) for n, ips in name_responders.items() if len(ips) > 1}
        if poisoned: d["llmnr_poisoning"] = poisoned

def extract_mdns(f, d):
    """Extract mDNS (Multicast DNS) traffic — udp port 5353."""
    lines = tshark_fields(f, "mdns", [
        "frame.number", "ip.src", "dns.qry.name", "dns.a", "dns.aaaa",
        "dns.srv.name", "dns.txt",
    ])
    if lines:
        entries = [l.strip() for l in lines if l.strip().replace("|","")]
        if entries: d["mdns_traffic"] = entries[:80]

def extract_nbns(f, d):
    """Extract NetBIOS Name Service (NBNS/WINS) traffic — udp port 137."""
    lines = tshark_fields(f, "nbns", [
        "frame.number", "frame.time", "ip.src", "ip.dst",
        "nbns.name", "nbns.flags.response", "nbns.addr",
        "nbns.type",
    ])
    if lines:
        queries, responses = [], []
        for line in lines:
            p_ = line.split("|")
            entry = {
                "frame": p_[0].strip() if len(p_) > 0 else "",
                "time": p_[1].strip() if len(p_) > 1 else "",
                "src": p_[2].strip() if len(p_) > 2 else "",
                "dst": p_[3].strip() if len(p_) > 3 else "",
                "name": p_[4].strip() if len(p_) > 4 else "",
                "is_response": p_[5].strip() if len(p_) > 5 else "",
                "addr": p_[6].strip() if len(p_) > 6 else "",
                "type": p_[7].strip() if len(p_) > 7 else "",
            }
            if entry["is_response"] == "1":
                responses.append(entry)
            else:
                queries.append(entry)
        if queries: d["nbns_queries"] = queries[:100]
        if responses: d["nbns_responses"] = responses[:100]
        # Detect NBNS poisoning
        name_responders = {}
        for r in responses:
            name = r.get("name", "")
            src = r.get("src", "")
            if name and src:
                name_responders.setdefault(name, set()).add(src)
        poisoned = {n: sorted(ips) for n, ips in name_responders.items() if len(ips) > 1}
        if poisoned: d["nbns_poisoning"] = poisoned

def extract_wifi(f, d):
    beacons = tshark_fields(f, "wlan.fc.type_subtype == 0x08", [
        "wlan.ssid", "wlan.bssid", "wlan_radio.channel",
        "wlan.fixed.capabilities.privacy",
    ])
    if beacons:
        ssids = set()
        for line in beacons:
            p_ = line.split("|")
            ssid = p_[0].strip() if p_ else ""
            bssid = p_[1].strip() if len(p_) > 1 else ""
            ch = p_[2].strip() if len(p_) > 2 else ""
            enc = "WPA/WEP" if (len(p_) > 3 and p_[3].strip() == "1") else "Open"
            if ssid: ssids.add(f"{ssid} ({bssid}) ch:{ch} [{enc}]")
        if ssids: d["wifi_networks"] = sorted(ssids)
    eapol = tshark_count(f, "eapol")
    if eapol: d["wifi_eapol_count"] = eapol
    deauth = tshark_count(f, "wlan.fc.type_subtype == 0x0c")
    if deauth: d["wifi_deauth_count"] = deauth
    probe = tshark_fields(f, "wlan.fc.type_subtype == 0x04", ["wlan.ssid", "wlan.sa"])
    if probe:
        probes = set()
        for line in probe:
            p_ = line.split("|")
            ssid = p_[0].strip() if p_ else ""
            mac = p_[1].strip() if len(p_) > 1 else ""
            if ssid: probes.add(f"{mac} -> {ssid}")
        if probes: d["wifi_probes"] = sorted(probes)[:30]
        # Check if probe SSIDs spell out a message (CTF trick)
        probe_ssids = sorted(set(p_[0].strip() for line in probe for p_ in [line.split("|")] if p_[0].strip()))
        if probe_ssids:
            ssid_concat = "".join(probe_ssids)
            for pat in FLAG_PATTERNS:
                if pat.search(ssid_concat):
                    d["wifi_ssid_flag"] = ssid_concat

def extract_http2(f, d):
    lines = tshark_fields(f, "http2", [
        "http2.headers.method", "http2.headers.path",
        "http2.headers.status", "http2.header.name", "http2.header.value",
    ])
    if lines: d["http2_traffic"] = lines[:100]

def extract_tor(f, d):
    """Detect Tor traffic by port patterns and TLS characteristics."""
    # Tor uses ports 9001 (OR), 9030 (Dir), 9050/9150 (SOCKS)
    tor_lines = tshark_fields(f, "tcp.dstport == 9001 || tcp.dstport == 9030 || tcp.srcport == 9001 || tcp.srcport == 9030", [
        "frame.number", "ip.src", "ip.dst", "tcp.dstport",
    ], limit=100)
    if tor_lines:
        tor_ips = set()
        for l in tor_lines:
            p_ = l.split("|")
            if len(p_) >= 3:
                tor_ips.add(p_[1].strip())
                tor_ips.add(p_[2].strip())
        d["tor_traffic"] = {"packet_count": len(tor_lines), "ips": sorted(tor_ips)[:20]}

    # Check for consistent 512-byte TLS records (Tor cells)
    tls_lens = tshark_fields(f, "tls.record.length", ["tls.record.length", "ip.dst"], limit=500)
    if tls_lens:
        size_counter = Counter()
        for l in tls_lens:
            p_ = l.split("|")
            try:
                size = int(p_[0].strip())
                size_counter[size] += 1
            except (ValueError, IndexError):
                pass
        # Tor cells padded to 512 bytes
        if size_counter.get(512, 0) > 20 or size_counter.get(586, 0) > 20:
            d.setdefault("tor_traffic", {})["cell_pattern"] = True
            d.setdefault("tor_traffic", {})["512_byte_records"] = size_counter.get(512, 0) + size_counter.get(586, 0)

def extract_mining(f, d):
    """Detect cryptocurrency mining protocols."""
    # Stratum JSON-RPC
    mining_lines = tshark_fields(f, 'tcp.payload contains "mining.subscribe" || tcp.payload contains "mining.authorize" || tcp.payload contains "mining.login"', [
        "frame.number", "ip.src", "ip.dst", "tcp.dstport",
    ], limit=50)
    if mining_lines:
        miners = set()
        pools = set()
        for l in mining_lines:
            p_ = l.split("|")
            if len(p_) >= 3:
                miners.add(p_[1].strip())
                pools.add(f"{p_[2].strip()}:{p_[3].strip()}" if len(p_) > 3 else p_[2].strip())
        d["crypto_mining"] = {
            "packet_count": len(mining_lines),
            "miners": sorted(miners),
            "pools": sorted(pools),
        }

    # Check DNS for known mining pool domains
    dns_queries = d.get("dns_queries", [])
    pool_hits = []
    for line in dns_queries:
        qname = line.split("|")[0].strip().lower()
        for pool in MINING_POOLS:
            if pool in qname:
                pool_hits.append(qname)
                break
    if pool_hits:
        d.setdefault("crypto_mining", {})["pool_dns"] = sorted(set(pool_hits))

    # Check common mining ports
    mining_ports = tshark_count(f, "tcp.dstport == 3333 || tcp.dstport == 3334 || tcp.dstport == 14444 || tcp.dstport == 14433")
    if mining_ports > 10:
        d.setdefault("crypto_mining", {})["mining_port_count"] = mining_ports

def extract_covert_channels(f, d):
    """Detect covert channels: TTL steganography, IP ID encoding, TCP seq encoding."""
    # TTL steganography (ASCII values in TTL field)
    ttl_lines = tshark_fields(f, "icmp || ip", ["ip.ttl", "ip.src", "ip.dst"], limit=5000)
    if ttl_lines:
        ttls_by_src = defaultdict(list)
        for l in ttl_lines:
            p_ = l.split("|")
            if len(p_) >= 3:
                try:
                    ttl = int(p_[0].strip())
                    src = p_[1].strip()
                    ttls_by_src[src].append(ttl)
                except (ValueError, IndexError):
                    pass
        for src, ttls in ttls_by_src.items():
            if len(ttls) < 10:
                continue
            # Check if TTL values fall in printable ASCII range
            ascii_ttls = [t for t in ttls if 32 <= t <= 126]
            if len(ascii_ttls) > len(ttls) * 0.7 and len(set(ttls)) > 5:
                try:
                    decoded = "".join(chr(t) for t in ttls if 32 <= t <= 126)
                    d["ttl_stego"] = {"src": src, "decoded": decoded[:200], "count": len(ttls)}
                except Exception:
                    pass
                break

    # IP ID field steganography
    ipid_lines = tshark_fields(f, "ip.id", ["ip.id", "ip.src"], limit=2000)
    if ipid_lines and len(ipid_lines) > 20:
        ipids_by_src = defaultdict(list)
        for l in ipid_lines:
            p_ = l.split("|")
            if len(p_) >= 2:
                try:
                    ipid = int(p_[0].strip(), 0)  # handles hex
                    src = p_[1].strip()
                    ipids_by_src[src].append(ipid)
                except (ValueError, IndexError):
                    pass
        for src, ids in ipids_by_src.items():
            if len(ids) < 10:
                continue
            # Check if low byte of IP ID encodes ASCII
            low_bytes = [i & 0xFF for i in ids]
            ascii_ids = [b for b in low_bytes if 32 <= b <= 126]
            if len(ascii_ids) > len(ids) * 0.6:
                try:
                    decoded = "".join(chr(b) for b in low_bytes if 32 <= b <= 126)
                    if len(decoded) >= 5:
                        d["ipid_stego"] = {"src": src, "decoded": decoded[:200]}
                except Exception:
                    pass
                break

def extract_revshells(f, d):
    """Detect reverse shell payloads in TCP stream content."""
    previews = d.get("tcp_stream_previews", [])
    revshell_hits = []
    for sp in previews:
        content = sp.get("preview", "")
        for pat, desc in REVSHELL_PATTERNS:
            if pat.search(content):
                revshell_hits.append({
                    "stream": sp["stream"],
                    "type": desc,
                    "preview": content[:300],
                })
                break
    # Also scan interesting streams
    for sp in d.get("interesting_streams", []):
        content = sp.get("preview", "")
        for pat, desc in REVSHELL_PATTERNS:
            if pat.search(content):
                revshell_hits.append({
                    "stream": sp["stream"],
                    "type": desc,
                    "preview": content[:300],
                })
                break
    if revshell_hits:
        d["reverse_shells"] = revshell_hits[:15]

def extract_powershell(f, d):
    """Detect PowerShell encoded commands and offensive payloads in HTTP."""
    http_data = d.get("http_file_data", "")
    posts = d.get("http_posts", [])
    ps_findings = []

    all_text = hex_decode(http_data) if http_data else ""
    for post in posts:
        body = hex_decode(post.get("body", ""))
        raw = hex_decode(post.get("raw", ""))
        all_text += f" {body} {raw}"

    # Also search TCP stream previews
    for sp in d.get("tcp_stream_previews", []):
        all_text += f" {sp.get('preview', '')}"

    for pat, desc in POWERSHELL_PATTERNS:
        m = pat.search(all_text)
        if m:
            finding = {"type": desc, "match": m.group(0)[:120]}
            # Try to decode EncodedCommand
            if desc == "EncodedCommand" and m.lastindex:
                b64_data = m.group(1)
                try:
                    decoded = base64.b64decode(b64_data).decode("utf-16-le", errors="ignore")
                    finding["decoded"] = decoded[:300]
                except Exception:
                    pass
            elif desc == "Download cradle" and m.lastindex:
                finding["url"] = m.group(m.lastindex)[:200]
            ps_findings.append(finding)

    if ps_findings:
        d["powershell_detected"] = ps_findings[:10]

def extract_default_creds(f, d):
    """Check extracted credentials against known defaults."""
    matches = []
    # Check FTP creds
    for cred in d.get("ftp_credentials", []):
        pair = (cred["user"].lower(), cred["pass"].lower())
        for u, p in DEFAULT_CREDS:
            if pair == (u, p):
                matches.append({"proto": "FTP", "user": cred["user"], "pass": cred["pass"],
                               "src": cred["src"], "dst": cred["dst"]})
                break
    # Check HTTP Basic Auth
    for cred in d.get("http_basic_auth", []):
        pair = (cred["user"].lower(), cred["pass"].lower())
        for u, p in DEFAULT_CREDS:
            if pair == (u, p):
                matches.append({"proto": "HTTP", "user": cred["user"], "pass": cred["pass"],
                               "src": cred["src"], "dst": cred["dst"]})
                break
    if matches:
        d["default_creds_found"] = matches

def extract_usb_mouse(f, d):
    """Extract and decode USB mouse movement data (common CTF challenge).
    Reuses classified events from extract_usb if available; otherwise re-reads."""
    # Check if extract_usb already classified mouse events
    mouse_events = d.get("_usb_mouse_events")
    if mouse_events is None:
        # Fallback: extract_usb hasn't run yet; read raw data
        lines = tshark_fields(f, "usb.capdata || usbhid.data", ["usb.capdata", "usbhid.data", "frame.len"])
        if not lines:
            return
        mouse_events = []
        for l in lines:
            raw = l.strip().replace("|", "").replace(" ", "").replace(":", "")
            if not raw or raw == "0000000000000000":
                continue
            try:
                data = bytes.fromhex(raw[:16])
            except ValueError:
                continue
            if len(data) == 4 or (3 <= len(data) <= 5):
                mouse_events.append(l)
            elif len(data) == 8:
                if not (data[0] <= 0x07 and data[1] == 0 and data[2] != 0 and all(b == 0 for b in data[3:])):
                    dx = struct.unpack('b', bytes([data[1]]))[0]
                    dy = struct.unpack('b', bytes([data[2]]))[0]
                    if dx != 0 or dy != 0:
                        mouse_events.append(l)

    if len(mouse_events) >= 10:
        coords = decode_usb_mouse(mouse_events)
        if coords and len(coords) >= 10:
            d["usb_mouse_coords"] = len(coords)
            d["usb_mouse_ascii"] = render_mouse_ascii(coords)
            drawn = sum(1 for _, _, b in coords if b & 1)
            d["usb_mouse_drawn"] = drawn
            d["usb_mouse_total"] = len(coords)

def extract_streams(f, d, max_tcp=10, max_udp=5):
    stream_out = _t([TSHARK, "-r", f, "-T", "fields", "-e", "tcp.stream", "-Y", "tcp.stream"])
    if stream_out:
        ids = sorted(set(int(s.strip()) for s in stream_out.splitlines() if s.strip().isdigit()))
        d["tcp_stream_count"] = len(ids)
        previews = []
        for sid in ids[:max_tcp]:
            content = tshark_follow(f, "tcp", sid)
            if content: previews.append({"stream": sid, "preview": content})
        if previews: d["tcp_stream_previews"] = previews
        d["_tcp_stream_ids"] = ids
    udp_out = _t([TSHARK, "-r", f, "-T", "fields", "-e", "udp.stream", "-Y", "udp.stream"])
    if udp_out:
        ids = sorted(set(int(s.strip()) for s in udp_out.splitlines() if s.strip().isdigit()))
        d["udp_stream_count"] = len(ids)
        previews = []
        for sid in ids[:max_udp]:
            content = tshark_follow(f, "udp", sid)
            if content: previews.append({"stream": sid, "preview": content})
        if previews: d["udp_stream_previews"] = previews

def extract_deep(f, d):
    http_lines = d.get("http_traffic", [])

    # Suspicious traffic
    sus_filters = [
        ('http.request.uri contains ".exe" || http.request.uri contains ".dll" || '
         'http.request.uri contains ".ps1" || http.request.uri contains ".sh" || '
         'http.request.uri contains ".elf" || http.request.uri contains ".bat" || '
         'http.request.uri contains ".vbs" || http.request.uri contains ".hta" || '
         'http.request.uri contains ".msi" || http.request.uri contains ".scr"', "Malware download"),
        ('http.request.uri contains ".php" && http.request.method == "POST"', "PHP C2/webshell"),
        ('http.request.uri contains ".aspx" && http.request.method == "POST"', "ASPX webshell"),
        ('http.request.uri contains ".jsp" && http.request.method == "POST"', "JSP webshell"),
        ('http.content_type contains "octet-stream" || http.content_type contains "x-executable"', "Binary xfer"),
        ('tcp.dstport == 4444 || tcp.dstport == 4443 || tcp.dstport == 1234 || '
         'tcp.dstport == 5555 || tcp.dstport == 9001 || tcp.dstport == 8443 || '
         'tcp.dstport == 1337 || tcp.dstport == 31337 || tcp.dstport == 6666 || '
         'tcp.dstport == 6667 || tcp.dstport == 9999 || tcp.dstport == 1338', "RevShell port"),
        ('http.request.uri contains "/wp-admin" || http.request.uri contains "/wp-login" || '
         'http.request.uri contains "/administrator" || http.request.uri contains "/phpmyadmin"', "Admin panel access"),
        ('http.request.uri matches "\\.(env|config|bak|sql|db|sqlite|log|old|orig|save|swp|~)$"', "Sensitive file access"),
    ]
    suspicious = []
    for filt, label in sus_filters:
        try:
            lines = tshark_fields(f, filt, [
                "frame.number", "frame.time", "ip.src", "ip.dst",
                "http.request.uri", "http.request.method", "http.content_type",
            ], limit=20)
            for line in lines:
                p_ = line.split("|")
                suspicious.append({
                    "frame": p_[0].strip() if len(p_) > 0 else "",
                    "time": p_[1].strip() if len(p_) > 1 else "",
                    "src": p_[2].strip() if len(p_) > 2 else "",
                    "dst": p_[3].strip() if len(p_) > 3 else "",
                    "uri": p_[4].strip() if len(p_) > 4 else "",
                    "method": p_[5].strip() if len(p_) > 5 else "",
                    "ctype": p_[6].strip() if len(p_) > 6 else "",
                    "reason": label,
                })
        except Exception: pass
    seen = set()
    unique = []
    for s in suspicious:
        if s["frame"] not in seen: seen.add(s["frame"]); unique.append(s)
    if unique: d["suspicious_traffic"] = unique

    # HTTP attack patterns (expanded)
    if http_lines:
        attack_pats = [
            (re.compile(r"(?:union\s+select|or\s+1\s*=\s*1|'\s*(?:or|and)\s|--\s|/\*|\bselect\b.*\bfrom\b)", re.I), "SQLi"),
            (re.compile(r"(?:\.\./|\.\.\\|/etc/passwd|/proc/self|file://|/windows/system32)", re.I), "LFI/Path Traversal"),
            (re.compile(r"(?:<script|javascript:|onerror=|onload=|eval\(|alert\(|<img\s+src=|<svg\s+onload)", re.I), "XSS"),
            (re.compile(r"(?:;.{0,30}(?:cat|id|ls|whoami|curl|wget|nc |bash|python|perl|ruby)|`[^`]+`|\$\()", re.I), "Command Injection"),
            (re.compile(r"(?:base64|exec|system|passthru|shell_exec|popen|proc_open)\s*\(", re.I), "RCE"),
            (re.compile(r"(?:cmd=|exec=|command=|ping=|ip=).*(?:[;&|]|%26|%7c)", re.I), "OS Command"),
            (re.compile(r"(?:SSRF|url=https?://|redirect=https?://|next=https?://|return=https?://)", re.I), "SSRF/Redirect"),
            (re.compile(r"(?:{{.*}}|{%.*%}|\$\{.*\})", re.I), "Template Injection"),
            (re.compile(r"(?:ldap://|jndi:|log4j|%24%7b)", re.I), "Log4Shell/JNDI"),
            (re.compile(r"(?:\.\.%2f|%2e%2e|%252e%252e|\.\.%5c|%c0%ae)", re.I), "Encoded Traversal"),
            (re.compile(r"(?:admin|root|test|guest|user).*(?:admin|root|test|123|password|pass|1234)", re.I), "Default Creds"),
        ]
        attacks = []
        for line in http_lines[:500]:
            for pat, label in attack_pats:
                if pat.search(line):
                    p_ = line.split("|")
                    attacks.append({
                        "type": label,
                        "src": p_[2].strip() if len(p_) > 2 else "",
                        "dst": p_[3].strip() if len(p_) > 3 else "",
                        "uri": (p_[6].strip() if len(p_) > 6 else line)[:120],
                    })
                    break
        if attacks: d["http_attacks"] = attacks[:30]

    # Brute force detection
    if http_lines:
        login_attempts = defaultdict(list)
        for line in http_lines:
            p_ = line.split("|")
            method = p_[4].strip() if len(p_) > 4 else ""
            uri = p_[6].strip() if len(p_) > 6 else ""
            resp = p_[7].strip() if len(p_) > 7 else ""
            src = p_[2].strip() if len(p_) > 2 else ""
            if method == "POST" and any(kw in uri.lower() for kw in
                ("login", "auth", "signin", "session", "token", "api/login", "wp-login")):
                login_attempts[f"{src}->{uri}"].append(resp)
        brute = []
        for key, responses in login_attempts.items():
            if len(responses) >= 5:
                failed = sum(1 for r in responses if r in ("401", "403", "302", "200"))
                brute.append({"target": key, "attempts": len(responses),
                             "responses": Counter(responses).most_common(3)})
        if brute:
            d["brute_force"] = sorted(brute, key=lambda x: -x["attempts"])[:10]

    # C2 framework detection
    if http_lines:
        c2_results = _detect_c2_in_http(http_lines)
        if c2_results:
            d["c2_frameworks"] = c2_results

    # Port scan + C2 beacon (single SYN fetch for both analyses)
    syn_lines = tshark_fields(f, "tcp.flags.syn == 1 && tcp.flags.ack == 0", [
        "frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport",
    ], limit=10000)
    if syn_lines:
        scanner = {}
        conn_times = {}
        for line in syn_lines:
            p_ = line.split("|")
            if len(p_) >= 4:
                src, dst, port = p_[1].strip(), p_[2].strip(), p_[3].strip()
                scanner.setdefault(f"{src}->{dst}", set()).add(port)
                try:
                    ts = float(p_[0].strip())
                    conn_times.setdefault(f"{src}->{dst}:{port}", []).append(ts)
                except (ValueError, IndexError):
                    pass
        scans = {k: len(v) for k, v in scanner.items() if len(v) > 15}
        if scans:
            d["port_scans"] = scans
        beacons = []
        for key, times in conn_times.items():
            if len(times) >= 4:
                times.sort()
                deltas = [times[i + 1] - times[i] for i in range(len(times) - 1)]
                if deltas:
                    avg = sum(deltas) / len(deltas)
                    if avg > 1:
                        var = sum((dd - avg) ** 2 for dd in deltas) / len(deltas)
                        std = var ** 0.5
                        if std / avg < 0.35:
                            beacons.append({"conn": key, "count": len(times), "avg": round(avg, 2), "std": round(std, 2)})
        if beacons:
            d["beacon_candidates"] = sorted(beacons, key=lambda x: -x["count"])[:10]

    # Packet length stego (reuse cached frame lengths from extract_overview)
    pkt_count = d.get("packet_count", 0)
    if pkt_count and pkt_count < 5000:
        lengths = d.get("_frame_lengths", [])
        if lengths:
            unique = len(set(lengths))
            if unique <= 256 and len(lengths) > 50:
                ascii_r = [l for l in lengths if 32 <= l <= 126]
                if len(ascii_r) > len(lengths) * 0.6:
                    try: d["pkt_len_stego"] = "".join(chr(l) for l in lengths if 32 <= l <= 126)[:200]
                    except Exception: pass

    # File signature detection in raw stream data
    raw_out = _t([TSHARK, "-r", f, "-T", "fields", "-e", "data.data", "-Y", "data.data"], timeout=30)
    if raw_out:
        all_hex = "".join(l.strip().replace(":","") for l in raw_out.splitlines() if l.strip())
        try:
            raw = bytes.fromhex(all_hex[:200000])
            text = raw.decode("utf-8", errors="ignore")
            # Flag search
            flags = set()
            for pat in FLAG_PATTERNS:
                for m in pat.finditer(text):
                    f_str = m.group(0) if '{' in m.group(0) else m.group(1) if m.lastindex else m.group(0)
                    if _is_plausible_flag(f_str):
                        flags.add(f_str)
            if flags: d["flags_in_data"] = sorted(flags)[:10]

            # File signature detection
            file_sigs = detect_file_signatures(raw[:100000])
            if file_sigs:
                d["embedded_files"] = file_sigs[:20]

            # Base64-encoded data detection
            b64_re = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
            b64_found = []
            for m in b64_re.finditer(text[:50000]):
                try:
                    decoded = base64.b64decode(m.group(0))
                    decoded_text = decoded.decode("utf-8", errors="ignore")
                    # Check for interesting content
                    if any(kw in decoded_text.lower() for kw in
                        ("flag", "password", "secret", "key", "admin", "root", "token",
                         "private", "ssh-rsa", "BEGIN", "<?php", "#!/", "import ", "def ")):
                        b64_found.append({
                            "encoded": m.group(0)[:60],
                            "decoded": decoded_text[:200],
                        })
                    # Check for file signatures in decoded data
                    dec_sigs = detect_file_signatures(decoded[:1000])
                    if dec_sigs:
                        b64_found.append({
                            "encoded": m.group(0)[:60],
                            "decoded": f"[{dec_sigs[0]['signature']}] {decoded[:50].hex()}",
                        })
                except Exception:
                    pass
            if b64_found:
                d["base64_hidden_data"] = b64_found[:10]
        except Exception: pass

    # Deep stream search
    stream_ids = d.get("_tcp_stream_ids", [])
    max_followed = len(d.get("tcp_stream_previews", []))
    if stream_ids and len(stream_ids) > max_followed:
        flag_streams = []
        for sid in stream_ids[max_followed:min(len(stream_ids), 80)]:
            content = tshark_follow(f, "tcp", sid, 2000)
            if content:
                flags = set()
                for pat in FLAG_PATTERNS:
                    for m in pat.finditer(content):
                        f_str = m.group(0) if '{' in m.group(0) else m.group(1) if m.lastindex else m.group(0)
                        if _is_plausible_flag(f_str):
                            flags.add(f_str)
                lc = content.lower()
                has_kw = any(kw in lc for kw in ("password","secret","token","admin","root","login","key","private","flag","base64","credential","ssh","BEGIN"))
                if flags:
                    flag_streams.append({"stream":sid,"flags":sorted(flags),"preview":content[:400]})
                elif has_kw:
                    flag_streams.append({"stream":sid,"flags":[],"preview":content[:400],"keywords":True})
        if flag_streams: d["interesting_streams"] = flag_streams[:15]

    # Data exfiltration volume analysis
    ep_raw = d.get("ip_endpoints", "")
    if ep_raw:
        exfil_suspects = []
        for line in ep_raw.splitlines():
            parts = line.split()
            if len(parts) >= 7 and parts[0].count(".") == 3:
                try:
                    tx_bytes = int(parts[4])
                    rx_bytes = int(parts[6])
                    total = tx_bytes + rx_bytes
                    if total > 0:
                        ratio = tx_bytes / total if total > 0 else 0
                        # Flag hosts with >80% outbound traffic and significant volume
                        if ratio > 0.8 and tx_bytes > 100000:
                            exfil_suspects.append({
                                "ip": parts[0], "tx": tx_bytes, "rx": rx_bytes,
                                "ratio": round(ratio * 100, 1),
                            })
                except (ValueError, IndexError):
                    pass
        if exfil_suspects:
            d["data_exfil_volume"] = sorted(exfil_suspects, key=lambda x: -x["tx"])[:10]

# ═══════════════════════════════════════════════════════════════════════════════
# Havoc C2 detection & analysis
# ═══════════════════════════════════════════════════════════════════════════════

def extract_havoc(f, d, magic=b'\xde\xad\xbe\xef', aes_key=None, aes_iv=None):
    """Detect and analyze Havoc C2 traffic patterns."""
    magic_hex = magic.hex()

    # Step 1: Extract TCP packets with payload data
    lines = tshark_fields(f, "tcp.payload", [
        "frame.number", "frame.time_epoch",
        "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport",
        "tcp.stream", "tcp.payload", "tcp.len",
    ], limit=50000)

    if not lines:
        return

    # Group packets by TCP stream
    streams = {}
    for line in lines:
        p_ = line.split("|")
        if len(p_) < 9:
            continue
        try:
            ts = float(p_[1].strip())
        except (ValueError, IndexError):
            continue
        payload_hex = p_[7].strip().replace(":", "")
        try:
            pkt_len = int(p_[8].strip())
        except ValueError:
            pkt_len = len(payload_hex) // 2

        stream_id = p_[6].strip()
        src = f"{p_[2].strip()}:{p_[3].strip()}"
        dst = f"{p_[4].strip()}:{p_[5].strip()}"
        flow = f"{src}->{dst}"

        streams.setdefault(stream_id, []).append({
            "frame": p_[0].strip(),
            "ts": ts,
            "src": src, "dst": dst, "flow": flow,
            "payload_hex": payload_hex,
            "len": pkt_len,
        })

    # Step 2: Check HTTP POST bodies for binary Havoc traffic
    http_havoc_posts = []
    post_lines = tshark_fields(f, 'http.request.method == "POST"', [
        "frame.number", "frame.time_epoch",
        "ip.src", "ip.dst", "tcp.dstport",
        "http.request.uri", "http.content_type",
        "http.file_data", "data.data",
    ], limit=500)

    for line in post_lines:
        p_ = line.split("|")
        if len(p_) < 7:
            continue
        ctype = p_[6].strip() if len(p_) > 6 else ""
        body_hex = (p_[7].strip() if len(p_) > 7 else "") or (p_[8].strip() if len(p_) > 8 else "")
        body_hex = body_hex.replace(":", "")

        is_binary_type = ctype and not any(t in ctype.lower() for t in
            ("json", "form", "text", "xml", "html", "javascript"))

        is_binary_body = False
        if body_hex and len(body_hex) >= 20:
            try:
                raw = bytes.fromhex(body_hex[:200])
                printable = sum(1 for b in raw if 32 <= b <= 126)
                is_binary_body = printable < len(raw) * 0.4
            except Exception:
                pass

        has_magic = magic_hex in body_hex if body_hex else False

        if is_binary_type or is_binary_body or has_magic:
            try:
                post_ts = float(p_[1].strip())
            except (ValueError, IndexError):
                post_ts = 0
            http_havoc_posts.append({
                "frame": p_[0].strip(),
                "ts": post_ts,
                "src": p_[2].strip(),
                "dst": f"{p_[3].strip()}:{p_[4].strip()}",
                "uri": p_[5].strip(),
                "ctype": ctype,
                "has_magic": has_magic,
                "is_binary": is_binary_body,
                "body_preview": body_hex[:128],
            })

    if http_havoc_posts:
        d["havoc_http_posts"] = http_havoc_posts

    # Step 3: Score each stream for Havoc C2 indicators
    havoc_streams = []

    for stream_id, pkts in streams.items():
        if len(pkts) < 2:
            continue

        score = 0
        indicators = []

        # --- Magic bytes check ---
        magic_pkts = []
        for pkt in pkts:
            if magic_hex in pkt["payload_hex"]:
                magic_pkts.append(pkt)

        if magic_pkts:
            score += 30
            indicators.append(f"magic_bytes({len(magic_pkts)})")

        # --- Beacon interval analysis (per directional flow) ---
        flow_groups = {}
        for pkt in pkts:
            flow_groups.setdefault(pkt["flow"], []).append(pkt)

        best_beacon = None
        for flow, fpkts in flow_groups.items():
            if len(fpkts) < 4:
                continue
            times = sorted(p["ts"] for p in fpkts)
            deltas = [times[i+1] - times[i] for i in range(len(times)-1)]
            if not deltas:
                continue
            avg = sum(deltas) / len(deltas)
            if avg < 0.5:
                continue
            variance = sum((dd - avg)**2 for dd in deltas) / len(deltas)
            std = variance ** 0.5
            cv = std / avg if avg > 0 else 999
            if cv < 0.40:
                bscore = max(0, int(25 * (1 - cv)))
                if best_beacon is None or bscore > best_beacon["score"]:
                    best_beacon = {
                        "flow": flow,
                        "count": len(fpkts),
                        "interval": round(avg, 2),
                        "jitter_pct": round(cv * 100, 1),
                        "std": round(std, 2),
                        "score": bscore,
                        "first_seen": min(times),
                        "last_seen": max(times),
                    }

        if best_beacon:
            score += best_beacon["score"]
            indicators.append(f"beacon({best_beacon['interval']}s \u00b1{best_beacon['jitter_pct']}%)")

        # --- Binary content detection ---
        binary_count = 0
        for pkt in pkts:
            ph = pkt["payload_hex"]
            if len(ph) < 20:
                continue
            try:
                raw = bytes.fromhex(ph[:200])
                printable = sum(1 for b in raw if 32 <= b <= 126)
                if printable < len(raw) * 0.3:
                    binary_count += 1
            except Exception:
                pass

        if binary_count > 2:
            score += 15
            indicators.append(f"binary_payload({binary_count})")

        # --- Consistent size pattern ---
        sizes = [p["len"] for p in pkts]
        if len(sizes) >= 3:
            size_freq = {}
            for s in sizes:
                size_freq[s] = size_freq.get(s, 0) + 1
            top_size = max(size_freq, key=size_freq.get)
            top_count = size_freq[top_size]
            if top_count >= len(sizes) * 0.4:
                score += 10
                indicators.append(f"size_pattern({top_size}B\u00d7{top_count})")

        # --- HTTP POST with binary body in this stream ---
        if http_havoc_posts:
            stream_frames = {pkt["frame"] for pkt in pkts}
            stream_http = [hp for hp in http_havoc_posts if hp["frame"] in stream_frames]
            if stream_http:
                score += 15
                indicators.append(f"http_binary_post({len(stream_http)})")

        if score < 15:
            continue

        # Build result
        all_times = [p["ts"] for p in pkts]
        stream_info = {
            "stream_id": stream_id,
            "score": score,
            "indicators": indicators,
            "packet_count": len(pkts),
            "first_seen": min(all_times),
            "last_seen": max(all_times),
            "flows": sorted(set(p["flow"] for p in pkts)),
            "beacon": best_beacon,
            "magic_count": len(magic_pkts),
        }

        # --- Parse checkin packets (packets with magic bytes) ---
        if magic_pkts:
            parsed_checkins = []
            for pkt in magic_pkts:
                try:
                    raw = bytes.fromhex(pkt["payload_hex"])
                    idx = raw.find(magic)
                    if idx >= 0:
                        ci = _parse_havoc_checkin(raw[idx:], magic)
                        if ci:
                            ci["frame"] = pkt["frame"]
                            ci["src"] = pkt["src"]
                            ci["dst"] = pkt["dst"]
                            parsed_checkins.append(ci)
                except Exception:
                    pass
            if parsed_checkins:
                stream_info["checkins"] = parsed_checkins

        # --- Decrypt payloads if key provided ---
        if aes_key:
            decrypted_cmds = []
            for pkt in pkts:
                ph = pkt["payload_hex"]
                if len(ph) < 64:
                    continue
                try:
                    raw = bytes.fromhex(ph)
                    # Skip Havoc header if magic is present
                    offset = 0
                    if raw[:4] == magic:
                        offset = 12
                    encrypted = raw[offset:]

                    if aes_iv:
                        iv = aes_iv
                        ciphertext = encrypted
                    else:
                        # IV = first 16 bytes of encrypted blob
                        if len(encrypted) < 32:
                            continue
                        iv = encrypted[:16]
                        ciphertext = encrypted[16:]

                    if len(ciphertext) < 16 or len(ciphertext) % 16 != 0:
                        continue

                    plaintext = _aes_cbc_decrypt(ciphertext, aes_key, iv)
                    if not plaintext:
                        continue

                    text = plaintext.decode("utf-8", errors="replace")
                    printable_chars = sum(1 for c in text if 32 <= ord(c) <= 126 or c in '\n\r\t')
                    if printable_chars < len(text) * 0.2:
                        continue

                    cmd = _parse_havoc_command(plaintext)
                    exfil = _detect_exfil_patterns(text)

                    decrypted_cmds.append({
                        "frame": pkt["frame"],
                        "src": pkt["src"],
                        "dst": pkt["dst"],
                        "plaintext": text[:500],
                        "command": cmd,
                        "exfil_indicators": exfil,
                    })
                except Exception:
                    pass

            if decrypted_cmds:
                stream_info["decrypted"] = decrypted_cmds

        havoc_streams.append(stream_info)

    if havoc_streams:
        havoc_streams.sort(key=lambda x: -x["score"])
        d["havoc_streams"] = havoc_streams

    # Store whether key was provided (for render hints)
    d["_havoc_key_provided"] = aes_key is not None

# ═══════════════════════════════════════════════════════════════════════════════
# Orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

def _progress(completed, total, label=""):
    pct = int((completed / total) * 100) if total else 100
    filled = int(pct / 5)
    prog = "█" * filled + "░" * (20 - filled)
    sys.stderr.write(f"\r  {DIM()}[{prog}] {pct:3d}% {label:<20}{RST()}")
    sys.stderr.flush()


def analyze(pcap_path, quick=False, max_streams=10,
             havoc_magic=b'\xde\xad\xbe\xef', havoc_key=None, havoc_iv=None):
    f = str(pcap_path)
    d = {"file": f, "size_bytes": pcap_path.stat().st_size}

    # Phase 1: Overview must run first (populates packet counts used later)
    _progress(0, 100, "Overview")
    extract_overview(f, d)

    # Phase 2: Independent protocol modules — run in parallel (I/O-bound tshark calls)
    parallel_modules = [
        ("Conversations", lambda: extract_conversations(f, d)),
        ("HTTP",          lambda: extract_http(f, d)),
        ("DNS",           lambda: extract_dns(f, d)),
        ("TLS/SSL",       lambda: extract_tls(f, d)),
        ("Credentials",   lambda: extract_credentials(f, d)),
        ("FTP",           lambda: extract_ftp(f, d)),
        ("SMTP/Email",    lambda: extract_smtp(f, d)),
        ("SMB",           lambda: extract_smb(f, d)),
        ("SSH",           lambda: extract_ssh(f, d)),
        ("DHCP",          lambda: extract_dhcp(f, d)),
        ("ARP",           lambda: extract_arp(f, d)),
        ("ICMP",          lambda: extract_icmp(f, d)),
        ("IRC",           lambda: extract_irc(f, d)),
        ("TFTP",          lambda: extract_tftp(f, d)),
        ("Kerberos",      lambda: extract_kerberos(f, d)),
        ("DCE/RPC",       lambda: extract_dcerpc(f, d)),
        ("MQTT",          lambda: extract_mqtt(f, d)),
        ("SNMP",          lambda: extract_snmp(f, d)),
        ("Syslog",        lambda: extract_syslog(f, d)),
        ("WiFi/802.11",   lambda: extract_wifi(f, d)),
        ("USB HID",       lambda: extract_usb(f, d)),
        ("HTTP/2",        lambda: extract_http2(f, d)),
        ("LLMNR",         lambda: extract_llmnr(f, d)),
        ("mDNS",          lambda: extract_mdns(f, d)),
        ("NBNS",          lambda: extract_nbns(f, d)),
        ("RDP",           lambda: extract_rdp(f, d)),
        ("SSDP",          lambda: extract_ssdp(f, d)),
        ("QUIC",          lambda: extract_quic(f, d)),
        ("NTP",           lambda: extract_ntp(f, d)),
        ("CLDAP",         lambda: extract_cldap(f, d)),
        ("LLDP",          lambda: extract_lldp(f, d)),
        ("Havoc C2",      lambda: extract_havoc(f, d, havoc_magic, havoc_key, havoc_iv)),
        ("Tor",           lambda: extract_tor(f, d)),
        ("Mining",        lambda: extract_mining(f, d)),
        ("CovertChan",    lambda: extract_covert_channels(f, d)),
        ("USB Mouse",     lambda: extract_usb_mouse(f, d)),
    ]
    total_steps = len(parallel_modules) + 3 + (1 if not quick else 0)  # +overview +streams +post +deep
    progress_lock = threading.Lock()
    done_count = [1]  # overview already done

    def _run_module(name_fn):
        name, fn = name_fn
        fn()
        with progress_lock:
            done_count[0] += 1
            _progress(done_count[0], total_steps, name)

    workers = min(6, len(parallel_modules))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_run_module, m) for m in parallel_modules]
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as exc:
                if VERBOSE:
                    warn(f"Module error: {exc}")

    # Phase 3: Streams (depends on nothing, but is sequential internally)
    _progress(done_count[0], total_steps, "Streams")
    extract_streams(f, d, max_streams)
    done_count[0] += 1

    # Phase 4: Deep analysis (depends on HTTP traffic, stream IDs, packet counts)
    if not quick:
        _progress(done_count[0], total_steps, "Deep analysis")
        extract_deep(f, d)
        done_count[0] += 1

    # Phase 5: Post-analysis (depends on stream previews and extracted data)
    _progress(done_count[0], total_steps, "Post-analysis")
    extract_revshells(f, d)
    extract_powershell(f, d)
    extract_default_creds(f, d)
    done_count[0] += 1

    sys.stderr.write(f"\r  {DIM()}[{'█' * 20}] 100% Done                {RST()}\n")
    sys.stderr.flush()
    d.pop("_tcp_stream_ids", None)
    d.pop("_frame_lengths", None)
    d.pop("_havoc_key_provided", None)
    d.pop("_start_epoch", None)
    d.pop("_end_epoch", None)
    d.pop("_usb_keyboard_events", None)
    d.pop("_usb_mouse_events", None)
    return d

# ═══════════════════════════════════════════════════════════════════════════════
# Render
# ═══════════════════════════════════════════════════════════════════════════════

def _compute_threat_score(d):
    """Compute overall threat score (0-100) from all findings."""
    score = 0
    reasons = []

    # Critical findings (high weight)
    if d.get("dcsync_detected"):
        score += 25; reasons.append("DCSync attack detected")
    if d.get("havoc_streams"):
        best = max(h["score"] for h in d["havoc_streams"])
        if best >= 50: score += 20; reasons.append(f"Havoc C2 (confidence={best})")
        elif best >= 25: score += 10; reasons.append(f"Havoc C2 suspect (confidence={best})")
    if d.get("c2_frameworks"):
        for fw, info_ in d["c2_frameworks"].items():
            score += min(info_["score"] // 3, 15)
            reasons.append(f"{fw} C2 indicators")

    # High severity
    if d.get("http_attacks"): score += min(len(d["http_attacks"]) * 2, 15); reasons.append(f"{len(d['http_attacks'])} HTTP attacks")
    if d.get("port_scans"): score += 10; reasons.append("Port scan activity")
    if d.get("beacon_candidates"): score += 12; reasons.append(f"{len(d['beacon_candidates'])} beacon pattern(s)")
    if d.get("kerberoasting_suspects"): score += 15; reasons.append("Kerberoasting")
    if d.get("kerberos_hashes"): score += 18; reasons.append(f"{len(d['kerberos_hashes'])} Kerberos TGS hash(es) extracted")
    if d.get("asrep_roast_suspects"): score += 15; reasons.append("AS-REP Roasting")
    if d.get("asrep_hashes"): score += 18; reasons.append(f"{len(d['asrep_hashes'])} AS-REP hash(es) extracted")
    if d.get("brute_force"): score += 8; reasons.append("Brute force attempts")

    # Medium severity
    if d.get("suspicious_traffic"): score += min(len(d["suspicious_traffic"]), 10); reasons.append("Suspicious traffic")
    if d.get("dns_exfil_suspects"): score += 8; reasons.append("DNS exfiltration suspects")
    if d.get("dns_tunnel_decoded"): score += 12; reasons.append("DNS tunnel data decoded")
    if d.get("arp_spoofing"): score += 10; reasons.append("ARP spoofing")
    if d.get("llmnr_poisoning"): score += 10; reasons.append("LLMNR poisoning")
    if d.get("nbns_poisoning"): score += 10; reasons.append("NBNS poisoning")
    if d.get("data_exfil_volume"): score += 8; reasons.append("Data exfiltration volume anomaly")
    if d.get("embedded_files"):
        for ef in d["embedded_files"]:
            if "PE" in ef["signature"] or "ELF" in ef["signature"]:
                score += 10; reasons.append(f"Embedded {ef['signature']}"); break

    # Low severity / CTF findings
    if d.get("flags_in_data"): score += 5; reasons.append(f"{len(d['flags_in_data'])} flag(s) found")
    if d.get("pkt_len_stego"): score += 5; reasons.append("Packet length steganography")
    if d.get("base64_hidden_data"): score += 5; reasons.append("Hidden base64 data")
    if d.get("credentials") or d.get("http_basic_auth") or d.get("ftp_credentials"):
        score += 5; reasons.append("Credentials exposed")
    if d.get("reverse_shells"):
        score += 20; reasons.append(f"{len(d['reverse_shells'])} reverse shell(s)")
    if d.get("powershell_detected"):
        score += 15; reasons.append("PowerShell payload detected")
    if d.get("eternalblue_suspect"):
        score += 25; reasons.append("EternalBlue / MS17-010 exploit")
    if d.get("ja3_malicious"):
        score += 15; reasons.append("Known malicious JA3 fingerprint")
    if d.get("tls_cert_anomalies"):
        score += 8; reasons.append("Suspicious TLS certificates")
    if d.get("tor_traffic"):
        score += 5; reasons.append("Tor traffic detected")
    if d.get("crypto_mining"):
        score += 10; reasons.append("Crypto mining detected")
    if d.get("default_creds_found"):
        score += 10; reasons.append("Default credentials used")
    if d.get("ttl_stego") or d.get("ipid_stego"):
        score += 8; reasons.append("Covert channel steganography")

    return min(score, 100), reasons


# ═══════════════════════════════════════════════════════════════════════════════
# Task Type Auto-Detection (heuristic, no AI)
# ═══════════════════════════════════════════════════════════════════════════════

# Each task type maps to:
#   weight_rules: list of (data_key, condition, weight) — condition is a lambda
#   render_keys:  set of data keys that should be shown in focused mode
#   description:  human-readable name

TASK_TYPES = {
    "usb_hid": {
        "label": "USB HID (Keyboard/Mouse) Challenge",
        "description": "Decode keystrokes or mouse drawings from USB capture data",
        "weight_rules": [
            ("usb_hid_events", lambda v: v and v > 5, 50),
            ("usb_hid_decoded", lambda v: bool(v), 30),
            ("usb_mouse_coords", lambda v: v and v > 10, 40),
            ("usb_mouse_ascii", lambda v: bool(v), 20),
        ],
        "render_sections": {"file_info", "usb_hid", "usb_mouse", "flags", "alerts"},
    },
    "dns_exfil": {
        "label": "DNS Exfiltration / Tunneling",
        "description": "Data hidden in DNS queries — hex/base64 encoded subdomains",
        "weight_rules": [
            ("dns_exfil_suspects", lambda v: v and len(v) > 2, 40),
            ("dns_hex_subdomains", lambda v: v and len(v) > 2, 35),
            ("dns_b64_subdomains", lambda v: v and len(v) > 2, 35),
            ("dns_tunnel_decoded", lambda v: bool(v), 50),
            ("dns_tool_suspects", lambda v: bool(v), 30),
            ("dns_txt_records", lambda v: v and len(v) > 3, 15),
        ],
        "render_sections": {"file_info", "dns", "dns_exfil", "dns_tunnel", "dns_tools", "dns_txt", "flags", "alerts"},
    },
    "credential_theft": {
        "label": "Credential Theft / Password Extraction",
        "description": "Plaintext credentials, NTLM hashes, or login brute-force",
        "weight_rules": [
            ("http_basic_auth", lambda v: bool(v), 40),
            ("http_form_logins", lambda v: bool(v), 35),
            ("ftp_credentials", lambda v: bool(v), 40),
            ("ntlm_hashes", lambda v: bool(v), 45),
            ("credentials", lambda v: bool(v), 20),
            ("smb_ntlm_auth", lambda v: bool(v), 30),
            ("telnet_data", lambda v: bool(v), 25),
            ("default_creds_found", lambda v: bool(v), 30),
            ("brute_force", lambda v: bool(v), 35),
            ("mqtt_messages", lambda v: v and any(":" in str(m) for m in v[:5]), 20),
        ],
        "render_sections": {"file_info", "credentials", "http_basic", "http_form", "ftp_creds",
                            "ntlm_hashes", "smb_ntlm", "telnet", "default_creds", "brute_force",
                            "flags", "alerts"},
    },
    "http_attack": {
        "label": "Web Application Attack",
        "description": "SQLi, XSS, RCE, LFI, SSRF, or other HTTP attacks",
        "weight_rules": [
            ("http_attacks", lambda v: v and len(v) > 1, 50),
            ("suspicious_traffic", lambda v: v and len(v) > 2, 25),
            ("http_posts", lambda v: v and len(v) > 3, 15),
            ("c2_frameworks", lambda v: bool(v), 20),
            ("reverse_shells", lambda v: bool(v), 30),
            ("powershell_detected", lambda v: bool(v), 25),
        ],
        "render_sections": {"file_info", "http", "http_posts", "http_objects", "http_body",
                            "http_attacks", "suspicious", "c2", "revshells", "powershell",
                            "flags", "alerts"},
    },
    "c2_beacon": {
        "label": "Command & Control / Beacon Traffic",
        "description": "C2 framework detection (Cobalt Strike, Metasploit, Havoc, etc.)",
        "weight_rules": [
            ("c2_frameworks", lambda v: bool(v), 50),
            ("beacon_candidates", lambda v: bool(v), 40),
            ("havoc_streams", lambda v: bool(v), 50),
            ("ja3_malicious", lambda v: bool(v), 35),
            ("ja3s_malicious", lambda v: bool(v), 30),
            ("tls_cert_anomalies", lambda v: bool(v), 20),
            ("reverse_shells", lambda v: bool(v), 25),
            ("powershell_detected", lambda v: bool(v), 20),
        ],
        "render_sections": {"file_info", "tls", "ja3", "ja3s", "cert_anomalies", "c2",
                            "beacons", "havoc", "revshells", "powershell",
                            "suspicious", "flags", "alerts", "malicious_endpoints"},
    },
    "ad_attack": {
        "label": "Active Directory Attack",
        "description": "DCSync, Kerberoasting, AS-REP roast, LLMNR/NBNS poisoning",
        "weight_rules": [
            ("dcsync_detected", lambda v: bool(v), 60),
            ("kerberoasting_suspects", lambda v: bool(v), 50),
            ("asrep_roast_suspects", lambda v: bool(v), 50),
            ("kerberos_hashes", lambda v: bool(v), 40),
            ("asrep_hashes", lambda v: bool(v), 40),
            ("llmnr_poisoning", lambda v: bool(v), 40),
            ("nbns_poisoning", lambda v: bool(v), 40),
            ("drsuapi_traffic", lambda v: bool(v), 35),
            ("smb_ntlm_auth", lambda v: bool(v), 15),
            ("kerberos_traffic", lambda v: v and len(v) > 5, 10),
            ("ntlm_hashes", lambda v: bool(v), 25),
        ],
        "render_sections": {"file_info", "kerberos", "kerberos_hashes", "asrep_hashes",
                            "dcerpc", "drsuapi", "dcsync", "smb", "llmnr", "nbns",
                            "credentials", "ntlm_hashes", "flags", "alerts", "malicious_endpoints"},
    },
    "wifi_capture": {
        "label": "WiFi / Wireless Capture",
        "description": "WiFi handshakes, deauth attacks, probe requests, SSID analysis",
        "weight_rules": [
            ("wifi_networks", lambda v: bool(v), 50),
            ("wifi_eapol_count", lambda v: v and v > 0, 40),
            ("wifi_deauth_count", lambda v: v and v > 0, 30),
            ("wifi_probes", lambda v: bool(v), 25),
            ("wifi_ssid_flag", lambda v: bool(v), 40),
        ],
        "render_sections": {"file_info", "wifi", "wifi_probes", "wifi_ssid_flag", "flags", "alerts"},
    },
    "smb_forensics": {
        "label": "SMB / File Share Forensics",
        "description": "File transfer analysis, share enumeration, EternalBlue",
        "weight_rules": [
            ("smb2_files", lambda v: v and len(v) > 3, 35),
            ("smb2_shares", lambda v: bool(v), 30),
            ("smb_files", lambda v: bool(v), 25),
            ("eternalblue_suspect", lambda v: bool(v), 50),
            ("smb_ntlm_auth", lambda v: bool(v), 20),
        ],
        "render_sections": {"file_info", "smb", "eternalblue", "smb_ntlm", "ntlm_hashes",
                            "embedded_files", "flags", "alerts"},
    },
    "icmp_stego": {
        "label": "ICMP Steganography / Covert Channel",
        "description": "Data hidden in ICMP payloads, packet lengths, or TTL values",
        "weight_rules": [
            ("icmp_decoded", lambda v: v and len(v.strip()) > 3, 40),
            ("icmp_len_decoded", lambda v: bool(v), 40),
            ("icmp_single_byte_decoded", lambda v: bool(v), 40),
            ("icmp_tunnel_suspect", lambda v: bool(v), 35),
            ("ttl_stego", lambda v: bool(v), 50),
            ("ipid_stego", lambda v: bool(v), 50),
            ("pkt_len_stego", lambda v: bool(v), 40),
        ],
        "render_sections": {"file_info", "icmp", "covert_channels", "stego", "flags", "alerts"},
    },
    "ftp_forensics": {
        "label": "FTP Traffic Analysis",
        "description": "FTP credentials, file transfers, and data exfiltration via FTP",
        "weight_rules": [
            ("ftp_traffic", lambda v: v and len(v) > 3, 30),
            ("ftp_credentials", lambda v: bool(v), 40),
            ("ftp_data", lambda v: bool(v), 25),
        ],
        "render_sections": {"file_info", "ftp", "ftp_creds", "credentials", "flags", "alerts"},
    },
    "email_forensics": {
        "label": "Email / SMTP Forensics",
        "description": "Email message analysis, attachments, phishing",
        "weight_rules": [
            ("smtp_email", lambda v: v and len(v) > 2, 50),
        ],
        "render_sections": {"file_info", "smtp", "embedded_files", "flags", "alerts"},
    },
    "network_recon": {
        "label": "Network Reconnaissance / Scanning",
        "description": "Port scans, service enumeration, ARP spoofing",
        "weight_rules": [
            ("port_scans", lambda v: bool(v), 50),
            ("arp_spoofing", lambda v: bool(v), 30),
            ("ssdp_devices", lambda v: v and len(v) > 5, 15),
            ("lldp_devices", lambda v: bool(v), 15),
            ("snmp_communities", lambda v: bool(v), 20),
        ],
        "render_sections": {"file_info", "conversations", "endpoints", "port_scans",
                            "arp_spoofing", "ssdp", "lldp", "snmp", "flags", "alerts",
                            "malicious_endpoints"},
    },
    "malware_traffic": {
        "label": "Malware / Exploit Traffic",
        "description": "Malware downloads, EternalBlue, mining, Tor, encrypted C2",
        "weight_rules": [
            ("eternalblue_suspect", lambda v: bool(v), 45),
            ("embedded_files", lambda v: v and any("PE" in e["signature"] or "ELF" in e["signature"] for e in v), 40),
            ("tor_traffic", lambda v: bool(v), 20),
            ("crypto_mining", lambda v: bool(v), 35),
            ("suspicious_traffic", lambda v: v and len(v) > 3, 20),
            ("reverse_shells", lambda v: bool(v), 35),
            ("base64_hidden_data", lambda v: bool(v), 15),
        ],
        "render_sections": {"file_info", "http", "tls", "suspicious", "eternalblue",
                            "embedded_files", "base64_data", "tor", "mining",
                            "revshells", "powershell", "flags", "alerts", "malicious_endpoints"},
    },
    "data_exfil": {
        "label": "Data Exfiltration Analysis",
        "description": "Large outbound transfers, DNS tunneling, covert channels",
        "weight_rules": [
            ("data_exfil_volume", lambda v: bool(v), 40),
            ("dns_tunnel_decoded", lambda v: bool(v), 35),
            ("icmp_tunnel_suspect", lambda v: bool(v), 30),
            ("ttl_stego", lambda v: bool(v), 25),
            ("dns_exfil_suspects", lambda v: v and len(v) > 3, 30),
        ],
        "render_sections": {"file_info", "conversations", "endpoints", "dns", "dns_exfil",
                            "dns_tunnel", "icmp", "covert_channels", "exfil_volume",
                            "flags", "alerts"},
    },
    "general_ctf": {
        "label": "General CTF Challenge",
        "description": "Mixed protocols with hidden flags — check streams and encoded data",
        "weight_rules": [
            ("flags_in_data", lambda v: bool(v), 40),
            ("interesting_streams", lambda v: bool(v), 30),
            ("base64_hidden_data", lambda v: bool(v), 25),
            ("pkt_len_stego", lambda v: bool(v), 30),
        ],
        "render_sections": {"file_info", "streams", "dns", "http", "http_body", "icmp",
                            "embedded_files", "base64_data", "stego", "interesting_streams",
                            "flags", "alerts"},
    },
}


def detect_task_type(d):
    """Heuristic task type detection. Returns list of (type_name, score, info_dict) sorted by score."""
    results = []
    for task_name, task_info in TASK_TYPES.items():
        total_weight = 0
        matched_rules = []
        for data_key, condition, weight in task_info["weight_rules"]:
            value = d.get(data_key)
            try:
                if condition(value):
                    total_weight += weight
                    matched_rules.append(data_key)
            except Exception:
                pass
        if total_weight > 0:
            results.append((task_name, total_weight, {
                "label": task_info["label"],
                "description": task_info["description"],
                "matched": matched_rules,
                "render_sections": task_info["render_sections"],
            }))
    results.sort(key=lambda x: -x[1])
    return results


def _should_render_section(section_name, focus_sections):
    """Check if a section should be rendered in focused mode.
    If focus_sections is None, render everything (full mode)."""
    if focus_sections is None:
        return True
    return section_name in focus_sections


def render(d, focus_mode=False):
    fname = d.get("file","")
    nl()
    # ═══ EXECUTIVE SUMMARY ═══
    threat_score, threat_reasons = _compute_threat_score(d)

    # Threat level banner
    if threat_score >= 70:
        threat_label = f"{BG_RED()}{BOLD()} CRITICAL {RST()}"
        threat_color = BRED()
        banner_char = "!"
    elif threat_score >= 40:
        threat_label = f"{BRED()}HIGH{RST()}"
        threat_color = BRED()
        banner_char = "!"
    elif threat_score >= 20:
        threat_label = f"{BYEL()}MEDIUM{RST()}"
        threat_color = BYEL()
        banner_char = "~"
    elif threat_score > 0:
        threat_label = f"{BCYN()}LOW{RST()}"
        threat_color = BCYN()
        banner_char = "-"
    else:
        threat_label = f"{BGRN()}CLEAN{RST()}"
        threat_color = BGRN()
        banner_char = "-"

    o(f"{threat_color}{'='*W}{RST()}")
    o(f"{BOLD()}{threat_color}  pcapsum v{__version__} -- PCAP/CTF Deep Analysis Report{RST()}")
    o(f"{threat_color}{'='*W}{RST()}")
    nl()

    # Threat assessment box
    o(f"  {BOLD()}Threat Level:{RST()} {threat_label}  {BOLD()}Score:{RST()} {threat_color}{threat_score}/100{RST()}")
    if threat_reasons:
        o(f"  {BOLD()}Findings:{RST()}")
        for reason in threat_reasons[:8]:
            o(f"    {threat_color}> {reason}{RST()}")
    nl()

    # ═══ FOCUS MODE: Task Type Detection ═══
    focus_sections = None  # None = show everything
    task_types_detected = detect_task_type(d)

    if focus_mode and task_types_detected:
        primary = task_types_detected[0]
        task_name, task_score, task_info = primary
        focus_sections = set(task_info["render_sections"])

        # If multiple types are close in score, merge their sections
        for name, score, info in task_types_detected[1:3]:
            if score >= task_score * 0.6:  # within 60% of top score
                focus_sections |= info["render_sections"]

        o(f"  {BOLD()}{BMAG()}{'─'*W}{RST()}")
        o(f"  {BOLD()}{BMAG()}  DETECTED TASK TYPE: {task_info['label']}{RST()}")
        o(f"  {BMAG()}  {task_info['description']}{RST()}")
        if len(task_types_detected) > 1:
            other = task_types_detected[1]
            if other[1] >= task_score * 0.6:
                o(f"  {DIM()}  Also possible: {other[2]['label']} (score: {other[1]}){RST()}")
        o(f"  {BOLD()}{BMAG()}{'─'*W}{RST()}")
        nl()
    elif focus_mode:
        # No strong task type detected - show everything with a note
        o(f"  {DIM()}  Auto-detect: No strong task type identified. Showing full output.{RST()}")
        nl()
    elif task_types_detected:
        # Not in focus mode but still show detected type as a hint
        primary = task_types_detected[0]
        if primary[1] >= 30:  # only show if confident enough
            o(f"  {DIM()}Detected: {primary[2]['label']} (use --auto for focused output){RST()}")
            nl()

    _sr = lambda section: _should_render_section(section, focus_sections)

    h2("FILE INFO")
    kv("File", fname)
    kv("Size", human_size(d.get("size_bytes",0)))
    pkt = d.get("packet_count",0)
    if pkt:
        kv("Packets", f"{pkt:,}")
        kv("Pkt size", f"min={d.get('pkt_len_min',0)}  max={d.get('pkt_len_max',0)}  avg={d.get('pkt_len_avg',0)}")
    cs = d.get("capture_start","")
    if cs: kv("Start", cs)
    ce = d.get("capture_end","")
    if ce: kv("End", ce)
    dur = d.get("capture_duration")
    if dur is not None:
        if dur > 3600:
            kv("Duration", f"{dur/3600:.1f} hours ({dur:.0f}s)")
        elif dur > 60:
            kv("Duration", f"{dur/60:.1f} minutes ({dur:.0f}s)")
        else:
            kv("Duration", f"{dur:.1f} seconds")
    # Show detected protocols summary
    proto_checks = [
        ("http_traffic", "HTTP"), ("dns_queries", "DNS"), ("tls_sni_certs", "TLS"),
        ("ftp_traffic", "FTP"), ("smtp_email", "SMTP"), ("smb2_files", "SMB2"),
        ("smb_files", "SMB"), ("ssh_banners", "SSH"), ("dhcp_leases", "DHCP"),
        ("irc_messages", "IRC"), ("kerberos_traffic", "Kerberos"),
        ("dcerpc_traffic", "DCE/RPC"), ("drsuapi_traffic", "DRSUAPI"),
        ("mqtt_messages", "MQTT"), ("rdp_connections", "RDP"),
        ("llmnr_queries", "LLMNR"), ("llmnr_responses", "LLMNR"),
        ("nbns_queries", "NBNS"), ("nbns_responses", "NBNS"),
        ("mdns_traffic", "mDNS"), ("wifi_networks", "WiFi"),
        ("usb_hid_events", "USB HID"), ("http2_traffic", "HTTP/2"),
        ("telnet_data", "Telnet"), ("credentials", "Creds"),
        ("tcp_stream_count", "TCP"), ("udp_stream_count", "UDP"),
        ("icmp_payloads", "ICMP"), ("arp_count", "ARP"),
        ("quic_connections", "QUIC"), ("ssdp_devices", "SSDP"),
        ("ntp_servers", "NTP"), ("cldap_traffic", "CLDAP"),
        ("lldp_devices", "LLDP"), ("lsarpc_traffic", "LSARPC"),
        ("srvsvc_traffic", "SRVSVC"), ("havoc_streams", "Havoc C2"),
        ("tftp_transfers", "TFTP"), ("snmp_communities", "SNMP"),
        ("syslog_messages", "Syslog"), ("tor_traffic", "Tor"),
        ("crypto_mining", "Mining"), ("usb_mouse_coords", "USB Mouse"),
    ]
    detected = []
    for key, label in proto_checks:
        v = d.get(key)
        if v and (isinstance(v, (list, str)) and len(v) > 0 or isinstance(v, int) and v > 0):
            if label not in detected:
                detected.append(label)
    if detected:
        kv("Protocols", ", ".join(detected))

    ph = d.get("protocol_hierarchy","")
    if ph and _sr("overview"):
        h2("PROTOCOL HIERARCHY")
        for l in ph.splitlines():
            dim(l)
    io = d.get("io_stats","")
    if io and _sr("overview"):
        h2("IO STATISTICS")
        for l in io.splitlines():
            dim(l)

    if _sr("conversations") or _sr("endpoints"):
        for key, label in [("ip_endpoints","IP ENDPOINTS"),("ip_conversations","IP CONVERSATIONS"),
                           ("tcp_conversations","TCP CONVERSATIONS"),("udp_conversations","UDP CONVERSATIONS")]:
            raw = d.get(key,"")
            if raw and raw.strip():
                h2(label)
                for l in raw.splitlines():
                    dim(l)

        # Top Talkers — parse from ip_endpoints stat output
        ep_raw = d.get("ip_endpoints", "")
        if ep_raw:
            talkers = []
            for line in ep_raw.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0].count(".") == 3:
                    try:
                        talkers.append((parts[0], int(parts[1]), int(parts[2])))
                    except (ValueError, IndexError):
                        pass
            if talkers:
                talkers.sort(key=lambda x: -x[2])
                h2("TOP TALKERS", min(len(talkers), 10))
                rows = [(ip, f"{pkts:,}", human_size(byt)) for ip, pkts, byt in talkers[:10]]
                table(rows, ["IP Address", "Packets", "Bytes"])

    tc = d.get("tcp_stream_count"); uc = d.get("udp_stream_count")
    if (tc or uc) and _sr("streams"):
        h2("STREAM SUMMARY")
        if tc: kv("TCP streams", str(tc))
        if uc: kv("UDP streams", str(uc))

    previews = d.get("tcp_stream_previews",[])
    if previews and _sr("streams"):
        h2("TCP STREAM CONTENT", len(previews))
        for sp in previews:
            h3(f"Stream {sp['stream']}")
            for line in sp["preview"].splitlines()[:25]: dim(line)
            flag_hunt(sp["preview"])

    udp_prev = d.get("udp_stream_previews",[])
    if udp_prev and _sr("streams"):
        h2("UDP STREAM CONTENT", len(udp_prev))
        for sp in udp_prev:
            h3(f"UDP Stream {sp['stream']}")
            for line in sp["preview"].splitlines()[:20]: dim(line)
            flag_hunt(sp["preview"])

    dns = d.get("dns_queries",[])
    if dns and _sr("dns"):
        h2("DNS", len(dns))
        rows = []
        for item in dns[:60]:
            p_ = item.split("|") if "|" in item else item.split("\t")
            rows.append((p_[0] if p_ else "", p_[1] if len(p_)>1 else "", ", ".join(x for x in p_[2:6] if x.strip())[:50]))
        table(rows, ["Query","Type","Answer"])
        domains = d.get("dns_unique_domains",[])
        if domains:
            h3("Unique domains")
            for dom in domains[:30]:
                dim(dom)
    exfil = d.get("dns_exfil_suspects",[])
    if exfil and _sr("dns_exfil"):
        h2("⚠ DNS EXFILTRATION SUSPECTS")
        for e in exfil:
            alert(e)
    hex_subs = d.get("dns_hex_subdomains",[])
    if hex_subs and _sr("dns_exfil"):
        h3("Hex-encoded subdomains")
        for s in hex_subs[:10]:
            warn(s)
    b64_subs = d.get("dns_b64_subdomains",[])
    if b64_subs and _sr("dns_exfil"):
        h3("Base64-encoded subdomains")
        for s in b64_subs[:10]:
            warn(s)
    if d.get("dns_errors") and _sr("dns"): warn(f"DNS errors: {d['dns_errors']}")

    # DNS Tunnel Data (decoded)
    tunnel_data = d.get("dns_tunnel_decoded", [])
    if tunnel_data and _sr("dns_tunnel"):
        h2("!! DNS TUNNEL DATA DECODED", len(tunnel_data))
        for td in tunnel_data:
            o(f"    {BOLD()}Domain:{RST()} {td['domain']}  {BOLD()}Encoding:{RST()} {td['encoding']}  {BOLD()}Chunks:{RST()} {td['chunks']}")
            o(f"    {BGRN()}Decoded:{RST()}")
            for line in td["decoded"][:500].splitlines()[:15]:
                o(f"      {BGRN()}{line}{RST()}")
            flag_hunt(td["decoded"])
        nl()

    # DNS Tool Suspects
    dns_tools = d.get("dns_tool_suspects", [])
    if dns_tools and _sr("dns_tools"):
        h3("DNS Tunneling Tool Indicators")
        for t in dns_tools[:10]:
            alert(t)

    # DNS TXT Records
    dns_txt = d.get("dns_txt_records", [])
    if dns_txt and _sr("dns_txt"):
        h3("DNS TXT Records")
        for t in dns_txt[:15]:
            dim(t[:120])
            flag_hunt(t)

    http = d.get("http_traffic",[])
    if http and _sr("http"):
        h2("HTTP TRAFFIC", len(http))
        rows, uas, servers, cookies = [], [], set(), []
        for item in http[:80]:
            p_ = item.split("|") if "|" in item else []; 
            if len(p_) < 5: continue
            frame, ftime = p_[0].strip(), short_time(p_[1].strip())
            src, dst = p_[2].strip(), p_[3].strip()
            method, host = p_[4].strip(), p_[5].strip() if len(p_)>5 else ""
            uri = p_[6].strip() if len(p_)>6 else ""
            resp = p_[7].strip() if len(p_)>7 else ""
            ctype = p_[8].strip() if len(p_)>8 else ""
            ua = p_[9].strip() if len(p_)>9 else ""
            cookie_set = p_[10].strip() if len(p_)>10 else ""
            server = p_[13].strip() if len(p_)>13 else ""
            if method:
                rows.append((frame, ftime, f"{src}->{dst}", f"{BCYN()}{method}{RST()}", host, uri[:45]))
            elif resp:
                rc = BGRN() if resp.startswith("2") else (BYEL() if resp.startswith("3") else BRED())
                rows.append((frame, ftime, f"{src}->{dst}", f"{rc}<-{resp}{RST()}", ctype[:25], ""))
            if ua and ua not in uas: uas.append(ua)
            if server: servers.add(server)
            if cookie_set: cookies.append(cookie_set)
        table(rows, ["Frame","Time","Flow","Method","Host/Type","URI"])
        if uas:
            h3("User-Agents")
            for u in uas[:8]:
                dim(u)
        if servers:
            h3("Servers")
            for s in sorted(servers):
                dim(s)
        if cookies:
            h3(f"Set-Cookie ({len(cookies)})")
            for c in cookies[:5]:
                dim(c[:100])

    fdata = d.get("http_file_data","")
    if fdata and _sr("http_body"):
        h2("HTTP RESPONSE BODY")
        decoded = hex_decode(fdata)
        for line in decoded[:1200].splitlines()[:20]: dim(line)
        flag_hunt(decoded)

    posts = d.get("http_posts",[])
    if posts and _sr("http_posts"):
        h2("HTTP POST BODIES", len(posts))
        for post in posts:
            o(f"    {BOLD()}Frame {post['frame']}{RST()}  {post['src']}->{post['dst']}  {BCYN()}{post['uri']}{RST()}")
            if post.get("ctype"): dim(f"Content-Type: {post['ctype']}")
            keys, vals = post.get("form_keys",""), post.get("form_values","")
            if keys or vals: o(f"      {BYEL()}Form: {keys} = {vals}{RST()}")
            body = hex_decode(post.get("body",""))
            if body: dim(body[:400])
            raw = post.get("raw","")
            if raw and not body: dim(hex_decode(raw)[:400])
            flag_hunt(f"{keys} {vals} {body} {raw}")

    objects = d.get("http_objects",[])
    if objects and _sr("http_objects"):
        h2("HTTP OBJECTS", len(objects))
        rows = [(o_["frame"],o_["ctype"][:30],o_.get("size",""),o_.get("uri","")[:40],o_.get("status",""),o_.get("server","")[:20]) for o_ in objects]
        table(rows, ["Frame","Content-Type","Size","URI","Status","Server"])
        info(f"Extract: tshark -r {fname} --export-objects http,./exported/")

    ftp = d.get("ftp_traffic",[])
    if ftp and _sr("ftp"):
        h2("FTP", len(ftp))
        for line in ftp[:30]:
            p_ = line.split("|")
            cmd = p_[3].strip() if len(p_)>3 else ""
            arg = p_[4].strip() if len(p_)>4 else ""
            resp_code = p_[5].strip() if len(p_)>5 else ""
            resp_arg = p_[6].strip() if len(p_)>6 else ""
            if cmd:
                color = BRED() if cmd in ("USER","PASS") else GRN()
                o(f"    {color}{cmd} {arg}{RST()}")
            elif resp_code: dim(f"{resp_code} {resp_arg}")
        flag_hunt(str(ftp))
    if d.get("ftp_data") and _sr("ftp"): info(f"FTP data transfers: {len(d['ftp_data'])}")

    # FTP Credentials
    ftp_creds = d.get("ftp_credentials", [])
    if ftp_creds and _sr("ftp_creds"):
        h2("!! FTP CREDENTIALS FOUND", len(ftp_creds))
        rows = [(c["frame"], f"{c['src']}->{c['dst']}", f"{BRED()}{c['user']}{RST()}", f"{BRED()}{c['pass']}{RST()}") for c in ftp_creds]
        table(rows, ["Frame", "Flow", "Username", "Password"])

    smtp = d.get("smtp_email",[])
    if smtp and _sr("smtp"):
        h2("SMTP / EMAIL")
        for line in smtp[:20]:
            p_ = line.split("|")
            frm, to, subj = p_[2].strip() if len(p_)>2 else "", p_[3].strip() if len(p_)>3 else "", p_[4].strip() if len(p_)>4 else ""
            if frm or to or subj:
                o(f"    From: {CYN()}{frm}{RST()}  To: {CYN()}{to}{RST()}")
                if subj: o(f"    Subject: {BOLD()}{subj}{RST()}")
            elif p_[0].strip(): dim(p_[0].strip()[:100])
        flag_hunt(str(smtp))

    smb = d.get("smb_files",[])
    smb2_shares = d.get("smb2_shares",[])
    smb2_files = d.get("smb2_files",[])
    smb_ntlm = d.get("smb_ntlm_auth",[])
    if (smb or smb2_shares or smb2_files or smb_ntlm) and _sr("smb"):
        h2("SMB / SMB2")
        if smb_ntlm:
            h3("NTLM Authentication")
            rows = [(a["frame"], f"{a['domain']}\\{a['user']}", a["host"], f"{a['src']}->{a['dst']}") for a in smb_ntlm[:15]]
            table(rows, ["Frame", "Domain\\User", "Hostname", "Flow"])
        if smb2_shares:
            h3("Share Access")
            rows = [(s["frame"], short_time(s["time"]), f"{s['src']}->{s['dst']}", f"{BCYN()}{s['share']}{RST()}") for s in smb2_shares[:20]]
            table(rows, ["Frame", "Time", "Flow", "Share"])
        if smb2_files:
            h3("File Operations")
            seen = set()
            rows = []
            for ff in smb2_files[:40]:
                key = ff["file"]
                if key not in seen:
                    seen.add(key)
                    rows.append((ff["frame"], f"{ff['src']}->{ff['dst']}", f"{GRN()}{ff['file']}{RST()}"))
            table(rows, ["Frame", "Flow", "File"])
        if smb:
            h3("SMB1 Files")
            for ff in smb[:15]:
                o(f"    {GRN()}{ff}{RST()}")

    tls = d.get("tls_sni_certs",[])
    if tls and _sr("tls"):
        h2("TLS SNI / CERTIFICATES", len(tls))
        for l in tls[:25]:
            dim(l)
    tls_ver = d.get("tls_versions")
    if tls_ver and _sr("tls"):
        h3("TLS Versions")
        vnames = {"0x0300":"SSL 3.0","0x0301":"TLS 1.0","0x0302":"TLS 1.1","0x0303":"TLS 1.2","0x0304":"TLS 1.3"}
        for ver, cnt in tls_ver.items():
            name = vnames.get(ver, ver)
            color = BRED() if ver in ("0x0300","0x0301","0x0302") else BGRN()
            o(f"    {color}{name} ({ver}): {cnt}{RST()}")
    ciph = d.get("tls_ciphers",[])
    if ciph and _sr("tls"):
        h3("Ciphers")
        for c in ciph[:10]:
            dim(c)
    ja3 = d.get("ja3_fingerprints")
    if ja3 and _sr("ja3"):
        h3("JA3 Client Fingerprints")
        for h_, s in ja3.items():
            tag = ""
            if h_ in KNOWN_JA3:
                tag = f"  {BRED()}** {KNOWN_JA3[h_]} **{RST()}"
            dim(f"{h_[:32]}...  from: {', '.join(s[:5])}{tag}")
    ja3s = d.get("ja3s_fingerprints")
    if ja3s and _sr("ja3s"):
        h3("JA3S Server Fingerprints")
        for h_, s in ja3s.items():
            tag = ""
            if h_ in KNOWN_JA3S:
                tag = f"  {BRED()}** {KNOWN_JA3S[h_]} **{RST()}"
            dim(f"{h_[:32]}...  server: {', '.join(s[:5])}{tag}")

    creds = d.get("credentials",[])
    if creds and _sr("credentials"):
        h2("⚠ CREDENTIALS")
        for c in creds:
            alert(c)
    telnet = d.get("telnet_data","")
    if telnet and _sr("telnet"):
        h2("TELNET PLAINTEXT")
        for l in telnet[:800].splitlines()[:15]:
            dim(l)
        flag_hunt(telnet)

    # HTTP Basic Auth (decoded)
    http_basic = d.get("http_basic_auth", [])
    if http_basic and _sr("http_basic"):
        h2("!! HTTP BASIC AUTH CREDENTIALS", len(http_basic))
        rows = [(c["frame"], f"{c['src']}->{c.get('host', c['dst'])}",
                 f"{BRED()}{c['user']}{RST()}", f"{BRED()}{c['pass']}{RST()}",
                 c.get("uri","")[:30]) for c in http_basic]
        table(rows, ["Frame", "Target", "Username", "Password", "URI"])

    # HTTP Form Login Credentials
    form_logins = d.get("http_form_logins", [])
    if form_logins and _sr("http_form"):
        h2("!! HTTP LOGIN FORM DATA", len(form_logins))
        for fl in form_logins:
            o(f"    {BOLD()}Frame {fl['frame']}{RST()}  {fl['src']}->{fl.get('host','')}{fl['uri']}")
            o(f"      {BRED()}{fl['keys']} = {fl['values']}{RST()}")

    # NTLM Hashes (for hashcat)
    ntlm_hashes = d.get("ntlm_hashes", [])
    if ntlm_hashes and _sr("ntlm_hashes"):
        h2("!! NTLM HASHES (hashcat -m 5600)", len(ntlm_hashes))
        for h_ in ntlm_hashes:
            alert(f"{h_['domain']}\\{h_['user']}")
            if h_.get("hashcat_format"):
                dim(f"  {h_['hashcat_format'][:120]}")

    icmp = d.get("icmp_payloads",0)
    if icmp and _sr("icmp"):
        h2(f"ICMP ECHO DATA ({icmp} packets)")
        decoded = d.get("icmp_decoded","")
        if decoded: found(f"Decoded: {decoded[:200]}")
        len_dec = d.get("icmp_len_decoded","")
        if len_dec: found(f"Length-encoded: {len_dec}")
        single_byte = d.get("icmp_single_byte_decoded", "")
        if single_byte: found(f"Single-byte-per-packet: {single_byte}")
        if d.get("icmp_tunnel_suspect"):
            alert(f"ICMP tunnel suspected! {d.get('icmp_tunnel_packets', 0)} large-payload packets")
        icmp_convos = d.get("icmp_conversations", {})
        if icmp_convos:
            h3("ICMP Conversations")
            for pair, count in icmp_convos.items():
                dim(f"{pair}: {count} packets")
        flag_hunt((decoded or "") + (len_dec or "") + (single_byte or ""))

    usb = d.get("usb_hid_events",0)
    if usb and _sr("usb_hid"):
        h2(f"USB HID ({usb} events)")
        # Show decoded keystrokes first (most important)
        usb_decoded = d.get("usb_hid_decoded", "")
        if usb_decoded:
            h3("!! DECODED KEYSTROKES")
            o(f"    {BGRN()}{usb_decoded}{RST()}")
            flag_hunt(usb_decoded)
        else:
            info("Could not decode keystrokes (may not be keyboard HID data)")
        h3("Raw HID events (first 15)")
        for r in d.get("usb_hid_raw",[])[:15]: dim(r)

    dhcp = d.get("dhcp_leases",[])
    if dhcp and _sr("dhcp"):
        h2("DHCP LEASES", len(dhcp))
        rows = [(e.get("hostname",""),e.get("assigned_ip","") or e.get("req_ip",""),e.get("mac",""),e.get("server",""),e.get("domain",""),e.get("vendor","")[:20]) for e in dhcp if e.get("hostname") or e.get("assigned_ip")]
        if rows: table(rows, ["Hostname","IP","MAC","Server","Domain","Vendor"])

    ac = d.get("arp_count",0)
    if ac and _sr("arp"): kv("ARP packets", str(ac))
    spoof = d.get("arp_spoofing")
    if spoof and _sr("arp_spoofing"):
        h2("⚠ ARP SPOOFING")
        for ip, macs in spoof.items():
            alert(f"{ip} claimed by: {', '.join(macs)}")

    ssh = d.get("ssh_banners",[])
    if ssh and _sr("ssh"):
        h2("SSH", len(ssh))
        for b in ssh:
            dim(b)

    # ═══ LLMNR ═══
    llmnr_q = d.get("llmnr_queries", [])
    llmnr_r = d.get("llmnr_responses", [])
    if (llmnr_q or llmnr_r) and _sr("llmnr"):
        h2("LLMNR", len(llmnr_q) + len(llmnr_r))
        if llmnr_q:
            h3("Queries")
            rows = [(e["frame"], short_time(e["time"]), e["src"], e["dst"], f"{BCYN()}{e['name']}{RST()}") for e in llmnr_q[:30]]
            table(rows, ["Frame", "Time", "Src", "Dst", "Name"])
        if llmnr_r:
            h3("Responses")
            rows = [(e["frame"], short_time(e["time"]), e["src"], e["dst"], f"{BCYN()}{e['name']}{RST()}", e.get("answer_a","") or e.get("answer_aaaa","")) for e in llmnr_r[:30]]
            table(rows, ["Frame", "Time", "Src", "Dst", "Name", "Answer"])
    llmnr_poison = d.get("llmnr_poisoning")
    if llmnr_poison and _sr("llmnr"):
        h2("⚠ LLMNR POISONING DETECTED")
        for name, ips in llmnr_poison.items():
            alert(f"'{name}' answered by multiple IPs: {', '.join(ips)}")

    # ═══ NBNS ═══
    nbns_q = d.get("nbns_queries", [])
    nbns_r = d.get("nbns_responses", [])
    if (nbns_q or nbns_r) and _sr("nbns"):
        h2("NBNS / NetBIOS", len(nbns_q) + len(nbns_r))
        if nbns_q:
            h3("Queries")
            rows = [(e["frame"], short_time(e["time"]), e["src"], e["dst"], f"{BCYN()}{e['name']}{RST()}") for e in nbns_q[:30]]
            table(rows, ["Frame", "Time", "Src", "Dst", "Name"])
        if nbns_r:
            h3("Responses")
            rows = [(e["frame"], short_time(e["time"]), e["src"], e["dst"], f"{BCYN()}{e['name']}{RST()}", e.get("addr","")) for e in nbns_r[:30]]
            table(rows, ["Frame", "Time", "Src", "Dst", "Name", "Address"])
    nbns_poison = d.get("nbns_poisoning")
    if nbns_poison and _sr("nbns"):
        h2("⚠ NBNS POISONING DETECTED")
        for name, ips in nbns_poison.items():
            alert(f"'{name}' answered by multiple IPs: {', '.join(ips)}")

    # ═══ mDNS ═══
    mdns = d.get("mdns_traffic", [])
    if mdns and _sr("mdns"):
        h2("mDNS", len(mdns))
        for line in mdns[:30]:
            dim(line)

    irc = d.get("irc_messages",[])
    if irc and _sr("irc"):
        h2("IRC", len(irc))
        for msg in irc[:30]:
            p_ = msg.split("|")
            text = (p_[2].strip() if len(p_)>2 else "") or (p_[3].strip() if len(p_)>3 else "")
            o(f"    {DIM()}{p_[0].strip() if p_ else ''}{RST()} {text}")
            flag_hunt(text)

    tftp = d.get("tftp_transfers",[])
    if tftp and _sr("tftp"):
        h2("TFTP TRANSFERS")
        for tl in tftp[:20]:
            p_ = tl.split("|")
            o(f"    {p_[0].strip() if p_ else ''}->{p_[1].strip() if len(p_)>1 else ''}  {GRN()}{(p_[3].strip() if len(p_)>3 else '') or (p_[4].strip() if len(p_)>4 else '')}{RST()}")
        info(f"Extract: tshark -r {fname} --export-objects tftp,./exported/")

    krb = d.get("kerberos_traffic",[])
    if krb and _sr("kerberos"):
        h2("KERBEROS", len(krb))
        rows = []
        for k in krb[:30]:
            rows.append((
                k.get("frame",""), short_time(k.get("time","")),
                f"{k.get('src','')}->{k.get('dst','')}",
                f"{BYEL()}{k.get('msg_type','')}{RST()}",
                k.get("cname",""), k.get("sname",""),
                k.get("realm",""),
            ))
        table(rows, ["Frame","Time","Flow","Type","Client","Service","Realm"])
        etypes = d.get("kerberos_etypes",[])
        if etypes:
            etype_names = {"17":"AES128","18":"AES256","23":"RC4-HMAC","24":"RC4-HMAC-EXP","3":"DES-CBC-MD5"}
            h3("Encryption Types")
            for e in etypes:
                name = etype_names.get(e, f"etype-{e}")
                color = BRED() if e == "23" else (BYEL() if e in ("3","24") else BGRN())
                o(f"    {color}{name} ({e}){RST()}")
    krb_err = d.get("kerberos_errors",[])
    if krb_err and _sr("kerberos"):
        h3("Kerberos Errors")
        for e in krb_err[:10]:
            alert(f"Frame {e['frame']}: error={e['error']} {e.get('cname','')} -> {e.get('sname','')} @{e.get('realm','')}")

    # Kerberos Hashes (hashcat-ready)
    krb_hashes = d.get("kerberos_hashes", [])
    if krb_hashes and _sr("kerberos_hashes"):
        h2("!! KERBEROS HASHES (hashcat-ready)", len(krb_hashes))
        for kh in krb_hashes:
            alert(f"Frame {kh['frame']}: {kh['type']} — {kh['user']} -> {kh['spn']} @{kh['realm']}")
            dim(f"  hashcat -m {kh['hashcat_mode']} hash.txt wordlist.txt")
            dim(f"  {kh['hash'][:120]}...")
    asrep_hashes = d.get("asrep_hashes", [])
    if asrep_hashes and _sr("asrep_hashes"):
        h2("!! AS-REP HASHES (hashcat -m 18200)", len(asrep_hashes))
        for ah in asrep_hashes:
            alert(f"Frame {ah['frame']}: {ah['user']}@{ah['realm']}")
            dim(f"  {ah['hash'][:120]}...")

    # DCE/RPC
    drsuapi = d.get("drsuapi_traffic",[])
    if drsuapi and _sr("drsuapi"):
        h2("⚠ DRSUAPI (DCSync Indicator)", len(drsuapi))
        rows = [(d_["frame"], short_time(d_["time"]), f"{d_['src']}->{d_['dst']}", f"{BRED()}{d_['op']}{RST()}") for d_ in drsuapi]
        table(rows, ["Frame", "Time", "Flow", "Operation"])
    dcsync = d.get("dcsync_detected",[])
    if dcsync and _sr("dcsync"):
        alert(f"DCSync detected! DsGetNCChanges from {', '.join(set(d_['src'] for d_ in dcsync))}")

    dcerpc = d.get("dcerpc_traffic",[])
    if dcerpc and not drsuapi and _sr("dcerpc"):
        h2("DCE/RPC", len(dcerpc))
        rows = [(e["frame"], f"{e['src']}->{e['dst']}", e.get("op",""), e.get("bind","")[:40]) for e in dcerpc[:20]]
        table(rows, ["Frame", "Flow", "Op", "Interface"])

    lsarpc = d.get("lsarpc_traffic",[])
    if lsarpc and _sr("dcerpc"):
        h2("LSARPC", len(lsarpc))
        for l in lsarpc[:10]: dim(l)

    srvsvc = d.get("srvsvc_traffic",[])
    if srvsvc and _sr("dcerpc"):
        h2("SRVSVC (Share Enum)", len(srvsvc))
        for l in srvsvc[:10]: dim(l)

    # RDP
    rdp = d.get("rdp_connections",[])
    if rdp and _sr("rdp"):
        h2("RDP CONNECTIONS", len(rdp))
        for r in rdp:
            o(f"    {BYEL()}{r}{RST()}")

    # QUIC
    quic = d.get("quic_connections")
    if quic and _sr("quic"):
        h2("QUIC", len(quic))
        rows = [(k, str(v["count"]), ", ".join(v["versions"])[:30]) for k, v in list(quic.items())[:15]]
        table(rows, ["Connection", "Packets", "Versions"])

    # SSDP
    ssdp = d.get("ssdp_devices",[])
    if ssdp and _sr("ssdp"):
        h2("SSDP DEVICES", len(ssdp))
        for s in ssdp[:15]: dim(s)

    # NTP
    ntp = d.get("ntp_servers",[])
    if ntp and _sr("ntp"):
        h2("NTP", len(ntp))
        for n in ntp: dim(n)

    # CLDAP
    cldap = d.get("cldap_traffic",[])
    if cldap and _sr("cldap"):
        h2("CLDAP (AD Discovery)", len(cldap))
        for l in cldap[:10]: dim(l)

    # LLDP
    lldp = d.get("lldp_devices",[])
    if lldp and _sr("lldp"):
        h2("LLDP DEVICES", len(lldp))
        for l in lldp: dim(l)

    mqtt = d.get("mqtt_messages",[])
    if mqtt and _sr("mqtt"):
        h2("MQTT", len(mqtt))
        for m in mqtt[:20]:
            p_ = m.split("|")
            user = p_[3].strip() if len(p_)>3 else ""
            pw = p_[4].strip() if len(p_)>4 else ""
            if user or pw: alert(f"MQTT creds: {user}:{pw}")
            topic = p_[0].strip() if p_ else ""
            msg = p_[1].strip() if len(p_)>1 else ""
            if topic: o(f"    {CYN()}{topic}{RST()}: {msg[:100]}")
            flag_hunt(msg)

    snmp = d.get("snmp_communities",[])
    if snmp and _sr("snmp"):
        h2("SNMP COMMUNITY STRINGS")
        for c in snmp:
            warn(c)

    syslog = d.get("syslog_messages",[])
    if syslog and _sr("syslog"):
        h2("SYSLOG", len(syslog))
        for m in syslog[:15]:
            dim(m[:120])

    wifi = d.get("wifi_networks",[])
    if wifi and _sr("wifi"):
        h2("WIFI NETWORKS", len(wifi))
        for n in wifi:
            o(f"    {GRN()}{n}{RST()}")
    probes = d.get("wifi_probes",[])
    if probes and _sr("wifi_probes"):
        h3("Probe Requests")
        for p_ in probes[:15]:
            dim(p_)
    eapol = d.get("wifi_eapol_count",0)
    if eapol and _sr("wifi"):
        warn(f"EAPOL/WPA Handshake: {eapol}")
        info(f"Crack: aircrack-ng -w wordlist.txt {fname}")
    deauth = d.get("wifi_deauth_count",0)
    if deauth and _sr("wifi"): alert(f"Deauth frames: {deauth}")

    h2_ = d.get("http2_traffic",[])
    if h2_ and _sr("http2"):
        h2("HTTP/2", len(h2_))
        for l in h2_[:20]:
            dim(l)

    # ═══ HAVOC C2 ═══
    havoc = d.get("havoc_streams", [])
    havoc_http = d.get("havoc_http_posts", [])
    if (havoc or havoc_http) and _sr("havoc"):
        nl()
        o(f"{BOLD()}{BMAG()}{'='*W}{RST()}")
        o(f"{BOLD()}{BMAG()}  HAVOC C2 ANALYSIS{RST()}")
        o(f"{BOLD()}{BMAG()}{'='*W}{RST()}")

        for hs in havoc:
            score = hs["score"]
            score_color = BRED() if score >= 50 else (BYEL() if score >= 25 else DIM())
            h3(f"Stream {hs['stream_id']}  {score_color}[score: {score}]{RST()}")
            kv("Packets", str(hs["packet_count"]))
            duration = hs["last_seen"] - hs["first_seen"]
            kv("Duration", f"{duration:.1f}s")
            kv("Indicators", ", ".join(hs["indicators"]))
            for flow in hs.get("flows", []):
                kv("Flow", flow)

            beacon = hs.get("beacon")
            if beacon:
                kv("Beacon", f"{beacon['interval']}s interval, {beacon['jitter_pct']}% jitter, "
                             f"{beacon['count']} hits")
                import time as _time
                try:
                    kv("First seen", _time.strftime("%Y-%m-%d %H:%M:%S", _time.gmtime(beacon["first_seen"])))
                    kv("Last seen", _time.strftime("%Y-%m-%d %H:%M:%S", _time.gmtime(beacon["last_seen"])))
                except Exception:
                    pass

            # Show checkins
            checkins = hs.get("checkins", [])
            if checkins:
                h3("  Agent Checkins")
                for ci in checkins[:5]:
                    o(f"    {BOLD()}Frame {ci['frame']}{RST()}  {ci['src']}->{ci['dst']}")
                    kv("Agent ID", ci["agent_id"], 6)
                    kv("Timestamp", str(ci["timestamp"]), 6)
                    kv("Encrypted blob", f"{ci['blob_size']} bytes", 6)
                    dim(f"      {ci['blob_hex'][:80]}{'...' if len(ci['blob_hex']) > 80 else ''}")

            # Show decrypted commands
            dec = hs.get("decrypted", [])
            if dec:
                h3("  Decrypted Commands/Responses")
                for dc in dec[:20]:
                    cmd = dc.get("command")
                    if cmd:
                        o(f"    {BOLD()}Frame {dc['frame']}{RST()} {dc['src']}->{dc['dst']}  "
                          f"{BRED()}{cmd['task_name']}{RST()} (type={cmd['task_type']})")
                        if cmd.get("data"):
                            for cline in cmd["data"][:200].splitlines()[:5]:
                                dim(f"      {cline}")
                    else:
                        o(f"    {BOLD()}Frame {dc['frame']}{RST()} {dc['src']}->{dc['dst']}")
                        for cline in dc.get("plaintext", "")[:200].splitlines()[:5]:
                            dim(f"      {cline}")

                    exfil = dc.get("exfil_indicators", [])
                    if exfil:
                        alert(f"Exfil: {', '.join(exfil)}")
                    flag_hunt(dc.get("plaintext", ""))
            elif hs.get("magic_count", 0) > 0:
                dim("    No decryption key provided. Use --key <hex> to decrypt.")
                if checkins:
                    dim(f"    First blob preview: {checkins[0].get('blob_hex', '')[:64]}")

        if havoc_http:
            h3("Suspicious HTTP POSTs (binary/Havoc)")
            rows = []
            for hp in havoc_http[:20]:
                flag = (f"{BRED()}MAGIC{RST()}" if hp.get("has_magic") else
                        f"{BYEL()}BIN{RST()}" if hp.get("is_binary") else "")
                rows.append((hp["frame"], hp["src"], hp["dst"],
                             hp.get("uri","")[:30], hp.get("ctype","")[:20], flag))
            table(rows, ["Frame", "Src", "Dst", "URI", "Content-Type", "Flag"])

    # ═══ ALERTS ═══
    # Alerts always show — they contain the most critical findings
    nl()
    o(f"{BOLD()}{BRED()}{'='*W}{RST()}")
    o(f"{BOLD()}{BRED()}  ALERTS & FINDINGS{RST()}")
    o(f"{BOLD()}{BRED()}{'='*W}{RST()}")
    has_alerts = False

    # C2 Framework Detection
    c2_fw = d.get("c2_frameworks", {})
    if c2_fw and _sr("c2"):
        has_alerts = True
        h2("!! C2 FRAMEWORK DETECTED")
        for fw, info_ in c2_fw.items():
            score_color = BRED() if info_["score"] >= 30 else BYEL()
            o(f"    {score_color}{BOLD()}{fw.upper()}{RST()} (score: {info_['score']})")
            for ind in info_.get("indicators", [])[:5]:
                alert(ind)
            for ev in info_.get("evidence", [])[:5]:
                dim(f"  {ev}")

    # Brute Force
    brute = d.get("brute_force", [])
    if brute and _sr("brute_force"):
        has_alerts = True
        h2("!! BRUTE FORCE / LOGIN ATTACKS", len(brute))
        for b in brute:
            alert(f"{b['target']}: {b['attempts']} attempts")
            resp_str = ", ".join(f"{code}:{cnt}" for code, cnt in b["responses"])
            dim(f"  Response codes: {resp_str}")

    # Embedded Files
    embedded = d.get("embedded_files", [])
    if embedded and _sr("embedded_files"):
        has_alerts = True
        h2("!! EMBEDDED FILES DETECTED", len(embedded))
        rows = [(ef["signature"], f"offset {ef['offset']}", ef["hex"][:40]) for ef in embedded]
        table(rows, ["Type", "Location", "Hex Preview"])

    # Base64 Hidden Data
    b64_data = d.get("base64_hidden_data", [])
    if b64_data and _sr("base64_data"):
        has_alerts = True
        h2("!! BASE64 ENCODED DATA", len(b64_data))
        for bd in b64_data:
            o(f"    {BOLD()}Encoded:{RST()} {bd['encoded']}...")
            o(f"    {BGRN()}Decoded:{RST()} {bd['decoded'][:120]}")
            flag_hunt(bd["decoded"])

    # Data Exfiltration Volume
    exfil_vol = d.get("data_exfil_volume", [])
    if exfil_vol and _sr("exfil_volume"):
        has_alerts = True
        h2("!! DATA EXFILTRATION SUSPECTS (by volume)")
        rows = [(ev["ip"], human_size(ev["tx"]), human_size(ev["rx"]), f"{ev['ratio']}% outbound") for ev in exfil_vol]
        table(rows, ["IP", "TX", "RX", "Outbound Ratio"])

    # Reverse Shells
    revshells = d.get("reverse_shells", [])
    if revshells and _sr("revshells"):
        has_alerts = True
        h2("!! REVERSE SHELLS DETECTED", len(revshells))
        for rs in revshells:
            alert(f"Stream {rs['stream']}: {BRED()}{rs['type']}{RST()}")
            for line in rs.get("preview", "")[:200].splitlines()[:5]:
                dim(f"  {line}")

    # PowerShell Detection
    ps = d.get("powershell_detected", [])
    if ps and _sr("powershell"):
        has_alerts = True
        h2("!! POWERSHELL PAYLOADS", len(ps))
        for p in ps:
            alert(f"{p['type']}: {p['match'][:80]}")
            if p.get("decoded"):
                o(f"      {BGRN()}Decoded:{RST()} {p['decoded'][:150]}")
                flag_hunt(p["decoded"])
            if p.get("url"):
                o(f"      {BYEL()}URL:{RST()} {p['url']}")

    # EternalBlue
    if d.get("eternalblue_suspect") and _sr("eternalblue"):
        has_alerts = True
        h2("!! ETERNALBLUE / MS17-010 EXPLOIT SUSPECTED")
        alert(f"{d.get('eternalblue_packets', 0)} large SMBv1 transaction packets")
        for src in d.get("eternalblue_sources", []):
            alert(f"Attacker IP: {src}")

    # Malicious JA3 Fingerprints
    ja3_mal = d.get("ja3_malicious", [])
    if ja3_mal and _sr("ja3"):
        has_alerts = True
        h2("!! KNOWN MALICIOUS JA3 FINGERPRINTS")
        for j in ja3_mal:
            alert(f"{j['match']} from {j['src']} (hash: {j['hash'][:16]}...)")
    ja3s_mal = d.get("ja3s_malicious", [])
    if ja3s_mal and _sr("ja3s"):
        for j in ja3s_mal:
            alert(f"Server: {j['match']} at {j['src']} (JA3S: {j['hash'][:16]}...)")

    # TLS Certificate Anomalies
    cert_anom = d.get("tls_cert_anomalies", [])
    if cert_anom and _sr("cert_anomalies"):
        has_alerts = True
        h2("!! TLS CERTIFICATE ANOMALIES", len(cert_anom))
        for ca in cert_anom:
            anomaly_str = ", ".join(ca["anomalies"])
            alert(f"Frame {ca['frame']}: {ca['src']}->{ca['dst']} [{anomaly_str}]")
            if ca.get("subject"):
                dim(f"  Subject: {ca['subject']}")

    # Tor Traffic
    tor = d.get("tor_traffic")
    if tor and _sr("tor"):
        has_alerts = True
        h2("!! TOR TRAFFIC DETECTED")
        kv("Packets", str(tor.get("packet_count", 0)))
        if tor.get("cell_pattern"):
            alert(f"Tor cell pattern confirmed ({tor.get('512_byte_records', 0)} records)")
        for ip in tor.get("ips", [])[:10]:
            dim(f"  {ip}")

    # Crypto Mining
    mining = d.get("crypto_mining")
    if mining and _sr("mining"):
        has_alerts = True
        h2("!! CRYPTO MINING DETECTED")
        if mining.get("miners"):
            kv("Miners", ", ".join(mining["miners"]))
        if mining.get("pools"):
            kv("Pools", ", ".join(mining["pools"]))
        if mining.get("pool_dns"):
            h3("Mining Pool DNS Queries")
            for pd in mining["pool_dns"]:
                alert(pd)
        if mining.get("mining_port_count"):
            kv("Mining port packets", str(mining["mining_port_count"]))

    # Default Credentials
    defcreds = d.get("default_creds_found", [])
    if defcreds and _sr("default_creds"):
        has_alerts = True
        h2("!! DEFAULT CREDENTIALS USED", len(defcreds))
        rows = [(dc["proto"], f"{dc['src']}->{dc['dst']}",
                 f"{BRED()}{dc['user']}{RST()}", f"{BRED()}{dc['pass']}{RST()}") for dc in defcreds]
        table(rows, ["Protocol", "Flow", "Username", "Password"])

    # Covert Channels
    ttl = d.get("ttl_stego")
    if ttl and _sr("covert_channels"):
        has_alerts = True
        h2("!! TTL STEGANOGRAPHY DETECTED")
        kv("Source", ttl["src"])
        found(f"Decoded: {ttl['decoded']}")
        flag_hunt(ttl["decoded"])
    ipid = d.get("ipid_stego")
    if ipid and _sr("covert_channels"):
        has_alerts = True
        h2("!! IP ID STEGANOGRAPHY DETECTED")
        kv("Source", ipid["src"])
        found(f"Decoded: {ipid['decoded']}")
        flag_hunt(ipid["decoded"])

    # USB Mouse visualization
    mouse_ascii = d.get("usb_mouse_ascii", "")
    if mouse_ascii and _sr("usb_mouse"):
        has_alerts = True
        h2(f"!! USB MOUSE DRAWING ({d.get('usb_mouse_total',0)} events, {d.get('usb_mouse_drawn',0)} drawn)")
        for line in mouse_ascii.splitlines():
            o(f"    {GRN()}{line}{RST()}")
        flag_hunt(mouse_ascii)

    # WiFi SSID Flag
    ssid_flag = d.get("wifi_ssid_flag")
    if ssid_flag and _sr("wifi_ssid_flag"):
        has_alerts = True
        h2("!! WIFI SSID FLAG")
        found(ssid_flag)
        flag_hunt(ssid_flag)

    sus = d.get("suspicious_traffic",[])
    if sus and _sr("suspicious"):
        has_alerts = True
        h2("⚠ SUSPICIOUS TRAFFIC", len(sus))
        rows = [(s["frame"],short_time(s["time"]),f"{s['src']}->{s['dst']}",s["method"],s.get("uri","")[:35] or s.get("ctype",""),f"{RED()}{s['reason']}{RST()}") for s in sus]
        table(rows, ["Frame","Time","Flow","Method","Detail","Reason"])
    attacks = d.get("http_attacks",[])
    if attacks and _sr("http_attacks"):
        has_alerts = True
        h2("!! HTTP ATTACKS", len(attacks))
        rows = [(f"{RED()}{a['type']}{RST()}",a["src"],a.get("dst",""),a["uri"][:60]) for a in attacks]
        table(rows, ["Attack","Source","Target","URI"])
    scans = d.get("port_scans")
    if scans and _sr("port_scans"):
        has_alerts = True
        h2("⚠ PORT SCAN")
        for fl, c in sorted(scans.items(), key=lambda x: -x[1]):
            alert(f"{fl}: {c} ports")
    beacons = d.get("beacon_candidates",[])
    if beacons and _sr("beacons"):
        has_alerts = True
        h2("⚠ C2 BEACONS")
        rows = [(b["conn"],str(b["count"]),f"{b['avg']}s",f"±{b['std']}s") for b in beacons]
        table(rows, ["Connection","Hits","Interval","StdDev"])

    # Active Directory attack detections
    dcsync = d.get("dcsync_detected",[])
    if dcsync and _sr("dcsync"):
        has_alerts = True
        h2("⚠ DCSYNC ATTACK DETECTED")
        for dc in dcsync:
            alert(f"Frame {dc['frame']}: {dc['src']} -> {dc['dst']} DsGetNCChanges")
    kerberoast = d.get("kerberoasting_suspects",[])
    if kerberoast and _sr("kerberos"):
        has_alerts = True
        h2("⚠ KERBEROASTING SUSPECTED")
        for k in kerberoast[:10]:
            alert(f"Frame {k['frame']}: {k.get('cname','')} requesting {k.get('sname','')} with RC4 (etype 23)")
    asrep = d.get("asrep_roast_suspects",[])
    if asrep and _sr("kerberos"):
        has_alerts = True
        h2("⚠ AS-REP ROASTING SUSPECTED")
        for a in asrep[:10]:
            alert(f"Frame {a['frame']}: {a.get('cname','')} AS-REP with RC4 (etype 23)")
    llmnr_poison = d.get("llmnr_poisoning")
    if llmnr_poison and _sr("llmnr"):
        has_alerts = True
        h2("⚠ LLMNR POISONING DETECTED")
        for name, ips in llmnr_poison.items():
            alert(f"'{name}' answered by multiple IPs: {', '.join(ips)}")
    nbns_poison = d.get("nbns_poisoning")
    if nbns_poison and _sr("nbns"):
        has_alerts = True
        h2("⚠ NBNS POISONING DETECTED")
        for name, ips in nbns_poison.items():
            alert(f"'{name}' answered by multiple IPs: {', '.join(ips)}")
    arp_spoof = d.get("arp_spoofing")
    if arp_spoof and _sr("arp_spoofing"):
        has_alerts = True
        h2("⚠ ARP SPOOFING DETECTED")
        for ip, macs in arp_spoof.items():
            alert(f"{ip} claimed by: {', '.join(macs)}")

    stego = d.get("pkt_len_stego")
    if stego and _sr("stego"):
        has_alerts = True
        h2("✓ PKT LENGTH STEGO")
        found(stego)
    data_flags = d.get("flags_in_data",[])
    if data_flags and _sr("flags"):
        has_alerts = True
        h2("✓ FLAGS IN DATA")
        for fl in data_flags:
            found(f"🚩 {fl}")
    int_streams = d.get("interesting_streams",[])
    if int_streams and _sr("interesting_streams"):
        has_alerts = True
        h2("✓ INTERESTING STREAMS", len(int_streams))
        for s in int_streams:
            kw_tag = f"  {BYEL()}(secrets){RST()}" if s.get("keywords") else ""
            h3(f"Stream {s['stream']}{kw_tag}")
            for fl in s.get("flags",[]): found(f"🚩 {fl}")
            for line in s.get("preview","")[:300].splitlines()[:10]: dim(line)
    havoc_alert = d.get("havoc_streams", [])
    if havoc_alert and _sr("havoc"):
        has_alerts = True
        h2("⚠ HAVOC C2 DETECTED", len(havoc_alert))
        for hs in havoc_alert:
            score_color = BRED() if hs["score"] >= 50 else BYEL()
            alert(f"Stream {hs['stream_id']}: {score_color}score={hs['score']}{RST()} — "
                  f"{', '.join(hs['indicators'])}")
            for flow in hs.get("flows", [])[:3]:
                dim(f"    {flow}")
            dec_count = len(hs.get("decrypted", []))
            if dec_count:
                info(f"  {dec_count} decrypted command(s)")
                exfil_cmds = [dc for dc in hs.get("decrypted", []) if dc.get("exfil_indicators")]
                if exfil_cmds:
                    for ec in exfil_cmds[:5]:
                        alert(f"  Exfil in frame {ec['frame']}: {', '.join(ec['exfil_indicators'])}")
    if not has_alerts:
        dim("No suspicious patterns detected.")

    # ═══ MALICIOUS ENDPOINTS ═══
    # Score each IP by aggregating evidence across all detection modules.
    ep_scores = {}  # ip -> {"reasons": set(), "severity": int}

    def _tag(ip, reason, severity=1):
        if not ip:
            return
        ep_scores.setdefault(ip, {"reasons": set(), "severity": 0})
        ep_scores[ip]["reasons"].add(reason)
        ep_scores[ip]["severity"] += severity

    # Attack sources (high severity)
    for a in d.get("http_attacks", []):
        _tag(a.get("src"), f"HTTP {a['type']} attack", 3)
        _tag(a.get("dst"), f"HTTP {a['type']} target", 1)

    # Port scanners (high severity)
    for scan_key, port_count in d.get("port_scans", {}).items():
        src = scan_key.split("->")[0]
        _tag(src, f"Port scan ({port_count} ports)", 3)

    # C2 beacon sources/destinations (high severity)
    for b in d.get("beacon_candidates", []):
        parts = b["conn"].split("->")
        if len(parts) == 2:
            _tag(parts[0], f"C2 beacon ({b['avg']}s interval)", 3)
            _tag(parts[1].split(":")[0], f"C2 server (beacon dst)", 3)

    # C2 Framework detection
    for fw, info_ in d.get("c2_frameworks", {}).items():
        for ev in info_.get("evidence", []):
            parts = ev.split("->")
            if len(parts) >= 2:
                src_ip = parts[0].strip().split(":")[0].split(" ")[-1]
                dst_ip = parts[1].strip().split(":")[0].split(" ")[0]
                _tag(src_ip, f"{fw} C2 client", 3)
                _tag(dst_ip, f"{fw} C2 server", 4)

    # Brute force (high severity)
    for b in d.get("brute_force", []):
        target = b["target"]
        parts = target.split("->")
        if parts:
            src = parts[0].strip()
            _tag(src, f"Brute force ({b['attempts']} attempts)", 3)

    # Reverse shell ports (medium severity)
    for s in d.get("suspicious_traffic", []):
        if s.get("reason") == "RevShell port":
            _tag(s.get("src"), f"RevShell port connection", 2)
            _tag(s.get("dst"), f"RevShell port listener", 2)
        elif s.get("reason") in ("Malware download", "Binary xfer"):
            _tag(s.get("src"), f"{s['reason']} (requester)", 2)
            _tag(s.get("dst"), f"{s['reason']} (server)", 2)
        elif "webshell" in s.get("reason", "").lower():
            _tag(s.get("src"), "Webshell client", 2)
            _tag(s.get("dst"), "Webshell host", 3)

    # ARP spoofing (medium severity)
    for ip, macs in d.get("arp_spoofing", {}).items():
        _tag(ip, f"ARP spoof ({len(macs)} MACs)", 2)

    # DCSync attack (critical severity)
    for dc in d.get("dcsync_detected", []):
        _tag(dc.get("src"), "DCSync (DsGetNCChanges)", 5)

    # Kerberoasting (high severity)
    for k in d.get("kerberoasting_suspects", []):
        _tag(k.get("src"), f"Kerberoasting RC4 TGS-REQ", 3)

    # AS-REP Roasting (high severity)
    for a in d.get("asrep_roast_suspects", []):
        _tag(a.get("dst"), f"AS-REP Roasting target", 3)

    # LLMNR poisoning (high severity)
    for name, ips in d.get("llmnr_poisoning", {}).items():
        for ip in ips:
            _tag(ip, f"LLMNR poisoning '{name}'", 3)

    # NBNS poisoning (high severity)
    for name, ips in d.get("nbns_poisoning", {}).items():
        for ip in ips:
            _tag(ip, f"NBNS poisoning '{name}'", 3)

    # DNS exfiltration — tag the querying IPs if available
    if d.get("dns_exfil_suspects"):
        # We don't have per-query source IPs cached, so tag via suspicious domains
        for dom in d.get("dns_exfil_suspects", []):
            parts = dom.split(".")
            if len(parts) >= 2:
                # Domain-level indicator, not IP — tracked separately below
                pass

    # Credential exposure sources (low severity, needs corroboration)
    for c in d.get("credentials", []):
        p_ = c.split("|")
        if len(p_) >= 5:
            src = p_[4].strip()
            if src:
                _tag(src, "Credential exposure", 1)

    # Havoc C2 endpoints (high severity)
    for hs in d.get("havoc_streams", []):
        sev = min(hs["score"] // 10, 5)
        for flow in hs.get("flows", []):
            parts = flow.split("->")
            if len(parts) == 2:
                src_ip = parts[0].split(":")[0]
                dst_ip = parts[1].split(":")[0]
                _tag(src_ip, f"Havoc agent (score={hs['score']})", sev)
                _tag(dst_ip, f"Havoc C2 server (score={hs['score']})", sev)

    # EternalBlue sources (critical severity)
    for src in d.get("eternalblue_sources", []):
        _tag(src, "EternalBlue / MS17-010 attacker", 5)

    # Reverse shells (critical severity)
    for rs in d.get("reverse_shells", []):
        preview = rs.get("preview", "")
        # Extract IPs from stream preview (Follow TCP format: "Node 0: x.x.x.x:port")
        for line in preview.splitlines()[:5]:
            ip_match = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            for ip in ip_match:
                _tag(ip, f"Reverse shell ({rs['type']})", 4)

    # Crypto mining (medium severity)
    mining = d.get("crypto_mining", {})
    for miner_ip in mining.get("miners", []):
        _tag(miner_ip, "Crypto miner", 2)
    for pool_addr in mining.get("pools", []):
        pool_ip = pool_addr.split(":")[0]
        if pool_ip.count(".") == 3:
            _tag(pool_ip, "Mining pool server", 2)

    # Tor traffic (low-medium severity)
    tor = d.get("tor_traffic", {})
    for ip in tor.get("ips", []):
        _tag(ip, "Tor relay/client", 1)

    # Default credentials users (medium severity)
    for dc in d.get("default_creds_found", []):
        _tag(dc.get("src"), f"Default creds ({dc['user']}:{dc['pass']})", 2)
        _tag(dc.get("dst"), f"Default creds target", 1)

    # PowerShell detected — tag IPs from suspicious traffic that correspond
    if d.get("powershell_detected"):
        for s in d.get("suspicious_traffic", []):
            if s.get("reason") in ("Malware download", "Binary xfer"):
                _tag(s.get("src"), "PowerShell payload delivery", 3)

    # Malicious JA3 — tag source IPs
    for j in d.get("ja3_malicious", []):
        _tag(j.get("src"), f"Malicious JA3 ({j['match']})", 3)

    # Filter: only show endpoints with severity >= 2
    malicious = {ip: info_ for ip, info_ in ep_scores.items() if info_["severity"] >= 2}

    # DNS exfil domains (separate from IP-based scoring)
    exfil_domains = set()
    for dom in d.get("dns_exfil_suspects", []):
        parts = dom.split(".")
        if len(parts) >= 2:
            exfil_domains.add(".".join(parts[-2:]))

    if (malicious or exfil_domains) and _sr("malicious_endpoints"):
        nl()
        o(f"{BOLD()}{BMAG()}{'='*W}{RST()}")
        o(f"{BOLD()}{BMAG()}  MALICIOUS ENDPOINTS{RST()}")
        o(f"{BOLD()}{BMAG()}{'='*W}{RST()}")

        if malicious:
            ranked = sorted(malicious.items(), key=lambda x: -x[1]["severity"])
            rows = []
            for ip, info_ in ranked:
                sev = info_["severity"]
                if sev >= 6:
                    sev_label = f"{BG_RED()}{BOLD()} CRITICAL {RST()}"
                elif sev >= 3:
                    sev_label = f"{BRED()}HIGH{RST()}"
                else:
                    sev_label = f"{BYEL()}MEDIUM{RST()}"
                reasons = ", ".join(sorted(info_["reasons"]))
                rows.append((ip, sev_label, reasons[:60]))
            table(rows, ["Endpoint", "Threat", "Evidence"])

        if exfil_domains:
            h3("Exfiltration Domains")
            for dom in sorted(exfil_domains):
                alert(dom)

    if not focus_sections:
        nl()
        h2("KALI SETUP")
        o(f"    {DIM()}# -- Install (run once) --{RST()}")
        dim("sudo apt update && sudo apt install -y tshark wireshark-common")
        dim("cd ~/Desktop")
        dim("git clone https://github.com/YOUR_USER/pcap-analyzer.git  # or copy the folder")
        dim("cd pcap-analyzer")
        dim("chmod +x pcapsum pcap-analyzer.sh")
        dim("sed -i 's/\\r$//' pcapsum pcap-analyzer.sh pcap-analyzer.py")
        dim("sudo ln -sf $(pwd)/pcapsum /usr/local/bin/pcapsum")
        nl()
        o(f"    {DIM()}# -- Verify install --{RST()}")
        dim("which tshark && tshark --version | head -1")
        dim("pcapsum --version")
        nl()

        h2("KALI COMMANDS")
        bname = Path(fname).name
        o(f"    {DIM()}# -- Analysis --{RST()}")
        dim(f"pcapsum {bname}")
        dim(f"pcapsum -q {bname}                   # quick mode")
        dim(f"pcapsum -f {bname}                   # flag hunt only")
        dim(f"pcapsum -j {bname} > out.json        # JSON output")
        nl()
        o(f"    {DIM()}# -- Stream follow --{RST()}")
        dim(f"pcapsum -s 0 {bname}                 # TCP stream 0")
        dim(f"pcapsum -s u:0 {bname}               # UDP stream 0")
        tc = d.get("tcp_stream_count", 0)
        if tc:
            dim(f"# {tc} TCP streams available (0-{tc-1})")
        nl()
        o(f"    {DIM()}# -- Export objects --{RST()}")
        dim(f"pcapsum -e http {bname}")
        dim(f"tshark -r {bname} --export-objects http,./exported/")
        if d.get("smb2_files") or d.get("smb_files"):
            dim(f"tshark -r {bname} --export-objects smb,./exported_smb/")
        nl()
        o(f"    {DIM()}# -- tshark one-liners --{RST()}")
        dim(f"tshark -r {bname} -q -z credentials")
        dim(f"tshark -r {bname} -q -z conv,ip")
        dim(f"tshark -r {bname} -q -z io,phs")
        dim(f"tshark -r {bname} -q -z follow,tcp,ascii,0")
        if d.get("tls_sni_certs"):
            dim(f"tshark -r {bname} -o tls.keylog_file:sslkey.log -Y http")
        if d.get("kerberos_traffic"):
            dim(f"tshark -r {bname} -Y kerberos -T fields -e kerberos.CNameString -e kerberos.SNameString -e kerberos.msg_type")
        if d.get("rdp_connections"):
            dim(f"tshark -r {bname} -Y 'tcp.port==3389' -q -z follow,tcp,ascii,0")
        if d.get("dns_queries"):
            dim(f"tshark -r {bname} -Y dns -T fields -e dns.qry.name -e dns.a | sort -u")
        if d.get("http_traffic"):
            dim(f"tshark -r {bname} -Y http.request -T fields -e http.host -e http.request.uri | sort -u")
        nl()
        o(f"    {DIM()}# -- Attack tools --{RST()}")
        if d.get("wifi_eapol_count"):
            dim(f"aircrack-ng -w /usr/share/wordlists/rockyou.txt {bname}")
        if d.get("drsuapi_traffic"):
            dim(f"secretsdump.py -just-dc DOMAIN/user@DC_IP  # extract hashes after DCSync")
        if d.get("credentials") or d.get("ntlm_hashes"):
            dim(f"hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt  # NTLMv2")
        if d.get("kerberoasting_suspects"):
            dim(f"hashcat -m 13100 kirbi.txt /usr/share/wordlists/rockyou.txt  # Kerberoast")
        if d.get("asrep_roast_suspects"):
            dim(f"hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt  # AS-REP")
        if d.get("havoc_streams"):
            dim(f"pcapsum --key <64-hex-chars> {bname}  # decrypt Havoc C2")
        if d.get("c2_frameworks"):
            for fw in d["c2_frameworks"]:
                dim(f"# {fw} C2 indicators detected - investigate further")
        if d.get("embedded_files"):
            dim(f"# Embedded files detected - extract with: tshark -r {bname} --export-objects http,./carved/")
            dim(f"# Or use: foremost -i {bname} -o ./carved/")
        if not any(d.get(k) for k in ("wifi_eapol_count","drsuapi_traffic","credentials","ntlm_hashes","kerberoasting_suspects","asrep_roast_suspects","havoc_streams","c2_frameworks","embedded_files")):
            dim(f"# No attack-specific tools suggested for this capture")
        nl()

# ═══════════════════════════════════════════════════════════════════════════════
# Subcommands
# ═══════════════════════════════════════════════════════════════════════════════

def cmd_follow_stream(pcap, stream_id, proto="tcp"):
    banner(f"Follow {proto.upper()} Stream {stream_id}")
    content = tshark_follow(str(pcap), proto, stream_id, 50000)
    if not content:
        err(f"Stream {stream_id} empty")
        return
    o(content)
    nl()
    flag_hunt(content)

def cmd_flag_hunt(pcap):
    f = str(pcap)
    banner("Flag Hunt Mode")
    all_flags = []
    info("Searching raw packet data...")
    raw = _t([TSHARK, "-r", f, "-T", "fields", "-e", "data.data", "-Y", "data.data"], timeout=60)
    if raw:
        hex_data = "".join(l.strip().replace(":","") for l in raw.splitlines() if l.strip())
        try:
            raw_bytes = bytes.fromhex(hex_data[:500000])
            text = raw_bytes.decode("utf-8", errors="ignore")
            for pat in FLAG_PATTERNS:
                all_flags.extend(m.group(0) for m in pat.finditer(text))
            # Try XOR/ROT13/base64 decoding on raw data
            decode_results = _try_decode_data(hex_data[:100000])
            for method, decoded in decode_results.items():
                if method == "raw":
                    continue
                for pat in FLAG_PATTERNS:
                    for m in pat.finditer(decoded):
                        all_flags.append(f"[{method}] {m.group(0)}")
        except Exception: pass
    info("Searching HTTP bodies...")
    body = _t([TSHARK, "-r", f, "-Y", "http.file_data", "-T", "fields", "-e", "http.file_data"], timeout=30)
    if body:
        decoded_body = hex_decode(body)
        for pat in FLAG_PATTERNS:
            all_flags.extend(m.group(0) for m in pat.finditer(decoded_body))
    info("Searching TCP streams...")
    stream_out = _t([TSHARK, "-r", f, "-T", "fields", "-e", "tcp.stream", "-Y", "tcp.stream"])
    if stream_out:
        ids = sorted(set(int(s.strip()) for s in stream_out.splitlines() if s.strip().isdigit()))
        for sid in ids[:80]:
            content = tshark_follow(f, "tcp", sid, 5000)
            if content:
                for pat in FLAG_PATTERNS:
                    all_flags.extend(m.group(0) for m in pat.finditer(content))
    info("Searching DNS + ICMP...")
    for filt, field in [("dns","dns.qry.name"),("dns","dns.txt"),("icmp.type == 8","data.data")]:
        out = _t([TSHARK, "-r", f, "-Y", filt, "-T", "fields", "-e", field])
        if out:
            for pat in FLAG_PATTERNS:
                all_flags.extend(m.group(0) for m in pat.finditer(out))
    info("Searching USB HID data...")
    usb_out = tshark_fields(f, "usb.capdata || usbhid.data", ["usb.capdata", "usbhid.data"])
    if usb_out:
        events = [l.strip() for l in usb_out if l.strip().replace("|","")]
        decoded_keys = decode_usb_hid(events)
        if decoded_keys:
            info(f"USB HID decoded: {decoded_keys}")
            for pat in FLAG_PATTERNS:
                all_flags.extend(m.group(0) for m in pat.finditer(decoded_keys))
    nl()
    unique = sorted(set(all_flags))
    if unique:
        h2(f"FLAGS FOUND ({len(unique)})")
        for fl in unique:
            found(f"🚩 {fl}")
    else:
        warn("No flags found. Try manual stream analysis.")
    nl()

def cmd_export(pcap, proto):
    f = str(pcap)
    out_dir = Path(f).parent / f"exported_{Path(f).stem}"
    out_dir.mkdir(exist_ok=True)
    banner(f"Export {proto.upper()} Objects")
    info(f"Output: {out_dir}")
    _t([TSHARK, "-r", f, "--export-objects", f"{proto},{out_dir}"], timeout=120)
    files = list(out_dir.iterdir())
    if files:
        found(f"Exported {len(files)} files:")
        for ff in sorted(files)[:50]:
            o(f"    {GRN()}{ff.name}{RST()}  ({human_size(ff.stat().st_size)})")
        nl()
        for ff in files:
            try:
                text = open(ff,"rb").read(100000).decode("utf-8",errors="ignore")
                for pat in FLAG_PATTERNS:
                    for m in pat.finditer(text):
                        fl = m.group(0)
                        if _is_plausible_flag(fl):
                            found(f"🚩 {fl}  (in {ff.name})")
            except Exception: pass
    else: warn(f"No {proto} objects found.")
    nl()

# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

# PCAP magic bytes for file validation
_PCAP_MAGICS = (
    b'\xd4\xc3\xb2\xa1',  # pcap LE
    b'\xa1\xb2\xc3\xd4',  # pcap BE
    b'\x0a\x0d\x0d\x0a',  # pcapng
    b'\x4d\x3c\xb2\xa1',  # pcap nanosecond LE
    b'\xa1\xb2\x3c\x4d',  # pcap nanosecond BE
)


def _validate_pcap(path):
    """Check file is readable and has valid pcap/pcapng magic bytes."""
    try:
        with open(path, 'rb') as fh:
            magic = fh.read(4)
    except PermissionError:
        err(f"Permission denied: {path}")
        err("Try: sudo python3 pcapsum ...")
        sys.exit(1)
    except OSError as exc:
        err(f"Cannot read file: {exc}")
        sys.exit(1)
    if magic not in _PCAP_MAGICS:
        err(f"Not a valid pcap/pcapng file (magic: {magic.hex()})")
        sys.exit(1)


def main():
    global NO_COLOR, TIMEOUT, VERBOSE
    p = argparse.ArgumentParser(
        prog="pcapsum",
        description=f"pcapsum v{__version__} — Deep PCAP analysis for CTF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  pcapsum capture.pcap                  full analysis
  pcapsum -q capture.pcap               quick mode
  pcapsum -f capture.pcap               flag hunt only
  pcapsum -s 0 capture.pcap             follow TCP stream 0
  pcapsum -s u:3 capture.pcap           follow UDP stream 3
  pcapsum -e http capture.pcap          export HTTP objects
  pcapsum -e tftp capture.pcap          export TFTP objects
  pcapsum -n 20 capture.pcap            follow 20 streams
  pcapsum -j capture.pcap > out.json    JSON output
  pcapsum -a capture.pcap               auto-detect task & focus output
  pcapsum -C capture.pcap | less        no color
  pcapsum -t 300 capture.pcap           300s timeout
""")
    p.add_argument("pcap", help="pcap/pcapng file")
    p.add_argument("-q", "--quick", action="store_true", help="quick mode (skip deep analysis)")
    p.add_argument("-f", "--flags", action="store_true", help="flag hunt: search all layers")
    p.add_argument("-s", "--stream", metavar="ID", help="follow stream (0, u:3 for UDP)")
    p.add_argument("-e", "--export", metavar="PROTO", help="export objects (http/smb/tftp/imf)")
    p.add_argument("-j", "--json", action="store_true", help="JSON output")
    p.add_argument("-n", "--streams", type=int, default=10, help="max streams to follow (default: 10)")
    p.add_argument("-t", "--timeout", type=int, default=120, help="timeout per command (default: 120s)")
    p.add_argument("-C", "--no-color", action="store_true", help="disable colors")
    p.add_argument("-v", "--verbose", action="store_true", help="show debug info")
    p.add_argument("-V", "--version", action="version", version=f"pcapsum {__version__}")
    p.add_argument("-a", "--auto", action="store_true",
                   help="auto-detect task type and show only relevant output")
    # Havoc C2 options
    p.add_argument("--key", metavar="HEX",
                   help="AES-256 key for Havoc C2 decryption (64 hex chars)")
    p.add_argument("--iv", metavar="HEX",
                   help="AES IV for Havoc decryption (32 hex chars; auto-detect if omitted)")
    p.add_argument("--magic", metavar="HEX", default="DEADBEEF",
                   help="Havoc magic bytes to detect (default: DEADBEEF)")
    args = p.parse_args()

    if args.no_color or not sys.stdout.isatty():
        NO_COLOR = True
    TIMEOUT = args.timeout
    VERBOSE = args.verbose

    # Parse Havoc parameters
    havoc_magic = b'\xde\xad\xbe\xef'
    havoc_key = None
    havoc_iv = None
    if args.magic:
        try:
            havoc_magic = bytes.fromhex(args.magic)
        except ValueError:
            err(f"Invalid --magic hex: {args.magic}")
            sys.exit(1)
    if args.key:
        try:
            havoc_key = bytes.fromhex(args.key)
        except ValueError:
            err(f"Invalid --key hex: {args.key}")
            sys.exit(1)
        if len(havoc_key) != 32:
            err("--key must be 64 hex chars (AES-256 = 32 bytes)")
            sys.exit(1)
        if not _HAS_CRYPTO:
            err("AES decryption requires pycryptodome or cryptography")
            err("Install: pip install pycryptodome")
            sys.exit(1)
    if args.iv:
        try:
            havoc_iv = bytes.fromhex(args.iv)
        except ValueError:
            err(f"Invalid --iv hex: {args.iv}")
            sys.exit(1)
        if len(havoc_iv) != 16:
            err("--iv must be 32 hex chars (16 bytes)")
            sys.exit(1)

    pcap = Path(args.pcap)
    if not pcap.is_file():
        err(f"File not found: {pcap}")
        sys.exit(1)
    _validate_pcap(pcap)
    find_tshark()

    if args.stream is not None:
        sid, proto = args.stream, "tcp"
        if sid.startswith("u:"):
            proto = "udp"
            sid = sid[2:]
        elif sid.startswith("t:"):
            sid = sid[2:]
        try:
            cmd_follow_stream(pcap, int(sid), proto)
        except ValueError:
            err(f"Invalid stream ID: {args.stream}")
        sys.exit(0)
    if args.flags:
        cmd_flag_hunt(pcap)
        sys.exit(0)
    if args.export:
        cmd_export(pcap, args.export)
        sys.exit(0)

    if not args.json:
        nl()
        banner(f"pcapsum v{__version__}")
        kv("File", str(pcap.resolve()))
        kv("Size", human_size(pcap.stat().st_size))
        kv("tshark", TSHARK)
        mode = "QUICK" if args.quick else f"FULL (streams:{args.streams} timeout:{args.timeout}s)"
        kv("Mode", mode)
        nl()

    data = analyze(pcap, quick=args.quick, max_streams=args.streams,
                   havoc_magic=havoc_magic, havoc_key=havoc_key, havoc_iv=havoc_iv)
    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        render(data, focus_mode=args.auto)

if __name__ == "__main__":
    main()
