#!/usr/bin/env python3
"""
===========================================================================
 FluxWAN Master Cryptographic License Generator (Vendor Tool)
 
 Exclusively for: Ahmed Al-Dulaimi (أحمد الدليمي)
 
 Generates military-grade cryptographically signed licenses using Ed25519.
 Licenses cannot be forged, cloned, or cracked without the Private Key.
===========================================================================
"""

import sys
import os
import struct
import time
import base64
import hashlib
import argparse

# ── Master Ed25519 Cryptographic Core ─────────────────────────────────────

q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493

def expmod(b, e, m):
    if e == 0: return 1
    t = expmod(b, e // 2, m) ** 2 % m
    if e & 1: t = (t * b) % m
    return t

def inv(x):
    return expmod(x, q - 2, q)

d = -121665 * inv(121666) % q
I = expmod(2, (q - 1) // 4, q)

def xrecover(y):
    xx = (y * y - 1) * inv(d * y * y + 1) % q
    x = expmod(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0: x = (x * I) % q
    if x % 2 != 0: x = q - x
    return x

By = 4 * inv(5) % q
Bx = xrecover(By)
B = (Bx, By)

def edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1*y2 + x2*y1) * inv(1 + d*x1*x2*y1*y2) % q
    y3 = (y1*y2 + x1*x2) * inv(1 - d*x1*x2*y1*y2) % q
    return (x3, y3)

def scalarmult(P, e):
    if e == 0: return (0, 1)
    Q = scalarmult(P, e // 2)
    Q = edwards(Q, Q)
    if e & 1: Q = edwards(Q, P)
    return Q

def encodeint(y):
    bits = [(y >> i) & 1 for i in range(256)]
    return bytes([sum([bits[i * 8 + j] << j for j in range(8)]) for i in range(32)])

def encodepoint(P):
    x, y = P
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes([sum([bits[i * 8 + j] << j for j in range(8)]) for i in range(32)])

def H(m):
    return hashlib.sha512(m).digest()

def Hint(m):
    h = H(m)
    return sum(2**i * ((h[i//8] >> (i%8)) & 1) for i in range(512))

def sign_ed25519(m, sk, pk):
    h = H(sk[:32])
    a = 2**254 + sum(2**i * ((h[i//8] >> (i%8)) & 1) for i in range(3, 254))
    r = Hint(bytes([h[i] for i in range(32, 64)]) + m)
    R = scalarmult(B, r)
    k = Hint(encodepoint(R) + pk + m)
    S = (r + k * a) % l
    return encodepoint(R) + encodeint(S)

# ── Vendor Master Private & Public Keys ──────────────────────────────────
# Generated securely for Ahmed Al-Dulaimi / FluxWAN Master Authority
VENDOR_PRIVKEY = bytes.fromhex('13be3c65758bdd4c661609f16a0acebab41bde21b8b78c330c84f644de8c0f2f7b4359c66eea55dcffa19f94dd900aed9a8c865de3f5d2bcec5ad75bf81a4069')
VENDOR_PUBKEY  = bytes.fromhex('7b4359c66eea55dcffa19f94dd900aed9a8c865de3f5d2bcec5ad75bf81a4069')

# ── License Generation Function ──────────────────────────────────────────

def generate_license(hwid: str, client_name: str, lic_type: str, days: int = 30, max_wans: int = 256):
    hwid = hwid.strip().upper()
    client_name = client_name.strip()
    
    is_lifetime = (lic_type.lower() == 'lifetime')
    type_code = 2 if is_lifetime else 1
    
    now_ts = int(time.time())
    if is_lifetime:
        expires_ts = 0
        days_total = 0
    else:
        expires_ts = now_ts + (days * 86400)
        days_total = days

    hwid_bytes = hwid.encode('ascii')[:31].ljust(32, b'\x00')
    client_bytes = client_name.encode('utf-8')[:63].ljust(64, b'\x00')
    features = 0xFF # All features enabled

    # Binary struct: <4sBBHQQI32s64sB15s (140 bytes)
    payload = struct.pack(
        '<4sBBHQQI32s64sB15s',
        b'FLIC',
        1,              # Version 1
        type_code,      # 1=DAYS, 2=LIFETIME
        max_wans,       # Max WANs
        now_ts,         # Issued at
        expires_ts,     # Expires at
        days_total,     # Days total
        hwid_bytes,
        client_bytes,
        features,
        b'\x00' * 15    # Reserved
    )

    sig = sign_ed25519(payload, VENDOR_PRIVKEY, VENDOR_PUBKEY)
    full_blob = payload + sig
    b64_key = base64.b64encode(full_blob).decode('ascii')
    
    return f"FLUX-LIC-{b64_key}"

def main():
    parser = argparse.ArgumentParser(description="FluxWAN Cryptographic License Key Generator (Ahmed Al-Dulaimi)")
    parser.add_argument("--hwid", required=True, help="Target Hardware ID (e.g. FWID-A1B2-C3D4-E5F6-7890)")
    parser.add_argument("--client", default="Licensed User", help="Client / ISP Network Name")
    parser.add_argument("--type", choices=["days", "lifetime"], default="days", help="License type")
    parser.add_argument("--days", type=int, default=30, help="Duration in days if type is 'days'")
    parser.add_argument("--wans", type=int, default=256, help="Maximum allowed concurrent WAN lines")

    args = parser.parse_args()

    key = generate_license(args.hwid, args.client, args.type, args.days, args.wans)

    print("\n" + "="*70)
    print("      FluxWAN Official Cryptographic License Key (Ed25519)      ")
    print("="*70)
    print(f" Client Name  : {args.client}")
    print(f" Hardware ID  : {args.hwid}")
    print(f" License Type : {args.type.upper()}")
    if args.type == "days":
        print(f" Duration     : {args.days} Days")
    else:
        print(f" Duration     : Permanent / Lifetime")
    print(f" Max WANs     : {args.wans}")
    print("-"*70)
    print(" LICENSE KEY (Send this to the customer):")
    print("\n" + key + "\n")
    print("="*70 + "\n")

if __name__ == '__main__':
    main()
