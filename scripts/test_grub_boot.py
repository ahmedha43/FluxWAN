#!/usr/bin/env python3
import subprocess, time, sys, os, signal

DISK = "/tmp/fluxwan_grub_test.img"
ISO  = "dist/fluxwan-os-x86_64.iso"

def stream(proc, timeout=240, triggers=None):
    os.set_blocking(proc.stdout.fileno(), False)
    buf = ""
    t0  = time.time()
    while time.time() - t0 < timeout:
        try:
            chunk = os.read(proc.stdout.fileno(), 8192).decode("utf-8", errors="ignore")
        except BlockingIOError:
            chunk = ""
        if chunk:
            sys.stdout.write(chunk)
            sys.stdout.flush()
            buf += chunk
            if triggers:
                for item in list(triggers):
                    pattern, action, fired = item
                    if not fired[0] and pattern.lower() in buf.lower():
                        fired[0] = True
                        action(proc)
        time.sleep(0.05)
    return buf

if os.path.exists(DISK):
    os.remove(DISK)
with open(DISK, "wb") as f:
    f.truncate(3 * 1024 * 1024 * 1024)

print("="*68)
print("  PHASE 1: Boot ISO -> Install FluxWAN to /dev/sda")
print("="*68)

def send(proc, text, delay=1.5):
    time.sleep(delay)
    proc.stdin.write(text.encode())
    proc.stdin.flush()

p1 = subprocess.Popen(
    ["qemu-system-x86_64","-nographic","-no-reboot","-m","512","-smp","1",
     "-serial","mon:stdio","-cdrom",ISO,"-boot","d",
     "-drive",f"file={DISK},format=raw,if=ide"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT, bufsize=0)

triggers1 = [
    ("enter option [1-8]",               lambda p: send(p,"1\n"),               [False]),
    ("enter target disk name",           lambda p: send(p,"sda\n"),             [False]),
    ("are you sure you want to install", lambda p: send(p,"yes\n"),             [False]),
    ("success: fluxwan embedded",        lambda p: (time.sleep(3), p.terminate()), [False]),
]
stream(p1, timeout=240, triggers=triggers1)
try: p1.terminate(); p1.wait(timeout=5)
except: p1.kill()

time.sleep(2)
print("\n"+"="*68)
print("  PHASE 2: Boot directly from Hard Disk (no ISO)")
print("="*68)

p2 = subprocess.Popen(
    ["qemu-system-x86_64","-nographic","-no-reboot","-m","512","-smp","1",
     "-serial","mon:stdio","-boot","c",
     "-drive",f"file={DISK},format=raw,if=ide"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT, bufsize=0)

output2 = stream(p2, timeout=90)
try: p2.terminate(); p2.wait(timeout=5)
except: p2.kill()

PASS_SIGNALS = ["grub", "linux version", "booting", "fluxwan", "login:"]
booted = any(s in output2.lower() for s in PASS_SIGNALS)
fail   = "not a bootable disk" in output2.lower() or "missing operating system" in output2.lower()

print("\n"+"="*68)
if booted and not fail:
    print("  [PASS] HARD DISK BOOT SUCCESSFUL!")
elif fail:
    print("  [FAIL] BOOT FAILED - disk not bootable")
else:
    print("  [WARN] UNCERTAIN - check output above")
print("="*68)
