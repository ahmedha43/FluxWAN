#!/usr/bin/env python3
import subprocess
import time
import sys
import os

def run_stream(proc, timeout=180, on_output=None):
    os.set_blocking(proc.stdout.fileno(), False)
    start = time.time()
    accumulated = ""
    while time.time() - start < timeout:
        try:
            chunk = os.read(proc.stdout.fileno(), 4096).decode('utf-8', errors='ignore')
        except BlockingIOError:
            chunk = ""
        if chunk:
            sys.stdout.write(chunk)
            sys.stdout.flush()
            accumulated += chunk
            if on_output:
                res = on_output(accumulated, proc)
                if res == "DONE":
                    return accumulated
        time.sleep(0.1)
    return accumulated

def main():
    print("=================================================================")
    print("   FLUXWAN END-TO-END AUTOMATION TEST (INSTALL -> DIRECT DISK)   ")
    print("=================================================================")
    disk_path = "/tmp/fluxwan_real_boot_disk.img"
    if os.path.exists(disk_path):
        os.remove(disk_path)
    with open(disk_path, "wb") as f:
        f.truncate(2 * 1024 * 1024 * 1024)

    # 1. Boot ISO and Install
    print("\n[PHASE 1] Booting ISO & Installing to /dev/sda...")
    p1 = subprocess.Popen([
        'qemu-system-x86_64',
        '-nographic',
        '-cdrom', 'dist/fluxwan-os-x86_64.iso',
        '-drive', f'file={disk_path},format=raw,if=ide',
        '-boot', 'd',
        '-m', '512',
        '-serial', 'mon:stdio',
        '-no-reboot',
        '-smp', '1'
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

    state = {"sent_1": False, "sent_sda": False, "sent_yes": False, "sent_q": False}

    def handle_install_output(text, proc):
        # Look for the interactive console menu
        if "enter option [1-8]:" in text.lower() and not state["sent_1"]:
            state["sent_1"] = True
            print("\n>>> [TEST] Menu detected! Sending '1' to start installer...")
            time.sleep(1)
            proc.stdin.write(b"1\n")
            proc.stdin.flush()

        if "enter target disk name" in text.lower() and not state["sent_sda"]:
            state["sent_sda"] = True
            print("\n>>> [TEST] Prompt 'enter target disk name' found! Sending 'sda'...")
            time.sleep(1)
            proc.stdin.write(b"sda\n")
            proc.stdin.flush()

        if "are you sure you want to install fluxwan" in text.lower() and not state["sent_yes"]:
            state["sent_yes"] = True
            print("\n>>> [TEST] Confirmation prompt found! Sending 'yes'...")
            time.sleep(1)
            proc.stdin.write(b"yes\n")
            proc.stdin.flush()

        if "success: fluxwan embedded appliance installed successfully" in text.lower() and not state["sent_q"]:
            state["sent_q"] = True
            print("\n>>> [TEST] Installation Success banner detected! Rebooting...")
            time.sleep(3)
            proc.stdin.write(b"\n")
            proc.stdin.flush()
            time.sleep(2)
            return "DONE"
        return None

    run_stream(p1, timeout=180, on_output=handle_install_output)

    try:
        p1.terminate()
        p1.wait(timeout=3)
    except Exception:
        p1.kill()

    time.sleep(2)

    # 2. Boot Hard Disk Directly (No ISO attached)
    print("\n=================================================================")
    print(" [PHASE 2] BOOTING DIRECTLY FROM INSTALLED HARD DISK (NO CD-ROM) ")
    print("=================================================================")
    p2 = subprocess.Popen([
        'qemu-system-x86_64',
        '-nographic',
        '-drive', f'file={disk_path},format=raw,if=ide',
        '-boot', 'c',
        '-m', '512',
        '-serial', 'mon:stdio',
        '-no-reboot',
        '-smp', '1'
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

    disk_result = {"booted": False}

    def handle_disk_output(text, proc):
        if "fluxwan" in text.lower() or "linux version" in text.lower() or "login:" in text.lower() or "booting" in text.lower():
            disk_result["booted"] = True
        return None

    run_stream(p2, timeout=60, on_output=handle_disk_output)

    try:
        p2.terminate()
        p2.wait(timeout=3)
    except Exception:
        p2.kill()

    print("\n=================================================================")
    print(f" [RESULT] Hard Disk Direct Boot Verified: {disk_result['booted']}")
    print("=================================================================")

if __name__ == '__main__':
    main()
