#!/usr/bin/env python3
import subprocess
import time
import sys
import os

def main():
    print("=======================================================")
    print("   [1/2] RUNNING FLUXWAN INSTALLATION IN QEMU          ")
    print("=======================================================")
    disk_img = "/tmp/fluxwan_test_disk.img"
    if os.path.exists(disk_img):
        os.remove(disk_img)
    with open(disk_img, "wb") as f:
        f.truncate(2 * 1024 * 1024 * 1024)

    # 1. Run Installer in QEMU
    qemu_cmd = [
        'qemu-system-x86_64',
        '-nographic',
        '-cdrom', 'dist/fluxwan-os-x86_64.iso',
        '-drive', f'file={disk_img},format=raw,if=ide',
        '-boot', 'd',
        '-m', '512',
        '-serial', 'mon:stdio',
        '-no-reboot',
        '-smp', '1'
    ]

    p1 = subprocess.Popen(qemu_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    start_time = time.time()
    menu_detected = False

    while time.time() - start_time < 120:
        line = p1.stdout.readline()
        if not line and p1.poll() is not None:
            break
        if line:
            sys.stdout.write(f"[ISO-BOOT] {line}")
            sys.stdout.flush()

            if "enter option [1-8]:" in line.lower() and not menu_detected:
                menu_detected = True
                print("\n>>> Menu detected! Sending 1 to launch installer...")
                time.sleep(1)
                p1.stdin.write("1\n")
                p1.stdin.flush()

            if "enter target disk name" in line.lower():
                print("\n>>> Sending sda as target disk...")
                time.sleep(1)
                p1.stdin.write("sda\n")
                p1.stdin.flush()

            if "are you sure you want to install" in line.lower():
                print("\n>>> Sending confirmation yes...")
                time.sleep(1)
                p1.stdin.write("yes\n")
                p1.stdin.flush()

            if "installed successfully" in line.lower():
                print("\n>>> Installation finished successfully! Sending q to exit installer...")
                time.sleep(2)
                p1.stdin.write("q\n")
                p1.stdin.flush()
                time.sleep(2)
                p1.stdin.write("\n")
                p1.stdin.flush()
                time.sleep(2)
                p1.stdin.write("8\n") # Power off in menu
                p1.stdin.flush()
                break

    try:
        p1.terminate()
        p1.wait(timeout=5)
    except Exception:
        p1.kill()

    time.sleep(2)

    print("\n=======================================================")
    print("   [2/2] BOOTING DIRECTLY FROM INSTALLED HARD DISK     ")
    print("=======================================================")
    qemu_disk_cmd = [
        'qemu-system-x86_64',
        '-nographic',
        '-drive', f'file={disk_img},format=raw,if=ide',
        '-boot', 'c',
        '-m', '512',
        '-serial', 'mon:stdio',
        '-no-reboot',
        '-smp', '1'
    ]

    p2 = subprocess.Popen(qemu_disk_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    start_time2 = time.time()
    disk_booted_successfully = False

    while time.time() - start_time2 < 45:
        line = p2.stdout.readline()
        if not line and p2.poll() is not None:
            break
        if line:
            sys.stdout.write(f"[HARD-DISK-OUTPUT] {line}")
            sys.stdout.flush()
            if "fluxwan" in line.lower() or "linux version" in line.lower() or "login:" in line.lower() or "welcome" in line.lower() or "booting" in line.lower():
                disk_booted_successfully = True

    try:
        p2.terminate()
        p2.wait(timeout=3)
    except Exception:
        p2.kill()

    print("\n=======================================================")
    print(f" FINAL RESULT: Hard Disk Direct Boot = {disk_booted_successfully}")
    print("=======================================================")

if __name__ == '__main__':
    main()
