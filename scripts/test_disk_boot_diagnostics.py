#!/usr/bin/env python3
import subprocess
import time
import sys
import os

def main():
    print("======================================================================")
    print("   FluxWAN - Direct Hard Disk Boot Verification in QEMU               ")
    print("======================================================================")
    disk_path = "/tmp/qemu_installed_disk.img"
    if os.path.exists(disk_path):
        os.remove(disk_path)
    with open(disk_path, "wb") as f:
        f.truncate(2 * 1024 * 1024 * 1024)

    print("\n[PHASE 1] Booting ISO and Running Installer to /dev/sda...")
    proc_install = subprocess.Popen([
        'qemu-system-x86_64',
        '-nographic',
        '-cdrom', 'dist/fluxwan-os-x86_64.iso',
        '-drive', f'file={disk_path},format=raw,if=ide',
        '-boot', 'd',
        '-m', '512',
        '-serial', 'mon:stdio',
        '-no-reboot',
        '-smp', '1'
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    start = time.time()
    booted = False
    while time.time() - start < 100:
        line = proc_install.stdout.readline()
        if not line and proc_install.poll() is not None:
            break
        if line:
            sys.stdout.write(f"[INSTALL] {line}")
            sys.stdout.flush()

            if ("sysfs on /sys failed" in line.lower() or "login:" in line.lower() or "enter option" in line.lower()) and not booted:
                booted = True
                print("\n>>> System live! Sending root login and install...")
                time.sleep(2)
                proc_install.stdin.write("\nroot\n")
                proc_install.stdin.flush()
                time.sleep(2)
                proc_install.stdin.write("/usr/local/bin/fluxwan-install\n")
                proc_install.stdin.flush()

            if "enter target disk name" in line.lower():
                time.sleep(1)
                proc_install.stdin.write("sda\n")
                proc_install.stdin.flush()

            if "are you sure" in line.lower():
                time.sleep(1)
                proc_install.stdin.write("yes\n")
                proc_install.stdin.flush()

            if "installed successfully" in line.lower():
                print("\n>>> Install Succeeded! Quitting installer...")
                time.sleep(2)
                proc_install.stdin.write("q\n")
                proc_install.stdin.flush()
                time.sleep(2)
                proc_install.stdin.write("poweroff\n")
                proc_install.stdin.flush()
                break

    try:
        proc_install.terminate()
        proc_install.wait(timeout=5)
    except Exception:
        proc_install.kill()

    print("\n======================================================================")
    print(" [PHASE 2] BOOTING DIRECTLY FROM INSTALLED DISK (NO CD-ROM / NO ISO)  ")
    print("======================================================================")
    proc_boot = subprocess.Popen([
        'qemu-system-x86_64',
        '-nographic',
        '-drive', f'file={disk_path},format=raw,if=ide',
        '-boot', 'c',
        '-m', '512',
        '-serial', 'mon:stdio',
        '-no-reboot',
        '-smp', '1'
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    start_boot = time.time()
    disk_boot_output = []
    while time.time() - start_boot < 60:
        line = proc_boot.stdout.readline()
        if not line and proc_boot.poll() is not None:
            break
        if line:
            disk_boot_output.append(line)
            sys.stdout.write(f"[DISK BOOT OUTPUT] {line}")
            sys.stdout.flush()

    try:
        proc_boot.terminate()
    except Exception:
        pass

    print("\n======================================================================")
    print("   DIRECT DISK BOOT SUMMARY                                           ")
    print("======================================================================")
    print("".join(disk_boot_output))

if __name__ == '__main__':
    main()
