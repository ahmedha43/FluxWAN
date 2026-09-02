#!/usr/bin/env python3
import subprocess
import os

def test_partition():
    disk = "/tmp/test_partition.img"
    with open(disk, "wb") as f:
        f.truncate(2 * 1024 * 1024 * 1024)

    env = os.environ.copy()
    env["PATH"] = env.get("PATH", "") + ":/sbin:/usr/sbin"

    # Test standard partition table creation
    p = subprocess.Popen(["sfdisk", disk], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    out, err = p.communicate("label: dos\n2048,,83,*\n")
    print("sfdisk out:", out)
    print("sfdisk err:", err)

    p2 = subprocess.Popen(["fdisk", "-l", disk], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    out2, err2 = p2.communicate()
    print("fdisk -l:\n", out2)

    # Write MBR
    with open("/usr/lib/syslinux/mbr/mbr.bin", "rb") as mbr_f:
        mbr_bytes = mbr_f.read(440)
    with open(disk, "r+b") as disk_f:
        disk_f.write(mbr_bytes)

    with open(disk, "rb") as disk_f:
        disk_data = disk_f.read(512)
    print("MBR signature (last 2 bytes):", hex(disk_data[510]), hex(disk_data[511]))
    print("Partition 1 active flag (byte 446):", hex(disk_data[446]))

if __name__ == '__main__':
    test_partition()
