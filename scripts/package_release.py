#!/usr/bin/env python3
import os
import sys
import json
import hashlib

def sha256_file(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    bin_path = os.path.join(repo_root, "fluxwan")
    manifest_path = os.path.join(repo_root, "version.json")
    
    if not os.path.exists(manifest_path):
        print(f"[ERROR] Manifest not found: {manifest_path}")
        sys.exit(1)
        
    with open(manifest_path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
        
    if os.path.exists(bin_path):
        file_sha = sha256_file(bin_path)
        file_size = os.path.getsize(bin_path)
        data.setdefault("packages", {}).setdefault("core", {})["sha256"] = file_sha
        data["packages"]["core"]["size_bytes"] = file_size
        print(f"[✓] Core binary SHA-256: {file_sha} ({file_size} bytes)")
        
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
        
    print(f"[✓] Updated {manifest_path} successfully.")

if __name__ == "__main__":
    main()
