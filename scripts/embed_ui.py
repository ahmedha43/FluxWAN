#!/usr/bin/env python3
import gzip
import os
import sys

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(script_dir, ".."))
    html_path = os.path.join(project_root, "web", "index.html")
    out_h_path = os.path.join(project_root, "include", "ui_assets.h")

    if not os.path.exists(html_path):
        print(f"Error: {html_path} does not exist.")
        sys.exit(1)

    with open(html_path, "rb") as f_in:
        raw_bytes = f_in.read()

    gzipped_bytes = gzip.compress(raw_bytes)

    with open(out_h_path, "w") as f_out:
        f_out.write("/* Auto-generated file by scripts/embed_ui.py - Do not edit manually */\n")
        f_out.write("#ifndef UI_ASSETS_H\n")
        f_out.write("#define UI_ASSETS_H\n\n")
        f_out.write(f"static const unsigned int UI_INDEX_HTML_LEN = {len(raw_bytes)};\n")
        f_out.write(f"static const unsigned int UI_INDEX_HTML_GZ_LEN = {len(gzipped_bytes)};\n\n")
        f_out.write("static const unsigned char UI_INDEX_HTML_GZ[] = {\n    ")
        
        for i, b in enumerate(gzipped_bytes):
            f_out.write(f"0x{b:02x}, ")
            if (i + 1) % 16 == 0:
                f_out.write("\n    ")
        
        f_out.write("\n};\n\n")
        f_out.write("#endif /* UI_ASSETS_H */\n")

    print(f"Successfully generated {out_h_path} (Original: {len(raw_bytes)} B, Gzip: {len(gzipped_bytes)} B)")

if __name__ == "__main__":
    main()
