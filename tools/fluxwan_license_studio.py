#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================================================
 FluxWAN License Studio — Desktop GUI Application
 Professional Ed25519 Cryptographic Key Generator & Management Suite
 
 Exclusively for: Ahmed Al-Dulaimi (أحمد الدليمي)
 High-Performance Carrier-Grade Security Architecture
===========================================================================
"""

import os
import sys
import time
import base64
import struct
import hashlib

# ── Ensure Tcl/Tk data directories are found properly under PyInstaller ───
def _setup_tcl_tk():
    base_dir = getattr(sys, '_MEIPASS', None)
    tcl_found = None
    tk_found = None

    if base_dir and os.path.isdir(base_dir):
        for root, dirs, files in os.walk(base_dir):
            if not tcl_found and 'init.tcl' in files:
                tcl_found = root
            if not tk_found and 'tk.tcl' in files:
                tk_found = root
            if tcl_found and tk_found:
                break

    # Fallbacks for system Python paths
    candidates_tcl = [
        tcl_found,
        os.path.join(base_dir, 'lib', 'tcl8.6') if base_dir else None,
        os.path.join(base_dir, '_tcl_data') if base_dir else None,
        r"C:\Users\ahmed\AppData\Local\Programs\Python\Python313\tcl\tcl8.6",
        os.path.join(sys.prefix, 'tcl', 'tcl8.6'),
    ]
    candidates_tk = [
        tk_found,
        os.path.join(base_dir, 'lib', 'tk8.6') if base_dir else None,
        os.path.join(base_dir, '_tk_data') if base_dir else None,
        r"C:\Users\ahmed\AppData\Local\Programs\Python\Python313\tcl\tk8.6",
        os.path.join(sys.prefix, 'tcl', 'tk8.6'),
    ]

    for p in candidates_tcl:
        if p and os.path.isfile(os.path.join(p, 'init.tcl')):
            os.environ['TCL_LIBRARY'] = p.replace('\\', '/')
            break

    for p in candidates_tk:
        if p and os.path.isfile(os.path.join(p, 'tk.tcl')):
            os.environ['TK_LIBRARY'] = p.replace('\\', '/')
            break

_setup_tcl_tk()

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ── Master Ed25519 Cryptographic Engine ───────────────────────────────────

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
    x3 = (x1 * y2 + x2 * y1) * inv(1 + d * x1 * x2 * y1 * y2) % q
    y3 = (y1 * y2 + x1 * x2) * inv(1 - d * x1 * x2 * y1 * y2) % q
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
    return sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(512))

def sign_ed25519(m, sk, pk):
    h = H(sk[:32])
    a = 2**254 + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, 254))
    r = Hint(bytes([h[i] for i in range(32, 64)]) + m)
    R = scalarmult(B, r)
    k = Hint(encodepoint(R) + pk + m)
    S = (r + k * a) % l
    return encodepoint(R) + encodeint(S)

# ── Vendor Master Cryptographic Authority Keypair ────────────────────────
VENDOR_PRIVKEY = bytes.fromhex('13be3c65758bdd4c661609f16a0acebab41bde21b8b78c330c84f644de8c0f2f7b4359c66eea55dcffa19f94dd900aed9a8c865de3f5d2bcec5ad75bf81a4069')
VENDOR_PUBKEY  = bytes.fromhex('7b4359c66eea55dcffa19f94dd900aed9a8c865de3f5d2bcec5ad75bf81a4069')

# ── Core License Generator Function ──────────────────────────────────────

def generate_signed_key(hwid: str, client_name: str, lic_type: str, days: int, max_wans: int):
    hwid = hwid.strip().upper()
    client_name = client_name.strip()
    
    is_lifetime = (lic_type == "LIFETIME")
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
    features = 0xFF # All features: High-Density PPPoE, Maglev, NAT46, PBR, WiFi WAN

    # Binary struct: <4sBBHQQI32s64sB15s (140 bytes)
    payload = struct.pack(
        '<4sBBHQQI32s64sB15s',
        b'FLIC',
        1,              # Version 1
        type_code,      # 1=DAYS, 2=LIFETIME
        max_wans,       # Max WAN interfaces
        now_ts,         # Issued at (Unix timestamp)
        expires_ts,     # Expires at (Unix timestamp)
        days_total,     # Total validity days
        hwid_bytes,
        client_bytes,
        features,
        b'\x00' * 15    # Reserved
    )

    sig = sign_ed25519(payload, VENDOR_PRIVKEY, VENDOR_PUBKEY)
    full_blob = payload + sig
    b64_key = base64.b64encode(full_blob).decode('ascii')
    
    formatted_key = f"FLUX-LIC-{b64_key}"
    return formatted_key, now_ts, expires_ts

# ── Modern Dark Desktop GUI ──────────────────────────────────────────────

class FluxWANLicenseStudioApp:
    def __init__(self, root):
        self.root = root
        self.root.title("FluxWAN License Studio | استوديو توليد تراخيص فلوكس وان")
        self.root.geometry("820x760")
        self.root.minsize(780, 720)
        
        # Color Palette (Dark Theme / Slate & Cyan)
        self.BG_DARK = "#0f172a"
        self.BG_CARD = "#1e293b"
        self.BG_INPUT = "#0b1329"
        self.BORDER_COLOR = "#334155"
        self.TEXT_PRIMARY = "#f8fafc"
        self.TEXT_SECONDARY = "#94a3b8"
        self.ACCENT_CYAN = "#06b6d4"
        self.ACCENT_BLUE = "#3b82f6"
        self.ACCENT_GREEN = "#10b981"
        self.ACCENT_PURPLE = "#8b5cf6"
        self.ACCENT_RED = "#ef4444"
        
        self.root.configure(bg=self.BG_DARK)
        
        # State Variables
        self.client_var = tk.StringVar(value="Al-Basrah Fiber Telecom")
        self.hwid_var = tk.StringVar(value="")
        self.lic_type_var = tk.StringVar(value="DAYS")
        self.days_preset_var = tk.StringVar(value="90")
        self.custom_days_var = tk.StringVar(value="30")
        self.max_wans_var = tk.StringVar(value="256")
        self.generated_key_var = tk.StringVar(value="")
        self.details_summary_var = tk.StringVar(value="أدخل بيانات العميل والبصمة ثم اضغط على زر التوليد.")

        self.setup_ui()

    def setup_ui(self):
        # Main Canvas & Scrollable Wrapper
        main_frame = tk.Frame(self.root, bg=self.BG_DARK, padx=25, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # ── Header Banner ────────────────────────────────────────────────
        header_card = tk.Frame(main_frame, bg=self.BG_CARD, highlightthickness=1, 
                               highlightbackground=self.BORDER_COLOR, padx=18, pady=14)
        header_card.pack(fill=tk.X, pady=(0, 16))

        title_box = tk.Frame(header_card, bg=self.BG_CARD)
        title_box.pack(fill=tk.X)

        title_lbl = tk.Label(
            title_box, 
            text="⚡ FluxWAN Carrier-Grade License Studio",
            font=("Segoe UI", 16, "bold"),
            fg=self.TEXT_PRIMARY,
            bg=self.BG_CARD
        )
        title_lbl.pack(anchor="w")

        sub_lbl = tk.Label(
            title_box,
            text="استوديو توليد وتوقيع التراخيص المشفرة عسكرياً (Ed25519) — حصرياً للأدمن المطور أحمد الدليمي",
            font=("Segoe UI", 9),
            fg=self.TEXT_SECONDARY,
            bg=self.BG_CARD
        )
        sub_lbl.pack(anchor="w", pady=(3, 0))

        # ── Inputs Card ──────────────────────────────────────────────────
        form_card = tk.Frame(main_frame, bg=self.BG_CARD, highlightthickness=1,
                             highlightbackground=self.BORDER_COLOR, padx=20, pady=16)
        form_card.pack(fill=tk.X, pady=(0, 16))

        # 1. Client Name
        lbl_client = tk.Label(
            form_card, text="👤 اسم العميل / شبكة الإنترنت (Client / ISP Name):",
            font=("Segoe UI", 10, "bold"), fg=self.TEXT_PRIMARY, bg=self.BG_CARD
        )
        lbl_client.pack(anchor="w", pady=(0, 4))

        ent_client = tk.Entry(
            form_card, textvariable=self.client_var, font=("Segoe UI", 11),
            bg=self.BG_INPUT, fg=self.TEXT_PRIMARY, insertbackground=self.TEXT_PRIMARY,
            relief=tk.FLAT, highlightthickness=1, highlightbackground=self.BORDER_COLOR,
            highlightcolor=self.ACCENT_CYAN
        )
        ent_client.pack(fill=tk.X, ipady=6, pady=(0, 12))

        # 2. Hardware ID
        lbl_hwid = tk.Label(
            form_card, text="🔒 بصمة العتاد للجهاز (Hardware ID - FWID):",
            font=("Segoe UI", 10, "bold"), fg=self.TEXT_PRIMARY, bg=self.BG_CARD
        )
        lbl_hwid.pack(anchor="w", pady=(0, 4))

        hwid_box = tk.Frame(form_card, bg=self.BG_CARD)
        hwid_box.pack(fill=tk.X, pady=(0, 12))

        ent_hwid = tk.Entry(
            hwid_box, textvariable=self.hwid_var, font=("Consolas", 12, "bold"),
            bg=self.BG_INPUT, fg=self.ACCENT_CYAN, insertbackground=self.TEXT_PRIMARY,
            relief=tk.FLAT, highlightthickness=1, highlightbackground=self.BORDER_COLOR,
            highlightcolor=self.ACCENT_CYAN
        )
        ent_hwid.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=6)

        btn_paste = tk.Button(
            hwid_box, text="📋 لصق من الحافظة", font=("Segoe UI", 9, "bold"),
            bg="#2563eb", fg="#ffffff", activebackground="#1d4ed8", activeforeground="#ffffff",
            relief=tk.FLAT, cursor="hand2", padx=14, command=self.paste_hwid
        )
        btn_paste.pack(side=tk.RIGHT, padx=(10, 0), ipady=5)

        # 3. License Duration Selection
        lbl_type = tk.Label(
            form_card, text="⏱️ نوع ومدة الترخيص (License Duration & Plan):",
            font=("Segoe UI", 10, "bold"), fg=self.TEXT_PRIMARY, bg=self.BG_CARD
        )
        lbl_type.pack(anchor="w", pady=(0, 6))

        presets_frame = tk.Frame(form_card, bg=self.BG_CARD)
        presets_frame.pack(fill=tk.X, pady=(0, 12))

        presets = [
            ("⚡ شهر واحد (30 يوماً)", "30"),
            ("⚡ 3 أشهر (90 يوماً)", "90"),
            ("⚡ 6 أشهر (180 يوماً)", "180"),
            ("⚡ سنة كاملة (365 يوماً)", "365"),
            ("👑 مفتوح مدى الحياة (Lifetime)", "LIFETIME"),
            ("⏳ عدد أيام مخصص", "CUSTOM")
        ]

        for idx, (label, val) in enumerate(presets):
            rb = tk.Radiobutton(
                presets_frame, text=label, value=val, variable=self.days_preset_var,
                font=("Segoe UI", 10), bg=self.BG_CARD, fg=self.TEXT_PRIMARY,
                selectcolor=self.BG_INPUT, activebackground=self.BG_CARD,
                activeforeground=self.ACCENT_CYAN, command=self.on_preset_change
            )
            col = idx % 3
            row = idx // 3
            rb.grid(row=row, column=col, sticky="w", padx=(0, 16), pady=4)

        # Custom Days Frame (hidden by default unless selected)
        self.custom_frame = tk.Frame(form_card, bg=self.BG_CARD)
        lbl_custom = tk.Label(
            self.custom_frame, text="أدخل عدد الأيام المطلوب:",
            font=("Segoe UI", 9), fg=self.TEXT_SECONDARY, bg=self.BG_CARD
        )
        lbl_custom.pack(side=tk.LEFT, padx=(0, 8))
        self.ent_custom = tk.Entry(
            self.custom_frame, textvariable=self.custom_days_var, font=("Segoe UI", 10),
            width=10, bg=self.BG_INPUT, fg=self.TEXT_PRIMARY, relief=tk.FLAT,
            highlightthickness=1, highlightbackground=self.BORDER_COLOR
        )
        self.ent_custom.pack(side=tk.LEFT)

        # 4. Max WANs
        wan_frame = tk.Frame(form_card, bg=self.BG_CARD)
        wan_frame.pack(fill=tk.X, pady=(4, 0))

        lbl_wans = tk.Label(
            wan_frame, text="🌐 أقصى عدد خطوط دمج مسموحة (Max WANs):",
            font=("Segoe UI", 9), fg=self.TEXT_SECONDARY, bg=self.BG_CARD
        )
        lbl_wans.pack(side=tk.LEFT, padx=(0, 10))

        wans_combo = ttk.Combobox(
            wan_frame, textvariable=self.max_wans_var, values=["16", "32", "64", "128", "256"],
            state="readonly", width=12, font=("Segoe UI", 9)
        )
        wans_combo.pack(side=tk.LEFT)

        # ── Big Action Button ────────────────────────────────────────────
        btn_generate = tk.Button(
            main_frame, text="🔑 توليد وتوقيع كود الترخيص المشفر (Generate Ed25519 License)",
            font=("Segoe UI", 12, "bold"), bg="#059669", fg="#ffffff",
            activebackground="#047857", activeforeground="#ffffff", relief=tk.FLAT,
            cursor="hand2", pady=10, command=self.do_generate
        )
        btn_generate.pack(fill=tk.X, pady=(0, 16))

        # ── Output Card ──────────────────────────────────────────────────
        out_card = tk.Frame(main_frame, bg=self.BG_CARD, highlightthickness=1,
                            highlightbackground=self.BORDER_COLOR, padx=20, pady=16)
        out_card.pack(fill=tk.BOTH, expand=True)

        out_header = tk.Frame(out_card, bg=self.BG_CARD)
        out_header.pack(fill=tk.X, pady=(0, 8))

        lbl_out_title = tk.Label(
            out_header, text="📜 كود الترخيص الرقمي الناتج (Send this License to Customer):",
            font=("Segoe UI", 10, "bold"), fg=self.ACCENT_GREEN, bg=self.BG_CARD
        )
        lbl_out_title.pack(side=tk.LEFT)

        self.key_text = tk.Text(
            out_card, height=4, font=("Consolas", 10), bg=self.BG_INPUT,
            fg="#38bdf8", insertbackground="#38bdf8", relief=tk.FLAT,
            highlightthickness=1, highlightbackground=self.BORDER_COLOR,
            wrap=tk.CHAR, padx=10, pady=8
        )
        self.key_text.pack(fill=tk.X, pady=(0, 10))
        self.key_text.insert("1.0", "اضغط على زر التوليد لإنشاء كود ترخيص مشفر...")
        self.key_text.configure(state="disabled")

        # Buttons below key output
        btns_row = tk.Frame(out_card, bg=self.BG_CARD)
        btns_row.pack(fill=tk.X, pady=(0, 10))

        btn_copy = tk.Button(
            btns_row, text="📋 نسخ كود المفتاح كاملاً (1-Click Copy)",
            font=("Segoe UI", 10, "bold"), bg=self.ACCENT_BLUE, fg="#ffffff",
            activebackground="#2563eb", activeforeground="#ffffff", relief=tk.FLAT,
            cursor="hand2", padx=16, pady=6, command=self.copy_key
        )
        btn_copy.pack(side=tk.LEFT, padx=(0, 10))

        btn_save = tk.Button(
            btns_row, text="💾 حفظ في ملف نصي (.txt)",
            font=("Segoe UI", 9), bg="#475569", fg="#ffffff",
            activebackground="#334155", activeforeground="#ffffff", relief=tk.FLAT,
            cursor="hand2", padx=14, pady=6, command=self.save_to_file
        )
        btn_save.pack(side=tk.LEFT)

        # Summary Info Label
        self.lbl_summary = tk.Label(
            out_card, textvariable=self.details_summary_var, font=("Segoe UI", 9),
            fg=self.TEXT_SECONDARY, bg=self.BG_CARD, justify=tk.LEFT, anchor="w"
        )
        self.lbl_summary.pack(fill=tk.X)

    # ── Event Handlers ───────────────────────────────────────────────────

    def paste_hwid(self):
        try:
            clipboard_text = self.root.clipboard_get().strip().upper()
            if clipboard_text:
                self.hwid_var.set(clipboard_text)
        except Exception:
            messagebox.showwarning("تنبيه", "الحافظة فارغة أو لا تحتوي على نص صالح.")

    def on_preset_change(self):
        val = self.days_preset_var.get()
        if val == "CUSTOM":
            self.custom_frame.pack(fill=tk.X, pady=(0, 10))
        else:
            self.custom_frame.pack_forget()

    def do_generate(self):
        client = self.client_var.get().strip()
        hwid = self.hwid_var.get().strip().upper()
        preset = self.days_preset_var.get()

        if not client:
            messagebox.showerror("خطأ في البيانات", "يرجى إدخال اسم العميل أو اسم الشبكة أولاً.")
            return

        if not hwid or not hwid.startswith("FWID-") or len(hwid) < 15:
            messagebox.showerror(
                "بصمة غير صالحة",
                "يرجى إدخال بصمة جهاز صالحة تبدأ بـ FWID- (مثال: FWID-F831-141C-52BE-3089).\n"
                "يمكن للعميل نسخها بنقرة واحدة من تبويب 'الترخيص والحماية' في لوحة تحكم الراوتر."
            )
            return

        lic_type = "LIFETIME" if preset == "LIFETIME" else "DAYS"
        days = 0

        if lic_type == "DAYS":
            if preset == "CUSTOM":
                try:
                    days = int(self.custom_days_var.get().strip())
                    if days <= 0 or days > 3650:
                        raise ValueError()
                except ValueError:
                    messagebox.showerror("عدد أيام غير صالح", "يرجى إدخال عدد أيام صحيح بين 1 و 3650 يوماً.")
                    return
            else:
                days = int(preset)

        try:
            max_wans = int(self.max_wans_var.get())
        except ValueError:
            max_wans = 256

        # Generate cryptographic Ed25519 key
        try:
            key, issued_ts, expires_ts = generate_signed_key(hwid, client, lic_type, days, max_wans)
            self.generated_key_var.set(key)

            # Update text box
            self.key_text.configure(state="normal")
            self.key_text.delete("1.0", tk.END)
            self.key_text.insert("1.0", key)
            self.key_text.configure(state="disabled")

            # Update details summary
            issued_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(issued_ts))
            if lic_type == "LIFETIME":
                summary = f"🟢 تم إنشاء ترخيص دائم (LIFETIME) بنجاح!\nالعميل: {client} | البصمة: {hwid}\nالصلاحية: غير محدودة مدى الحياة | أقصى خطوط WAN: {max_wans} خط | تاريخ الإصدار: {issued_str}"
            else:
                expires_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expires_ts))
                summary = f"🟢 تم إنشاء ترخيص محدد بـ ({days} يوماً) بنجاح!\nالعميل: {client} | البصمة: {hwid}\nتاريخ الانتهاء: {expires_str} | أقصى خطوط WAN: {max_wans} خط | تاريخ الإصدار: {issued_str}"

            self.details_summary_var.set(summary)
            self.lbl_summary.configure(fg=self.ACCENT_GREEN)

        except Exception as e:
            messagebox.showerror("فشل التشفير", f"حدث خطأ أثناء التوقيع التشفيري: {str(e)}")

    def copy_key(self):
        key = self.generated_key_var.get()
        if not key:
            messagebox.showwarning("تنبيه", "يرجى توليد كود الترخيص أولاً قبل النسخ.")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(key)
        messagebox.showinfo("تم النسخ بنجاح ✅", "تم نسخ كود الترخيص بالكامل إلى الحافظة.\nيمكنك إرساله الآن إلى العميل لتفعيله.")

    def save_to_file(self):
        key = self.generated_key_var.get()
        if not key:
            messagebox.showwarning("تنبيه", "يرجى توليد كود الترخيص أولاً.")
            return

        client = self.client_var.get().strip().replace(" ", "_")
        default_filename = f"FluxWAN_License_{client}.txt"

        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            initialfile=default_filename,
            title="حفظ كود الترخيص في ملف"
        )
        if filepath:
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write("======================================================================\n")
                    f.write("      FluxWAN Carrier-Grade Router — Official License Key            \n")
                    f.write("======================================================================\n\n")
                    f.write(self.details_summary_var.get() + "\n\n")
                    f.write("LICENSE KEY:\n")
                    f.write(key + "\n\n")
                    f.write("======================================================================\n")
                messagebox.showinfo("تم الحفظ ✅", f"تم حفظ ملف الترخيص بنجاح في:\n{filepath}")
            except Exception as e:
                messagebox.showerror("خطأ في الحفظ", f"فشل حفظ الملف: {str(e)}")

# ── Entry Point ──────────────────────────────────────────────────────────

def main():
    root = tk.Tk()
    app = FluxWANLicenseStudioApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
