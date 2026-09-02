# دليل حرق وتثبيت صورة الـ ISO لنظام FluxWAN Router OS
(FluxWAN Standalone Bootable ISO Installation Guide)

صورة الـ ISO الخاصة بـ **FluxWAN** مصممة لتكون نظام تشغيل راوتر مستقل وقابل للإقلاع المباشر (**Hybrid BIOS / UEFI**)، يمكن حرقها على فلاشة USB لتثبيتها على الأجهزة الفيزيائية (Bare-Metal x86 Mini PCs / Servers)، أو تركيبها مباشرة كـ ISO Image داخل الأنظمة الافتراضية (Virtual Machines).

---

## 🚀 1. كيفية بناء صورة الـ ISO (How to Build the ISO)

### الطريقة الأولى: عبر لينكس المباشر
```bash
# بأمر واحد بسيط:
make iso
# أو:
sudo bash scripts/build_iso.sh
```

### الطريقة الثانية: عبر Docker (تعمل على أي نظام Windows / Mac / Linux)
```bash
make iso-docker
```
ستجد ملف الـ ISO الناتج داخل المجلد:
📁 `dist/fluxwan-os-x86_64.iso`

---

## 💾 2. حرق الـ ISO على فلاشة USB للأجهزة الحقيقية (Bare-Metal Hardware)

### أ) باستخدام برنامج Rufus (على Windows):
1. افتح برنامج **Rufus**.
2. اختر فلاشة الـ USB الخاصة بك.
3. اضغط **Select** واختر ملف `fluxwan-os-x86_64.iso`.
4. Partition scheme: اختر **MBR** أو **GPT** (الـ ISO يدعم الاثنين معاً).
5. اضغط **START** واختر **Write in ISO Image mode** أو **DD mode**.

### ب) باستخدام برنامج BalenaEtcher (على Windows / Mac / Linux):
1. افتح **BalenaEtcher**.
2. اختر **Flash from file** وحدد `fluxwan-os-x86_64.iso`.
3. حدد فلاشة الـ USB ثم اضغط **Flash!**.

### ج) باستخدام Ventoy:
- فقط انسخ ملف `fluxwan-os-x86_64.iso` والصقه داخل فلاشة الـ **Ventoy**.

---

## 🖥️ 3. الإقلاع والتثبيت على الأنظمة والمحاكيات الافتراضية (VMs)

### أ) Proxmox VE
1. ارفع ملف `fluxwan-os-x86_64.iso` إلى قسم `local (ISO Images)`.
2. أنشئ VM جديدة:
   - OS: اختر الـ ISO المرفوع.
   - System: Q35 أو i440fx (مع BIOS أو UEFI).
   - Disks: أنشئ قرص بحجم 4 GB إلى 8 GB (نوع VirtIO Block أو SCSI).
   - Network: أضف كروت الشبكة المطلوبة (`net0` للـ LAN، `net1`, `net2` للـ WAN).
3. شغل الـ VM وستقلع مباشرة إلى FluxWAN OS.

### ب) Oracle VirtualBox
1. أنشئ VM جديدة بنظام `Linux (64-bit)`.
2. في إعدادات **Storage** -> Optical Drive: اختر ملف `fluxwan-os-x86_64.iso`.
3. شغل الـ VM.

### ج) VMware ESXi / Workstation
1. في إعدادات الـ CD/DVD Drive -> اختر **Datastore ISO File** أو **Use ISO image file** وحدد `fluxwan-os-x86_64.iso`.
2. تأكد من تفعيل خيار **Connect at power on**.

---

## ⚡ 4. خيارات الإقلاع من الـ ISO (Boot Menu Modes)

عند إقلاع الجهاز أو الـ VM من الـ ISO، ستظهر لك شاشة الإقلاع مع الخيارات التالية:

1. **FluxWAN OS - Live Multi-WAN Router (Run from RAM) [الافتراضي]:**
   - يعمل النظام فوراً من ذاكرة الرام (RAM) خلال 3 ثوانٍ دون الحاجة لتثبيته على القرص الصلب.
   - مناسب جداً للتجربة السريعة واختبار كروت الشبكة ومنافذ الـ Multi-WAN.

2. **FluxWAN OS - Install to Hard Disk / SSD / NVMe / VM:**
   - الدخول إلى معالج التثبيت الدائم على القرص الصلب أو الـ NVMe.

---

## 🛠️ 5. التثبيت الدائم على القرص الصلب (Permanent Installation)

إذا كنت في الوضع الحي (Live Mode) وتريد تثبيت النظام بشكل دائم على الهارد ديسك:

1. في شاشة سطر الأوامر (Console)، اكتب الأمر:
   ```bash
   fluxwan-install
   ```
2. سيعرض لك المعالج قائمة الأقراص المتاحة (`sda`, `vda`, `nvme0n1`).
3. اكتب اسم القرص المستهدف، ثم اكتب `YES` لتأكيد الفورمات والتثبيت.
4. سيتم تهيئة الـ GRUB وتثبيت النظام بالكامل خلال أقل من 10 ثوانٍ.
5. أخرج الفلاشة وأعد التشغيل ليعمل جهازك كراوتر FluxWAN دائم!

---

## 🌐 6. أول تشغيل والدخول للوحة التحكم:

- المنفذ الأول (`eth0` أو `ens18`) مخصص تلقائياً كمنفذ **LAN** بعنوان:
  `http://192.168.1.1:8080`
- خادم الـ **DHCP** مفعّل تلقائياً ليمنح حاسوبك عنوان IP فور توصيل كابل الشبكة.
- **بيانات الدخول الافتراضية:**
  - اسم المستخدم: `admin`
  - كلمة المرور: `admin`
