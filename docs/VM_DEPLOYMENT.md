# دليل تشغيل ونشر FluxWAN على الأنظمة الافتراضية والـ VMs
(Virtual Machine & Hypervisor Deployment Guide)

يدعم **FluxWAN** العمل المباشر والسلس كراوتر افتراضي (Virtual Router Appliance) على كافة بيئات ومحاكيات الأنظمة الافتراضية (Hypervisors).

---

## 🖥️ 1. متطلبات الـ VM الموصى بها (Recommended VM Specs)

- **المعالج (CPU):** 1 إلى 2 vCPU (x86_64).
- **الذاكرة (RAM):** 512 MB إلى 1 GB (استهلاك FluxWAN الحقيقي أقل من 10 MB فقط!).
- **القرص الصلب (Disk):** 4 GB إلى 8 GB.
- **كروت الشبكة (NICs):** على الأقل كرتين شبكة (1x LAN + 1x WAN) أو أكثر (مثلاً 1x LAN + 3x WAN).
- **نوع كرت الشبكة الموصى به:** `VirtIO (virtio-net)` لأقصى أداء، أو `Intel e1000/e1000e` أو `VMXNET3`.

---

## ⚡ 2. التثبيت التلقائي بضغطة زر (One-Click VM Deploy)

داخل أي نظام لينكس يعمل داخل الـ VM (مثل Ubuntu 22.04/24.04, Debian 12, Alpine Linux):

```bash
# استنساخ وتشغيل سكربت التثبيت التلقائي:
git clone https://github.com/fluxwan/fluxwan.git /tmp/fluxwan-install
cd /tmp/fluxwan-install
sudo bash scripts/deploy_vm.sh
```

يقوم السكربت بالآتي تلقائياً:
1. تثبيت حزم الترجمة و `libbpf` و `iptables` و `conntrack`.
2. ضبط كيرنل لينكس على وضع التوجيه السريع وتفعيل `rp_filter = 2` للدمج المتعدد.
3. بناء وترجمة FluxWAN مع الواجهة الرسومية المدمجة.
4. تثبيت وتفعيل خدمة `systemd` ليعمل الراوتر تلقائياً عند إقلاع الـ VM (`fluxwan.service`).

---

## 🌐 3. إعدادات الشبكة بحسب نوع الـ Hypervisor

### أ) Proxmox VE (PVE)
1. أنشئ VM بنظام Linux (Debian أو Ubuntu).
2. أضف كروت الشبكة من نوع `VirtIO (paravirtualized)`:
   - `net0` (vmbr0) -> منفذ الـ LAN.
   - `net1` (vmbr1 أو منفذ فيزيائي) -> منفذ WAN 1.
   - `net2` (vmbr2 أو منفذ فيزيائي) -> منفذ WAN 2.
3. شغل السكربت `sudo bash scripts/deploy_vm.sh`.
4. افتح المتصفح على `http://<IP-LAN>:8080` (اسم المستخدم الافتراضي: `admin` / كلمة المرور: `admin`).

### ب) VMware ESXi / Workstation
1. اختر كروت الشبكة من نوع `VMXNET3` أو `Intel E1000`.
2. اضبط كرت الـ LAN على Switch/VLAN داخلي (Host-only أو Custom).
3. اضبط كروت الـ WAN على Bridged أو NAT لمزودي الخدمة.

### ج) Oracle VirtualBox
1. في إعدادات الـ VM -> Network:
   - Adapter 1 (LAN): اضبطه على `Internal Network` (لتغذية باقي الأجهزة الافتراضية).
   - Adapter 2 (WAN 1): اضبطه على `Bridged Adapter` (المودم الأول).
   - Adapter 3 (WAN 2): اضبطه على `Bridged Adapter` (المودم الثاني أو هاتف 4G).
2. نوع المحول: `Paravirtualized Network (virtio-net)` أو `Intel PRO/1000 MT Desktop`.

---

## 🐳 4. التشغيل عبر Docker / Docker Compose

إذا كنت تفضل تشغيل FluxWAN داخل حاوية افتراضية (Container):

```bash
docker-compose up -d
```

---

## 🔍 5. أوامر إدارة الخدمة داخل الـ VM

```bash
# فحص حالة الراوتر:
sudo systemctl status fluxwan.service

# إعادة تشغيل الراوتر:
sudo systemctl restart fluxwan.service

# متابعة السجلات الحية:
sudo journalctl -u fluxwan.service -f
```
