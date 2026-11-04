#!/data/data/com.termux/files/usr/bin/bash

echo "=== [بدء تثبيت منظومة Termux Security Agent] ==="

# 1. تحديث الحزم وتثبيت الاعتماديات الأساسية
echo "[+] جاري فحص وتثبيت الحزم المطلوبة..."
pkg update -y
pkg install -y python nmap cronie termux-api android-tools

# 2. تثبيت مكتبات بايثون المطلوبة
echo "[+] تثبيت مكتبات Python..."
pip install --upgrade pip
pip install requests

# 3. منح الصلاحيات التنفيذية للسكريبتات
echo "[+] ضبط صلاحيات التنفيذ..."
chmod +x ~/termux-sec-agent/*.py
chmod +x ~/termux-sec-agent/*.sh

# 4. إعداد ملف الأجهزة الموثوقة الافتراضي إذا لم يكن موجوداً
if [ ! -f ~/termux-sec-agent/trusted_macs.txt ]; then
    echo "[+] إنشاء ملف trusted_macs.txt أولي..."
    cp ~/termux-sec-agent/trusted_macs.txt.example ~/termux-sec-agent/trusted_macs.txt
fi

# 5. تفعيل خدمة الجدولة Crond وحجز قفل المعالج
echo "[+] تفعيل خدمات الخلفية والجدولة..."
termux-wake-lock
pgrep crond > /dev/null || crond

# 6. تسجيل مهمة الفحص الدوري في crontab (كل 15 دقيقة)
(crontab -l 2>/dev/null | grep -v 'net_guardian.py' ; echo "*/15 * * * * python3 ~/termux-sec-agent/net_guardian.py > /dev/null 2>&1") | crontab -

# 7. إعداد الإقلاع التلقائي مع الهاتف عبر Termux:Boot
mkdir -p ~/.termux/boot
cat << 'BOOT_EOF' > ~/.termux/boot/start-sec-agent.sh
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
sleep 10
pgrep crond > /dev/null || crond
pgrep -f watchdog.py > /dev/null || nohup python3 -u ~/termux-sec-agent/watchdog.py > ~/termux-sec-agent/watchdog.log 2>&1 &
BOOT_EOF
chmod +x ~/.termux/boot/start-sec-agent.sh

echo "============================================="
echo "[✓] اكتمل التثبيت بنجاح!"
echo "- الحارس watchdog جاهز."
echo "- الفحص الدوري net_guardian مجدول كل 15 دقيقة."
echo "- تم ربط الإقلاع التلقائي مع Termux:Boot."
echo "============================================="
