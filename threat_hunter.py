import os
import subprocess
import requests

print("\033[1;36m[+] جمع معلومات الشبكة المتوافقة مع صلاحيات أندرويد...\033[0m")

# 1. جمع جدول الجوار ARP
try:
    arp_data = subprocess.check_output("ip neigh 2>/dev/null", shell=True).decode().strip()
    if not arp_data:
        arp_data = "لا توجد أجهزة مسجلة في كاش ARP حالياً"
except Exception:
    arp_data = "غير متوفر"

# 2. تحديد البوابة الافتراضية والواجهة
try:
    gw_data = subprocess.check_output("ip route 2>/dev/null", shell=True).decode().strip()
except Exception:
    gw_data = "غير متوفر"

# 3. محاولة استخراج خوادم DNS عبر getprop بطريقة أندرويد القياسية
try:
    dns1 = subprocess.check_output("getprop net.dns1 2>/dev/null", shell=True).decode().strip()
    dns2 = subprocess.check_output("getprop net.dns2 2>/dev/null", shell=True).decode().strip()
    dns_data = f"DNS 1: {dns1}\nDNS 2: {dns2}" if (dns1 or dns2) else "مقيّد بواسطة SELinux (طبيعي بدون Root)"
except Exception:
    dns_data = "مقيّد بواسطة SELinux"

print("\033[1;33m[*] جاري إرسال البيانات للذكاء الاصطناعي مع سياق بيئة أندرويد...\033[0m\n")

api_key = os.environ.get("GEMINI_API_KEY")
if not api_key:
    print("خطأ: لم يتم ضبط GEMINI_API_KEY")
    exit(1)

prompt = f"""
أنت مهندس دفاع سيبراني متخصص في أمن الشبكات المحلية وأجهزة الهاتف المحمول.
البيانات التالية تم استخراجها من بيئة Termux على هاتف أندرويد (غير مروّت / Non-Root).
ملاحظة أساسية: غياب بعض بيانات المقابس (Sockets) أو خصائص الـ DNS ناتج عن سياسات حماية SELinux الافتراضية في أندرويد وليس دليلاً على Rootkit أو اختراق.

--- [1. مسارات التوجيه والواجهات (IP Route)] ---
{gw_data}

--- [2. جدول الجوار والـ ARP (Neighbour Table)] ---
{arp_data}

--- [3. خوادم الـ DNS المستخرجة] ---
{dns_data}

قم بتحليل هذه البيانات وتقديم تقرير واقعي يركز على:
1. تقييم أمان الشبكة المحلية المحيطة (Security Score) من 100 بناءً على حالة الأجهزة المرئية فقط.
2. التحقق من سلامة البوابة الافتراضية وجدول ARP (هل يوجد أي تعارض أو اشتباه في انتحال ARP Spoofing؟).
3. قراءة نطاق الشبكة والأجهزة المتصلة المكتشفة في الجدول.
4. إرشادات دفاعية عملية لتأمين الاتصال عبر الواي فاي (مثل استخدام DoH/DoT أو VPN).
"""

url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-lite-latest:generateContent?key={api_key}"
headers = {"Content-Type": "application/json"}
payload = {"contents": [{"parts": [{"text": prompt}]}]}

try:
    res = requests.post(url, json=payload, headers=headers)
    if res.status_code == 200:
        report = res.json()['candidates'][0]['content']['parts'][0]['text']
        print("\033[1;32m" + "="*60 + "\033[0m")
        print("\033[1;35m       تقرير تقييم الشبكة المحلية (Termux Safe Audit)       \033[0m")
        print("\033[1;32m" + "="*60 + "\033[0m\n")
        print(report)
        print("\n\033[1;32m" + "="*60 + "\033[0m")
    else:
        print(f"خطأ من الخادم: {res.text}")
except Exception as e:
    print(f"حدث خطأ أثناء الاتصال: {e}")
