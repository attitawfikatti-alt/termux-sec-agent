#!/data/data/com.termux/files/usr/bin/bash

# اكتشاف نطاق الشبكة المتصل تلقائياً
SUBNET=$(ip route show dev wlan0 | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' | head -n 1)

if [ -z "$SUBNET" ]; then
    echo "⚠️ تعذر اكتشاف نطاق wlan0 تلقائياً. تأكد من الاتصال بالـ Wi-Fi."
    exit 1
fi

echo "🔍 بدء فحص الشبكة للنطاق: $SUBNET"
python net_radar.py "$SUBNET"

# جلب التقرير الناتج وتمريره إلى الوكيل الذكي
LATEST_REPORT=$(ls -t ~/reports/radar_report_*.md 2>/dev/null | head -n 1)

if [ -n "$LATEST_REPORT" ]; then
    echo "🤖 جاري تحليل التقرير عبر Gemini Agent..."
    python gemini_agent.py "$LATEST_REPORT"
else
    echo "❌ لم يتم العثور على تقرير فحص."
fi
