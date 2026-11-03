import os
import sys
import subprocess
import requests

api_key = os.environ.get("GEMINI_API_KEY")
if not api_key:
    print("خطأ: لم يتم ضبط مفتاح GEMINI_API_KEY بعد.")
    print("اكتب في الطرفية: export GEMINI_API_KEY='مفتاحك'")
    sys.exit(1)

url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-lite-latest:generateContent?key={api_key}"
headers = {"Content-Type": "application/json"}

def render_bidi(text):
    """تمرير النص عبر fribidi لتصحيح اتجاه الحروف العربية"""
    try:
        proc = subprocess.Popen(
            ["fribidi", "-c", "UTF-8"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8"
        )
        out, _ = proc.communicate(input=text)
        return out if out else text
    except FileNotFoundError:
        # إذا لم تكن الأداة مثبتة يطبع النص الخام
        return text

def ask_gemini(prompt_text):
    payload = {"contents": [{"parts": [{"text": prompt_text}]}]}
    try:
        res = requests.post(url, json=payload, headers=headers)
        if res.status_code == 200:
            raw_text = res.json()['candidates'][0]['content']['parts'][0]['text']
            formatted_text = render_bidi(raw_text)
            print(formatted_text)
        else:
            print(f"خطأ ({res.status_code}): {res.text}")
    except Exception as e:
        print(f"حدث خطأ أثناء الاتصال: {e}")

# 1. حالة الإدخال عبر الأنبوب (Pipe): cat file.txt | python ai.py
if not sys.stdin.isatty():
    piped_data = sys.stdin.read().strip()
    instruction = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "قم بتحليل وتلخيص النص التالي:"
    ask_gemini(f"{instruction}\n\nالنص المطلوب تحليله:\n{piped_data}")
    sys.exit(0)

# 2. حالة تمرير ملف أو سؤال كمعامل مباشر: python ai.py -f file.txt
elif len(sys.argv) > 1:
    arg = sys.argv[1]
    if os.path.isfile(arg):
        with open(arg, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        ask_gemini(f"قم بتحليل النص التالي المستخرج من الملف ({arg}):\n\n{content}")
    else:
        ask_gemini(" ".join(sys.argv[1:]))
    sys.exit(0)

# 3. وضع المحادثة التفاعلية
print("\n=== مساعد الذكاء الاصطناعي (اكتب 'exit' للخروج) ===")
while True:
    try:
        user_input = input("\nأنت: ")
        if user_input.strip().lower() in ['exit', 'خروج']:
            break
        if not user_input.strip():
            continue
        ask_gemini(user_input)
    except KeyboardInterrupt:
        print("\nتم الإغلاق.")
        break
