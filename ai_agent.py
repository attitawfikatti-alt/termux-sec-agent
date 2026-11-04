#!/usr/bin/env python3
import os
import sys
import requests

API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    print("[!] خطأ: المتغير GEMINI_API_KEY غير موجود في بيئة العمل.")
    sys.exit(1)

# النموذج المعتمد لحسابك
MODEL = "gemini-3.8-flash"
API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent?key={API_KEY}"

def ask_gemini(prompt_text):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    clean_prompt = str(prompt_text).strip()
    payload = {
        "contents": [
            {
                "parts": [{"text": clean_prompt}]
            }
        ]
    }

    try:
        res = requests.post(API_URL, headers=headers, json=payload, timeout=60)
        if res.status_code == 200:
            data = res.json()
            return data["candidates"][0]["content"]["parts"][0]["text"].strip()
        else:
            return f"[!] رفض الخادم الطلب ({res.status_code}): {res.text}"
    except requests.exceptions.RequestException as e:
        return f"[!] خطأ في الاتصال بالشبكة: {e}"
    except (KeyError, IndexError):
        return f"[!] استجابة غير متوقعة: {res.text}"

if __name__ == "__main__":
    query = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "قل مرحبا فقط"
    print(ask_gemini(query))
