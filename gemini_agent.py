import os
import sys
import subprocess
import requests

api_key = os.environ.get("GEMINI_API_KEY")
if not api_key:
    print("خطأ: يرجى ضبط GEMINI_API_KEY أولاً.")
    sys.exit(1)

def check_host_alive(target: str) -> str:
    """فحص وصول الجهاز عبر Ping"""
    try:
        res = subprocess.run(["ping", "-c", "2", "-W", "2", target], capture_output=True, text=True, check=False)
        return res.stdout if res.returncode == 0 else f"الجهاز لا يستجيب: {res.stderr}"
    except Exception as e:
        return f"فشل تشغيل ping: {e}"

def scan_open_ports(target: str) -> str:
    """فحص المنافذ السريعة عبر nmap"""
    try:
        res = subprocess.run(["nmap", "-Pn", "-sT", "-F", target], capture_output=True, text=True, check=False)
        return res.stdout if res.returncode == 0 else f"خطأ في nmap: {res.stderr}"
    except Exception as e:
        return f"فشل تشغيل nmap: {e}"

AVAILABLE_FUNCTIONS = {
    "check_host_alive": check_host_alive,
    "scan_open_ports": scan_open_ports
}

tools_schema = [
    {
        "function_declarations": [
            {
                "name": "check_host_alive",
                "description": "فحص اتصال الجهاز بالشبكة باستخدام Ping.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "target": {"type": "STRING", "description": "عنوان IP المراد فحصه"}
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "scan_open_ports",
                "description": "فحص المنافذ والخدمات المفتوحة على جهاز محدد باستخدام nmap.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "target": {"type": "STRING", "description": "عنوان IP المراد فحصه"}
                    },
                    "required": ["target"]
                }
            }
        ]
    }
]

url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-lite-latest:generateContent?key={api_key}"
headers = {"Content-Type": "application/json"}

def run_agent(user_prompt: str):
    print(f"\n\033[1;34m[+] المستخدم:\033[0m {user_prompt}")
    
    messages = [
        {"role": "user", "parts": [{"text": user_prompt}]}
    ]

    max_steps = 5  # حد أمان لمنع التكرار اللانهائي
    step = 0

    while step < max_steps:
        step += 1
        payload = {
            "contents": messages,
            "tools": tools_schema
        }

        res = requests.post(url, headers=headers, json=payload).json()
        
        if "error" in res:
            print(f"\033[1;31m[-] خطأ من الخادم:\033[0m {res['error']}")
            return

        candidate = res.get("candidates", [{}])[0].get("content", {})
        parts = candidate.get("parts", [])

        # استخراج استدعاءات الدوال
        function_calls = [p["functionCall"] for p in parts if "functionCall" in p]

        if function_calls:
            messages.append(candidate)
            function_response_parts = []

            for call in function_calls:
                f_name = call["name"]
                f_args = call.get("args", {})
                print(f"\033[1;33m[*] [خطوة {step}] الوكيل يستدعي محلياً: {f_name}({f_args})\033[0m")
                
                if f_name in AVAILABLE_FUNCTIONS:
                    output = AVAILABLE_FUNCTIONS[f_name](**f_args)
                else:
                    output = "الدالة غير متوفرة."

                # كائن JSON متوافق مع معايير واجهة Gemini
                function_response_parts.append({
                    "functionResponse": {
                        "name": f_name,
                        "response": {"content": output}
                    }
                })

            messages.append({
                "role": "user",
                "parts": function_response_parts
            })

        else:
            # عندما ينتهي النموذج من استدعاء الأدوات ويصدر التقرير النهائي
            text_response = "".join([p.get("text", "") for p in parts])
            print(f"\n\033[1;32m[+] تقرير التحليل النهائي:\033[0m\n{text_response}\n")
            break

if __name__ == "__main__":
    prompt = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "هل الراوتر 192.168.8.1 متصل حالياً؟ وما هي المنافذ المفتوحة عليه؟"
    run_agent(prompt)
