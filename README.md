# Termux Automated Network Audit & AI Agent

مجموعة أدوات دفاعية وتدقيق شبكي مدمجة مع نموذج Gemini عبر Termux:
- `ai.py`: مساعد محادثة طرفي يدعم تحليل الملفات، الأنابيب، والنصوص العربية عبر `fribidi`.
- `threat_hunter.py`: فاحص تشخيصي لطبقات الشبكة المحلية (ARP و Routing) متوافق مع قيود بيئة أندرويد.
- `gemini_agent.py`: وكيل ذكي ينفذ أوامر التشخيص محلياً (Ping / Nmap) عبر Function Calling ذاتي.

## المتطلبات
- Termux (Android)
- Python 3 + `requests` + `nmap` + `fribidi`
- ضبط مفتاح `GEMINI_API_KEY` كمتغير بيئة.
