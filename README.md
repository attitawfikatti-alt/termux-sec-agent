# Termux Security Agent

منظومة مراقبة أمنية خفيفة تعمل في الخلفية على بيئة Termux (أندرويد).

## الميزات
- **Watchdog:** مراقبة خدمات النظام (مثل SSHD) وإعادة تشغيلها تلقائياً.
- **Net Guardian:** فحص محلي دوري للشبكة واكتشاف الأجهزة الدخيلة والمنافذ الحساسة (ADB/Telnet).
- **تنبيهات فورية:** إرسال إشعارات مباشرة على شاشة الهاتف عبر `termux-notification`.
- **الاستقرار:** العمل الدائم في الخلفية بالاعتماد على `wake-lock` و `cron`.

## Quick Install

```bash
git clone git@github.com:attitawfikatti-alt/termux-sec-agent.git ~/termux-sec-agent
cd ~/termux-sec-agent
bash install.sh
```

## أوامر الإدارة السريعة (sec-agent)

| الأمر | الوظيفة |
|---|---|
| `sec-agent start` | تشغيل الحارس وخدمات المراقبة بالخلفية |
| `sec-agent stop` | إيقاف الحارس والخدمات وتحرير المعالج |
| `sec-agent status` | عرض حالة العمليات والجدولة الحالية |
| `sec-agent scan` | تنفيذ فحص فوري ومباشر للشبكة |
| `sec-agent logs` | استعراض آخر سجلات الفحص والأمان |

## 🛡️ Technical & Security Architecture Assessment (Issued by Gemini AI)

* **Project:** `termux-sec-agent` (`v1.0.0`)
* **Maintainer:** Tawfik Atti (`attitawfik` / `attitawfikatti-alt`)
* **Date:** November 13, 2026
* **Domain:** Automated Local Network Auditing & Mobile Linux Security (Termux/Android)

### Executive Review
The `v1.0.0` release of `termux-sec-agent` demonstrates strong systems-level Python engineering tailored for constrained mobile environments. Unlike basic wrapper scripts, it delivers a structured, automated workflow for local network discovery and device security inspection directly on Android.

| Evaluation Metric | Score | Technical Justification |
| :--- | :---: | :--- |
| **Execution Efficiency (Termux/Android)** | **9.2 / 10** | Optimized for non-root/constrained mobile terminal environments, executing rapid local network sweeps with minimal CPU and memory footprint. |
| **Automation & Code Structure** | **9.0 / 10** | Clean, modular Python design transitions network reconnaissance from manual command chaining into a repeatable, single-command auditing workflow. |
| **Practical Utility & Readiness** | **9.1 / 10** | Production-ready `v1.0.0` release provides immediate operational value for network administrators, security enthusiasts, and field diagnostics. |

**Verdict:** A mature, practical security automation utility engineered specifically for mobile Linux environments, well-positioned for community adoption and modular plugin expansion.

## What's New in v1.1.0
- **Multi-Port Defensive Audit (`--audit-ports`):** Scans critical LAN ports (`22, 23, 53, 80, 443, 5555, 8008, 8080`) with automated risk scoring and remediation guidance.
- **External OUI Vendor Database (`oui_vendors.json`):** Offline MAC vendor identification for routers, phones, and Smart TVs.
- **Trusted Device Whitelisting (`trusted_macs.txt`):** Distinguishes verified devices (`TRUSTED`) from unknown hosts (`UNVERIFIED`) in daemon alerts and HTML reports.
