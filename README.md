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
