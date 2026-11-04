# Termux Security Agent (termux-sec-agent)

An automated network service auditor and device inspection tool tailored for Termux on Android.

## Features
- **Subnet Auditing:** Scan `/24` subnets concurrently for target ports.
- **Stealth Mode:** Rate-limited single-worker scanning with randomized jitter.
- **Dual Reporting:** Generates audit logs in structured JSON and mobile-friendly HTML.
- **Device Fingerprinting:** Captures basic device metadata over open ports.

## Installation
```bash
pkg update && pkg install git python android-tools termux-api -y
git clone [https://github.com/attitawfikatti-alt/termux-sec-agent.git](https://github.com/attitawfikatti-alt/termux-sec-agent.git)
cd termux-sec-agent
chmod +x agent.py
```

## Usage
```bash
python agent.py -s 192.168.8 -p 5555
python agent.py -s 192.168.8 --stealth -o html
```
