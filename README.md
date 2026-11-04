# Termux Security Agent (termux-sec-agent)

An automated network service auditor and background monitor tailored for Termux on Android.

## Features
- **Auto-Subnet Detection:** Automatically identifies the local active Wi-Fi subnet.
- **Concurrent Auditing:** Scans `/24` subnets in parallel using native multi-threading.
- **Stealth Mode:** Rate-limited single-worker scanning with randomized jitter.
- **Dmon Watcher:** Periodic background monitoring with Android system notifications for new hosts.
- **MAC Caching & VOUI:** ARP-priming for vendor identification and risk evaluation.
- **Dual Reporting:** Generates structured JSON data and clean, mobile-friendly HTML files.

## Installation

```bash
pkg update && pkg install git python android-tools termux-api -y
git clone https://github.com/attitawfikatti-alt/termux-sec-agent.git
cd termux-sec-agent
chmod +x sec_agent.py setup.sh
./setup.sh
```B‚ˆÈÈ\ØYÙB‚ˆÈÈÈKˆ™\›ËPÛÛ™šYÈ[ˆ
[œİ[ØØ[ŠB˜˜\Úœ]ÛˆÙX×ØYÙ[œB˜‚ˆÈÈÈ‹ˆ˜XÚÙÜ›İ[™Y[[Ûˆ[ÙB”[ˆ[ˆ›Ü™YÜ›İ[™[™ÚXÚÈ]™\HHZ[]\È
ÌÙXÛÛ™ÊN‚˜˜\Úœ]ÛˆÙX×ØYÙ[œHKYY[[ÛˆKZ[\˜[Ì˜‚”[ˆ\ÈH]XÚY˜XÚÙÜ›İ[™›ØÙ\ÜÈšXH›Ú\‚˜˜\Ú››Ú\]ÛˆÙX×ØYÙ[œHKYY[[ÛˆKZ[\˜[ÌˆÙÜËÙY[[Û‹›ÙÈ‰ŒH	‚˜˜‚Šˆ
ÚXÚÈ[›š[™È›ØÙ\ÜÎŠŠˆÈ]^Ü™\ÙX×ØYÙ[œXŠˆ
“[Ûš]ÜˆÙÜÎêŠˆZ[YˆÙÜËÙY[[Û‹›ÙØŠˆ
”İÜ˜XÚÙÜ›İ[™Y[[ÛŠŠˆÚ[YˆÙX×ØYÙ[œX‚ˆÈÈÈËˆİX[ØØ[ˆÚ]S™\Ü˜˜\Úœ]ÛˆÙX×ØYÙ[œHK\İX[[È[˜‚ˆÈÈÓH™Y™\™[˜ÙB‚ŸÜ[Ûˆ›YÈ\ØÜš\[ÛˆY˜][Ÿ‹KKH‹KKH‹KKH‹KKHŸ
Š”İX›™]
Šˆ\ËK\İX›™]™]ÛÜšÈ™Yš^
K™ËˆNL‹ŒMŒX
HÜˆ]]Ø]]ØŸ
Š”Ü
Šˆ\K\Ü\™Ù]ÔÜMMMXŸ
Š”İX[
ŠˆK\İX[Ú[™ÛK]ÛÜšÙ\ˆ[ÙHÚ]˜[™ÛHš]\ˆ˜[ÙXŸ
Š‘Y[[ÛŠŠˆKYY[[Û˜\š[ÙXÈ˜XÚÙÜ›İ[™Ø]Ú\ˆ˜[ÙXŸ
Š’[\˜[
ŠˆKZ[\˜[ÚXÚÈ[\˜[[ˆÙXÛÛ™ÈÌŸ
Š‘›Ü›X]
Šˆ[ËKY›Ü›X]ÉÛÛ˜[Üˆ›İœÛÛ˜Ÿ
Š“İ]]\ŠŠˆK[İ]Y\˜\™XİÜH›ÜˆÙ[™\˜]Y™\ÜÈ™\ÜØ‚ˆÈÈXÙ[œÙB“RUXÙ[œÙKˆÙYHÓPÑS”ÑWJPÑS”ÑJH›Üˆ]Z[Ë‚