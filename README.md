# Termux Security Agent (termux-sec-agent)

An automated network service auditor and device inspection tool tailored for Termux on Android.

## Features
- **Auto-Subnet Detection:** Automatically identifies the local active Wi-Fi subnet without manual input.
- **Concurrent Auditing:** Scans `/24` subnets in parallel using native multi-threading.
- **Stealth Mode:** Rate-limited single-worker scanning with randomized jitter to minimize network congestion.
- **Dual Reporting:** Generates structured JSON data for archiving and clean, mobile-friendly HTML for direct viewing.
- **Device Fingerprinting:** Retrieves basic Android properties over exposed diagnostic ports.

## Installation

gbash
pkg update && pkg install git python android-tools termux-api -y
git clone https://github.com/attitawfikatti-alt/termux-sec-agent.git
cd termux-sec-agent
chmod +x sec_agent.py setup.sh
./setup.sh
```

## Usage

### 1. Zero-Config Run (Auto Detection)
Runs using the auto-detected local subnet and default target port:
`bash
python sec_agent.py
```

### 2. Manual Subnet Specification
Specify a target subnet explicitly:
`bash
python sec_agent.py -s 192.168.1 -p 5555
```

### 3. Stealth Scan with HTML Report
Low-profile scanning with browser-ready report output:
`bash
python sec_agent.py --stealth -o html
```

## CLI Reference

| Option | Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| **Subnet** | `-s, --subnet` | Network prefix (e.g. `192.168.1`) or `auto` | `auto` |
| **Port** | `-p, --port` | Target TCP port to verify | `5555` |
| **Stealth** | `--stealth` | Enables single-worker mode with random delay | `False` |
| **Format** | `-o, --format` | Output report type: `json`, `html`, or `both` | `json` |
| **Output Directory** | `--out-dir` | Folder destination for generated reports | `reports` |

## Viewing Reports
To open the latest HTML report in your device browser:
`bash
termux-open-url $(ls -t reports/*.html | head -n 1)
```

## License
MIT License. See [LICENSE](LICENSE) for details.
