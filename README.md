# 🚀 BreachPilot - Automated Penetration Testing

AI-powered automated penetration testing with real tools and intelligent analysis.

## ✨ Features

- 🔍 **OSINT Reconnaissance** - DNS, WHOIS, SSL, Subdomain enumeration
- 🎯 **Real Tool Execution** - Actual Nmap scans with service detection
- 🛡️ **CVE Identification** - NVD API integration for vulnerability detection
- 📊 **Real-time Results** - Live progress bars and result display
- 📋 **Detailed Reports** - JSON output for each phase

## 🔧 Quick Start

### 1. Install Dependencies

```bash
# Python packages
pip install flask python-dotenv dnspython python-whois requests pyOpenSSL

# System tools
# Ubuntu/Debian:
sudo apt-get install nmap

# macOS:
brew install nmap

# Windows:
# Download from https://nmap.org/download.html
```

### 2. Run the Application

```bash
python app.py
```

### 3. Access the Web UI

```
🌐 Main Page:    http://localhost:5000
⚡ Pentest:      http://localhost:5000/pentest
⚙️ Settings:    http://localhost:5000/settings
```

## 🎯 How to Use

1. **Go to Pentest Page** - http://localhost:5000/pentest
2. **Enter Target** - Domain or IP address
3. **Click "Start Pentest"**
4. **Watch Real-time Results**
   - Progress bars for each agent
   - Live logs
   - OSINT, Nmap, and CVE results

## 📁 Project Structure

```
BreachPilot/
├── app.py                          # Main Flask application
├── api_realtime_endpoints.py      # API endpoints
├── src/
│   ├── tools/
│   │   └── real_scanning_tools.py # OSINT, Nmap, CVE tools
│   └── agents/
│       └── realtime_orchestrator.py # Task orchestration
├── templates/
│   ├── index.html                  # Home page
│   └── pentest.html               # Pentest UI
└── reports/                        # JSON results (auto-generated)
    └── {chain_id}/
        ├── osint.json
        ├── nmap.json
        └── vulnerabilities.json
```

## 🔍 Testing

Use these safe targets for testing:

```
scanme.nmap.org      # Official Nmap test server
testphp.vulnweb.com  # Vulnerability testing site
```

## ⚠️ Important Notes

1. **Only scan authorized targets**
2. **Legal responsibility is yours**
3. **Not for production use**

## 🐛 Troubleshooting

### Results not showing?
- Check browser console (F12) for errors
- Verify `/api/attack-chain/{id}/status` returns data
- Check `reports/{chain_id}/` for JSON files

### Nmap not found?
```bash
which nmap
nmap --version
```

### DNS resolution errors?
```bash
python -c "import dns.resolver; print('OK')"
```

## 📊 Workflow

```
1. OSINT Intelligence
   ↓ (saved to osint.json)
2. Nmap Port Scan
   ↓ (saved to nmap.json)  
3. Vulnerability Analysis
   ↓ (saved to vulnerabilities.json)
4. Results Display
```

## 🎨 UI Features

### Progress Bars
Each agent shows 0-100% progress with color-coded status

### Live Logs
Real-time execution logs with timestamps

### Result Cards
- 🔍 OSINT: DNS, Subdomains, SSL info
- 🔎 Nmap: Open ports, Services
- ⚠️ Vulnerabilities: CVE, CVSS, Severity

## 📝 License

Educational purposes only. Use responsibly.

---

**Version:** 2.0 (Automated Pentest Edition)
**Last Updated:** 2025-09-21
