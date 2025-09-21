# 🚀 BreachPilot - AI-Powered Automated Penetration Testing

## ✨ Features

- 🔍 **OSINT Reconnaissance** - DNS, WHOIS, SSL, Subdomain enumeration
- 🎯 **Port Scanning** - Nmap integration with service detection  
- 🤖 **AI Vulnerability Analysis** - CrewAI-powered CVE identification with XAI
- 📊 **Real-time Results** - Live progress and explainable AI reasoning
- 🎭 **Simulation Mode** - Test without real tools

## 🔧 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/d01ki/BreachPilot.git
cd BreachPilot
git checkout feature/dev_v2

# Install dependencies
pip install flask python-dotenv

# Optional: For AI analysis (CrewAI)
pip install crewai langchain-anthropic langchain-openai

# Optional: For real scanning
pip install dnspython python-whois requests pyOpenSSL
sudo apt-get install nmap  # or brew install nmap (macOS)
```

### Configuration

```bash
# Set environment variables
export ANTHROPIC_API_KEY="your-api-key"  # For AI analysis
export SIMULATION_MODE="true"  # Use simulation mode
```

### Run

```bash
python app.py
```

Access at: **http://localhost:5000/pentest**

## 🎭 Simulation Mode (Default)

**No tools required!** Just pull and run:

```bash
git pull
python app.py
# Enter any target (e.g., "test.example.com")
```

Returns realistic simulation data:
- OSINT: DNS, subdomains, SSL info
- Nmap: 5 open ports with services
- CVEs: 5 vulnerabilities with severity

## 🤖 AI Analysis (CrewAI)

Set API key for CrewAI-powered analysis:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
# or
export OPENAI_API_KEY="sk-..."
```

### AI Features

1. **3 Specialized Agents**
   - Vulnerability Analyst
   - CVE Researcher
   - XAI Explainer

2. **Explainable AI (XAI)**
   - WHY was CVE identified?
   - WHAT evidence supports it?
   - HOW can it be exploited?
   - WHAT is the impact?

3. **Results include:**
   ```json
   {
     "vulnerabilities": [...],
     "xai_explanations": {
       "CVE-2021-44228": {
         "why_identified": "Apache version matches vulnerable range",
         "evidence": "Service: Apache 2.4.6 on port 8080",
         "attack_vector": "Remote code execution via Log4j",
         "impact": "Full system compromise possible"
       }
     }
   }
   ```

## 🔍 How to Use

### 1. Go to Pentest Page
```
http://localhost:5000/pentest
```

### 2. Enter Target
- Simulation: Any value (e.g., "demo.target.com")
- Real mode: Authorized target only

### 3. Watch Results
- ✅ Progress bars (0% → 50% → 100%)
- 📋 Live execution logs
- 🔍 OSINT results
- 🔎 Port scan results  
- ⚠️ Vulnerabilities with AI explanations

## 📊 Workflow

```
🔍 OSINT Gathering (3s)
   ↓ JSON saved
🔎 Nmap Scanning (5s)
   ↓ JSON saved
🤖 AI CVE Analysis (4s)
   ↓ JSON + XAI saved
📋 Display Results
```

## 🎯 Testing

### Safe Simulation Test
```bash
# No tools needed
python app.py

# Enter: test.example.com
# Results appear in 12s
```

### Real Tool Test
```bash
export SIMULATION_MODE="false"
python app.py

# Enter: scanme.nmap.org
```

## 📁 Output Files

Results saved to `reports/{chain_id}/`:

```
reports/
└── abc123-def456/
    ├── osint.json           # OSINT results
    ├── nmap.json            # Port scan
    └── ai_vulnerabilities.json  # AI analysis + XAI
```

## 🧠 AI Analysis Details

### Without API Key (Fallback)
- Pattern-based CVE matching
- Basic severity assessment
- Simple explanations

### With API Key (CrewAI)
- Multi-agent collaboration
- Deep CVE research
- Explainable reasoning
- PoC availability check
- Attack chain analysis

## 🐛 Troubleshooting

### No results showing?
1. Check browser console (F12)
2. Verify simulation mode: `export SIMULATION_MODE="true"`
3. Check logs in terminal

### AI analysis not working?
1. Set API key: `export ANTHROPIC_API_KEY="..."`
2. Install CrewAI: `pip install crewai langchain-anthropic`
3. Check terminal for errors

### Progress bars stuck?
1. Refresh page
2. Check `/api/attack-chain/{id}/status` response
3. Look for errors in browser console

## 📝 Example XAI Output

```
CVE-2021-44228 (Log4Shell)
├── Why Identified: Apache Tomcat 9.0.30 uses vulnerable Log4j
├── Evidence: Port 8080 running http-proxy service
├── Attack Vector: Remote code execution via JNDI injection
└── Impact: Complete system compromise

Reasoning Chain:
1. Detected Tomcat 9.0.30 on port 8080
2. Tomcat versions use Log4j 2.x
3. Log4j 2.x < 2.17.0 vulnerable to CVE-2021-44228
4. Service publicly accessible → High exploitability
5. RCE vulnerability → Critical severity
```

## ⚠️ Legal Notice

**Educational purposes only**
- Only scan authorized targets
- Legal responsibility is yours
- Not for malicious use

## 🔗 Links

- Documentation: `/FIXED_IMPLEMENTATION.md`
- API Docs: `/api/attack-chain/create`
- Issues: GitHub Issues

---

**Version:** 3.0 (AI + Simulation Edition)
**Last Updated:** 2025-09-21

**🎉 Just `git pull` and `python app.py` to test!**
