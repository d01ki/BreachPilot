# 🚀 BreachPilot - Hybrid AI Pentest Platform

**Mock Scans + Real AI CVE Analysis = Best of Both Worlds**

## ✨ Features

- 🎭 **Mock OSINT & Nmap** - Instant results without tools
- 🤖 **Real AI CVE Analysis** - CrewAI agents identify vulnerabilities
- 💥 **PoC Retrieval** - Find exploits on GitHub/ExploitDB
- 📊 **XAI Explanations** - Understand why CVEs were identified
- 🎯 **Compact UI** - Clean, efficient interface

## 🔧 Quick Start

```bash
git pull
python app.py
# Visit http://localhost:5000/pentest
```

**That's it!** Enter any target and get instant mock scans.

## 🤖 Enable Real AI Analysis

For actual AI-powered CVE identification:

```bash
# Set your API key
export ANTHROPIC_API_KEY="sk-ant-..."
# or
export OPENAI_API_KEY="sk-..."

# Install CrewAI
pip install crewai langchain-anthropic

# Run
python app.py
```

## 🎯 How It Works

### Phase 1: Mock Scans (3s)
- OSINT: DNS, subdomains, IPs
- Nmap: 5 open ports with services

### Phase 2: Real AI Analysis (5-10s)
**With API key:**
- 🤖 CVE Analyst identifies vulnerabilities
- 🔍 PoC Researcher finds exploits
- 📝 XAI explains reasoning

**Without API key:**
- Pattern-based fallback matching

## 📊 UI Overview

### Compact Layout
```
┌─────────────────────────────────────┐
│  🔍 Recon      🤖 AI      💥 Exploit │
│  [████] 100%   [██] 50%   [░] 0%    │
└─────────────────────────────────────┘

┌──────────────────┬──────────────────┐
│  🔎 Scan Results │ 🤖 AI Vulns      │
│  - 5 open ports  │ CVE-2021-44228   │
│  - 7 subdomains  │ ┌──────────────┐ │
│                  │ │🧠 AI Reasoning│ │
│                  │ │Why: Apache...│ │
│                  │ │PoC: GitHub   │ │
│                  │ └──────────────┘ │
└──────────────────┴──────────────────┘
```

## 🧠 Real AI Agent Details

### CVE Analyst Agent
```python
Role: 'CVE Security Analyst'
Goal: Identify CVEs with high accuracy
Output: CVE ID, CVSS, severity, reasoning
```

### PoC Researcher Agent
```python
Role: 'Exploit Researcher'
Goal: Find working exploits
Output: GitHub links, ExploitDB entries
```

### XAI Output Example
```json
{
  "cve": "CVE-2021-44228",
  "severity": "CRITICAL",
  "xai_explanation": {
    "why_identified": "Apache Tomcat 9.0.30 uses Log4j 2.x",
    "evidence": "Port 8080 running Tomcat",
    "poc_available": "Yes - Multiple PoCs on GitHub"
  }
}
```

## 📁 Results

Saved to `reports/{chain_id}/`:
- `osint.json` - Mock OSINT data
- `nmap.json` - Mock port scan
- `vulnerabilities.json` - Real AI CVE analysis with XAI

## 🎭 Mock vs Real

| Component | Type | Speed |
|-----------|------|-------|
| OSINT | Mock | 3s |
| Nmap | Mock | 5s |
| CVE Analysis | **Real AI** | 5-10s |
| PoC Retrieval | **Real AI** | Included |

## 🐛 Troubleshooting

### No results?
```bash
# Check browser console (F12)
# Verify API responded
curl http://localhost:5000/api/attack-chain/{id}/status
```

### AI not working?
```bash
# Verify API key
echo $ANTHROPIC_API_KEY

# Check CrewAI installation
pip show crewai
```

### Want full simulation?
```bash
# No API key needed
# Just run and test
python app.py
```

## 🔬 Testing

### Instant Test (No API key)
```bash
python app.py
# Enter: test.example.com
# Result: Mock data + pattern matching
```

### Full AI Test (With API key)
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
python app.py
# Enter: vulnerable.site.com
# Result: Mock data + Real AI CVE analysis
```

## 📊 Example Output

### Mock Scan Results
```
Target: demo.example.com
- IPs: 192.168.1.100
- Subdomains: 7 found
- Open Ports:
  22/tcp SSH OpenSSH 7.4
  80/tcp HTTP Apache 2.4.6
  443/tcp HTTPS
  3306/tcp MySQL 5.7.30
  8080/tcp Tomcat 9.0.30
```

### Real AI Analysis
```
🤖 AI Analysis Complete

CVE-2021-44228 (CRITICAL)
└─ Why: Apache Tomcat uses vulnerable Log4j
└─ Evidence: Service version Tomcat 9.0.30
└─ PoC: Available on GitHub
└─ Impact: Remote code execution

CVE-2018-15473 (MEDIUM)  
└─ Why: OpenSSH 7.4 vulnerable to enum
└─ Evidence: SSH service detected
└─ PoC: Python script available
└─ Impact: Username enumeration
```

## 🚀 Architecture

```
┌─────────────┐
│   Flask     │
│   Server    │
└──────┬──────┘
       │
┌──────▼──────────────┐
│ Hybrid Orchestrator │
├─────────────────────┤
│ 1. Mock OSINT (3s)  │
│ 2. Mock Nmap (5s)   │
│ 3. Real AI CVE (10s)│
└─────────────────────┘
       │
┌──────▼──────────┐
│   Real AI Agent │
├─────────────────┤
│ - CVE Analyst   │
│ - PoC Researcher│
│ - XAI Generator │
└─────────────────┘
```

## 📝 Summary

**Perfect for:**
- ✅ Instant testing without tools
- ✅ Real CVE identification with AI
- ✅ PoC discovery
- ✅ Learning XAI reasoning

**Just:**
```bash
git pull && python app.py
```

---

**Version:** 4.0 (Hybrid Edition)
**Last Updated:** 2025-09-21
