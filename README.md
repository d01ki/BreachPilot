# 🚀 BreachPilot - OpenAI Powered Pentest

**Mock Port Scan + Real OpenAI CVE Analysis + PoC Hunting**

## ✨ Features

- 🎭 **Mock Port Scan** - Instant 5 open ports
- 🤖 **Real OpenAI CVE Analysis** - GPT-4o identifies vulnerabilities
- 💥 **Real PoC Hunter** - Finds exploits on GitHub/ExploitDB
- 📊 **XAI Explanations** - Why each CVE was identified
- 🎯 **Risk-Based Sorting** - CVEs sorted by CVSS score

## 🔧 Quick Start

```bash
# 1. Clone and install dependencies
git pull
pip install -r requirements.txt

# 2. Set OpenAI API key
export OPENAI_API_KEY="sk-..."

# 3. Run
python app.py

# 4. Visit
http://localhost:5000/pentest
```

## 🎯 How It Works

### Phase 1: Mock Port Scan (2s)
```
Returns 5 open ports:
- 22/tcp SSH OpenSSH 7.4
- 80/tcp HTTP Apache 2.4.6
- 443/tcp HTTPS Apache 2.4.6
- 3306/tcp MySQL 5.7.30
- 8080/tcp Tomcat 9.0.30
```

### Phase 2: Real AI CVE Analysis (10-15s)

**Two AI Agents:**

1. **CVE Analyst** (OpenAI GPT-4o)
   - Analyzes service versions
   - Identifies specific CVEs
   - Calculates CVSS scores
   - Explains WHY vulnerable

2. **PoC Hunter** (OpenAI GPT-4o)
   - Searches GitHub for exploits
   - Checks ExploitDB
   - Finds Metasploit modules
   - Assesses attack complexity

### JSON-Based Agent Communication
```
reports/{chain_id}/agent_work/
├── scan_results.json      # Input to CVE Analyst
├── cve_analysis.json      # CVE Analyst → PoC Hunter
└── poc_results.json       # Final PoC findings
```

## 📦 Dependencies

Install all dependencies:
```bash
pip install -r requirements.txt
```

**Key packages:**
- `flask` - Web framework
- `crewai` - AI agent framework
- `langchain-openai` - OpenAI integration
- `langchain-anthropic` - Optional Anthropic support

## 📊 Example Output

### CVE Results (Sorted by Risk)
```
CVE-2021-44228 (CRITICAL) - CVSS 10.0
┌─────────────────────────────────┐
│ 🧠 AI Reasoning                 │
│ Why: Tomcat 9.0.30 uses Log4j   │
│ Evidence: Port 8080 service     │
│ PoC: GitHub - 3 repos found     │
│ Attack: LOW complexity          │
└─────────────────────────────────┘

CVE-2020-1938 (CRITICAL) - CVSS 9.8
┌─────────────────────────────────┐
│ 🧠 AI Reasoning                 │
│ Why: Ghostcat AJP vulnerability │
│ Evidence: Tomcat version match  │
│ PoC: ExploitDB EDB-48143        │
│ Attack: MEDIUM complexity       │
└─────────────────────────────────┘
```

## 🧠 AI Agent Architecture

```
┌─────────────┐
│ Port Scan   │ (Mock - 2s)
│   (Mock)    │
└──────┬──────┘
       │ scan_results.json
       ↓
┌─────────────┐
│ CVE Analyst │ (Real AI - 5-8s)
│  (GPT-4o)   │
└──────┬──────┘
       │ cve_analysis.json
       ↓
┌─────────────┐
│ PoC Hunter  │ (Real AI - 5-7s)
│  (GPT-4o)   │
└──────┬──────┘
       │ poc_results.json
       ↓
    Results
```

## 📁 Output Files

```
reports/{chain_id}/
├── scan.json              # Port scan results
├── vulnerabilities.json   # CVE + PoC info
└── agent_work/
    ├── scan_results.json
    ├── cve_analysis.json
    └── poc_results.json
```

## 🔬 Testing

### With OpenAI API Key
```bash
export OPENAI_API_KEY="sk-..."
pip install -r requirements.txt
python app.py
# Enter any target → Real AI analysis
```

### Without API Key
```bash
pip install -r requirements.txt
python app.py
# Enter any target → Fallback pattern matching
```

## 🐛 Troubleshooting

### No AI analysis?
```bash
# Check API key
echo $OPENAI_API_KEY

# Reinstall dependencies
pip install -r requirements.txt
```

### Import errors?
```bash
# Make sure all dependencies are installed
pip install -r requirements.txt

# Check Python version (3.8+ required)
python --version
```

### Results not showing?
- Check browser console (F12)
- Verify API responded: `curl localhost:5000/api/attack-chain/{id}/status`
- Check `reports/{chain_id}/` for JSON files

## 💡 Key Features

1. **OpenAI Integration** ✅
   - Uses GPT-4o-mini by default
   - Upgrade to GPT-4o for better results

2. **JSON Communication** ✅
   - Agents exchange data via files
   - Transparent data flow
   - Easy debugging

3. **PoC Hunting** ✅
   - GitHub repository search
   - ExploitDB entries
   - Metasploit modules

4. **Risk Sorting** ✅
   - CVEs sorted by CVSS score
   - Critical vulnerabilities first

## 🎯 Summary

**Just run:**
```bash
export OPENAI_API_KEY="sk-..."
pip install -r requirements.txt
python app.py
```

**Get:**
- ✅ Instant mock port scan
- ✅ Real AI CVE identification
- ✅ Real PoC hunting
- ✅ XAI explanations
- ✅ Risk-based sorting

---

**Version:** 5.0 (OpenAI Edition)
**Last Updated:** 2025-09-21
