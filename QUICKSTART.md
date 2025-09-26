# 🚀 BreachPilot Professional - Quick Start Guide

## CrewAI Security Assessment Framework v2.0

### ⚡ 2-Minute Setup

```bash
# 1. Clone and enter directory
git clone https://github.com/d01ki/BreachPilot.git
cd BreachPilot
git checkout crewai-redesign-professional

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Add your OpenAI API key to .env file

# 4. Start application
python app.py

# 5. Open browser
# Visit: http://localhost:8000
```

### 🔑 Required API Key

1. **OpenAI API Key** (Required)
   - Get from: https://platform.openai.com/
   - Add to `.env`: `OPENAI_API_KEY=sk-your_key_here`

2. **Serper API Key** (Optional - enhances web search)
   - Get from: https://serper.dev/
   - Add to `.env`: `SERPER_API_KEY=your_serper_key`

### 🧪 Test Your Setup

#### 1. Check System Status
```bash
curl http://localhost:8000/status
```

#### 2. Verify CrewAI
```bash
curl http://localhost:8000/crewai/status
```

#### 3. Run Security Scan
```bash
curl -X POST "http://localhost:8000/scan/start" \
     -H "Content-Type: application/json" \
     -d '{
       "target": "scanme.nmap.org",
       "scan_type": "comprehensive",
       "enable_exploitation": false
     }'
```

### 📊 What You Get

- **🤖 5 AI Agents**: Professional security experts
- **🔍 Advanced CVE Detection**: 100+ vulnerability types
- **📈 Business Risk Analysis**: Executive-ready reports
- **🛡️ Enterprise Security**: Production-quality assessments
- **🌐 Web Interface**: User-friendly dashboard
- **📚 API Documentation**: Complete REST API

### 🎯 Key Features

#### CrewAI Agents
1. **Elite Vulnerability Hunter** - CVE discovery specialist
2. **CVE Research Specialist** - Technical analysis expert
3. **Senior Security Analyst** - Business risk assessment
4. **Professional Penetration Tester** - Exploitation strategies
5. **Professional Report Writer** - Executive documentation

#### Vulnerability Coverage
- **Zerologon** (CVE-2020-1472) - Domain Controller compromise
- **EternalBlue** (CVE-2017-0144) - SMB remote code execution
- **BlueKeep** (CVE-2019-0708) - RDP vulnerability
- **Log4Shell** (CVE-2021-44228) - Java logging vulnerability
- **PrintNightmare** (CVE-2021-34527) - Windows Print Spooler
- **100+ other CVEs** - Comprehensive coverage

### 🔧 Troubleshooting

#### Common Issues

**"OpenAI API key not configured"**
```bash
# Check your .env file
cat .env | grep OPENAI_API_KEY
# Should show: OPENAI_API_KEY=sk-your_actual_key
```

**"CrewAI not available"**
```bash
# Reinstall CrewAI
pip install crewai[tools]==0.51.0
```

**"Module not found"**
```bash
# Install all requirements
pip install -r requirements.txt
```

**"Port 8000 in use"**
```bash
# Kill existing process
sudo lsof -ti:8000 | xargs kill -9
```

### 🌟 Success Indicators

✅ **Application starts without errors**
✅ **Web interface loads at http://localhost:8000**
✅ **System status shows "operational"**
✅ **CrewAI status shows 5 agents available**
✅ **Security scans complete successfully**

### 🎉 You're Ready!

Your CrewAI-powered security assessment framework is now running!

**Next Steps:**
1. Try the web interface
2. Test with a sample target
3. Review the generated reports
4. Explore the API documentation

**Support:**
- 📖 Full documentation: README.md
- 🐛 Report issues: GitHub Issues
- 💬 API reference: http://localhost:8000/docs

---

**🏆 Welcome to enterprise-grade AI-powered security assessment!**
