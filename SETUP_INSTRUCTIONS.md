# 🚀 BreachPilot Professional Setup Instructions

## CrewAI Architecture - Enterprise Edition v2.0

### ⚙️ Quick Setup (5 Minutes)

1. **Clone Repository**
```bash
git clone https://github.com/d01ki/BreachPilot.git
cd BreachPilot
git checkout crewai-redesign-professional
```

2. **Install Dependencies**
```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
```

3. **Configure Environment**
```bash
# Copy environment template
cp .env.example .env

# Edit with your API keys
nano .env  # or use your preferred editor
```

4. **Required API Keys**
```env
# REQUIRED - Get from https://platform.openai.com/
OPENAI_API_KEY=sk-your_actual_openai_key_here

# OPTIONAL - Get from https://serper.dev/ (enhances web search)
SERPER_API_KEY=your_serper_key_here
```

5. **Start Application**
```bash
python app.py
```

6. **Verify Setup**
- Visit: http://localhost:8000
- Check API docs: http://localhost:8000/docs
- System status: http://localhost:8000/status

---

### 🗘️ Detailed Configuration

#### OpenAI API Setup
1. Go to [OpenAI Platform](https://platform.openai.com/)
2. Sign up or log in
3. Navigate to API Keys section
4. Create new secret key
5. Copy key to `.env` file
6. **Important**: Ensure you have credits/billing set up

#### Serper API Setup (Optional)
1. Go to [Serper.dev](https://serper.dev/)
2. Sign up for free account
3. Get your API key
4. Add to `.env` file
5. This enhances web search capabilities

#### Environment Variables
```env
# Core Settings
OPENAI_API_KEY=your_key_here
SERPER_API_KEY=your_serper_key  # Optional
LLM_MODEL=gpt-4
LLM_TEMPERATURE=0.1

# CrewAI Settings
CREWAI_MEMORY_ENABLED=true
CREWAI_VERBOSE=true
MAX_CVES_PER_ANALYSIS=7
ASSESSMENT_TIMEOUT=300

# Application Settings
DEBUG=false
LOG_LEVEL=INFO
```

---

### 🧪 Testing Your Setup

#### 1. System Health Check
```bash
curl http://localhost:8000/health
```

#### 2. CrewAI Status Check
```bash
curl http://localhost:8000/crewai/status
```

#### 3. Start Test Security Scan
```bash
curl -X POST "http://localhost:8000/scan/start" \
     -H "Content-Type: application/json" \
     -d '{
       "target": "scanme.nmap.org",
       "scan_type": "comprehensive",
       "enable_exploitation": false
     }'
```

#### 4. Python Test
```python
from backend.crews import SecurityAssessmentCrew
from backend.models import NmapResult

# Test CrewAI initialization
crew = SecurityAssessmentCrew()
print("CrewAI Status:", crew.get_crew_status())

# Test configuration validation
validation = crew.validate_configuration()
print("Configuration:", validation)
```

---

### 🐛 Troubleshooting

#### Common Issues

**1. "OpenAI API key not configured"**
```bash
# Check your .env file
cat .env | grep OPENAI_API_KEY

# Make sure the key starts with 'sk-'
# Verify credits at https://platform.openai.com/usage
```

**2. "CrewAI not available"**
```bash
# Reinstall CrewAI
pip uninstall crewai
pip install crewai[tools]==0.51.0

# Check installation
python -c "import crewai; print(crewai.__version__)"
```

**3. "Module not found" errors**
```bash
# Install all requirements
pip install -r requirements.txt

# Check virtual environment
which python
which pip
```

**4. "SerperDevTool not working"**
```bash
# This is optional - the system will work without it
# Check SERPER_API_KEY in .env if you want enhanced search
```

**5. Port 8000 already in use**
```bash
# Kill existing process
sudo lsof -ti:8000 | xargs kill -9

# Or use different port
uvicorn backend.main:app --host 0.0.0.0 --port 8001
```

#### Log Analysis
```bash
# Check application logs
tail -f logs/breachpilot.log  # if logging to file

# Or run with debug mode
DEBUG=true LOG_LEVEL=DEBUG python app.py
```

---

### 📊 System Requirements

#### Minimum Requirements
- Python 3.8+
- 2GB RAM
- 1GB disk space
- Internet connection
- OpenAI API access with credits

#### Recommended Requirements
- Python 3.10+
- 4GB RAM
- 2GB disk space
- Fast internet connection
- OpenAI API with GPT-4 access
- Serper API for enhanced search

#### Operating Systems
- ✅ Linux (Ubuntu 20.04+)
- ✅ macOS (10.15+)
- ✅ Windows 10/11 with WSL2
- ✅ Docker (all platforms)

---

### 🐳 Docker Setup (Alternative)

```bash
# Build image
docker build -t breachpilot .

# Run with environment file
docker run -p 8000:8000 --env-file .env breachpilot

# Or run with docker-compose
docker-compose up
```

---

### 🔧 Advanced Configuration

#### Custom CrewAI Configuration
Edit `backend/agents.yaml` and `backend/tasks.yaml` to customize:
- Agent personalities and expertise
- Task descriptions and workflows
- Context sharing between tasks
- Output expectations

#### Performance Tuning
```env
# Increase timeouts for complex scans
ASSESSMENT_TIMEOUT=600
NMAP_TIMEOUT=600

# Adjust LLM settings
LLM_TEMPERATURE=0.05  # More deterministic
MAX_CVES_PER_ANALYSIS=10  # More thorough analysis
```

#### Security Hardening
```env
# Production settings
DEBUG=false
LOG_LEVEL=WARNING
CREWAI_VERBOSE=false

# Add security headers (if deploying)
ALLOWED_HOSTS=yourdomain.com
SECRET_KEY=your_secure_secret_key
```

---

### 🎆 Success!

If you see this page, your CrewAI security assessment framework is ready:
- 🤖 **5 AI Agents**: Professional security experts
- 🔍 **Advanced CVE Detection**: 100+ vulnerability types
- 📊 **Executive Reporting**: Business-ready analysis
- 🔒 **Enterprise Security**: Production-quality assessments

**Next Steps:**
1. Try the web interface at http://localhost:8000
2. Test the API with sample scans
3. Review the generated reports
4. Customize agents for your specific needs

**Support:**
- Documentation: Check README.md and CHANGELOG.md
- Issues: Use GitHub Issues for bugs
- API Reference: http://localhost:8000/docs

---

**🎉 Welcome to enterprise-grade AI-powered security assessment!**
