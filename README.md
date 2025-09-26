# BreachPilot Professional Security Assessment Framework

## 🚨 **CrewAI Redesign - Enterprise Edition** 🚨

> **⚠️ IMPORTANT**: This branch contains the complete CrewAI redesign. See [FINAL_CLEANUP_REPORT.md](FINAL_CLEANUP_REPORT.md) for cleanup details.

BreachPilot has been completely redesigned using **CrewAI** multi-agent AI framework following official best practices for professional enterprise security assessments.

## 🚀 What's New in v2.0

### 🤖 CrewAI Multi-Agent System

The new architecture uses **5 specialized AI agents** working collaboratively:

- 🎯 **Elite Vulnerability Hunter**: CVE discovery specialist with 15+ years experience
- 🔬 **CVE Research Specialist**: Technical analysis and validation expert  
- 📊 **Senior Security Analyst**: Business risk assessment and prioritization
- 🔓 **Professional Penetration Tester**: Exploitation strategy development
- 📝 **Professional Report Writer**: Enterprise security documentation

### 📁 Clean Project Structure

```
breachpilot/
├── 📄 README.md                     # This file - main documentation
├── 📄 CHANGELOG.md                  # Complete version history  
├── 📄 FINAL_CLEANUP_REPORT.md       # Cleanup documentation
├── ⚙️ .env.example                  # Environment template
├── 📦 requirements.txt              # Updated CrewAI dependencies
├── 🐍 app.py                        # Main application entry
└── 🏗️ backend/
    ├── 🤖 crews/                     # NEW: CrewAI implementation
    │   ├── security_crew.py          # Main security assessment crew
    │   ├── legacy_crew.py            # Backwards compatibility wrapper
    │   ├── main.py                   # Orchestrator and examples
    │   └── utils/                    # Utility classes
    ├── 📋 agents.yaml                # Agent configurations
    ├── 📋 tasks.yaml                 # Task definitions
    ├── ⚙️ config.py                  # Updated configuration
    ├── 🎛️ orchestrator.py            # Updated orchestrator
    └── [existing modules...]         # Other backend components
```

## 🔧 Quick Setup

### 1. Clone & Install
```bash
git clone https://github.com/d01ki/BreachPilot.git
cd BreachPilot
git checkout crewai-redesign-professional
pip install -r requirements.txt
```

### 2. Configure API Keys
```bash
cp .env.example .env
# Edit .env file:
```

```env
# Required for CrewAI
OPENAI_API_KEY=your_openai_api_key_here

# Optional for enhanced web search
SERPER_API_KEY=your_serper_api_key_here

# LLM Configuration
LLM_MODEL=gpt-4
LLM_TEMPERATURE=0.1
```

### 3. Run Application
```bash
python app.py
```

Visit `http://localhost:8000` to access the web interface.

## 💻 Usage Examples

### New CrewAI Approach (Recommended)
```python
from backend.crews import SecurityAssessmentCrew
from backend.models import NmapResult

# Initialize the professional security crew
crew = SecurityAssessmentCrew()

# Run comprehensive analysis
result = crew.analyze_target("192.168.1.100", nmap_result)

print(f"Found {len(result.identified_cves)} vulnerabilities")
print(f"Risk Level: {result.risk_assessment}")
```

### Legacy Compatibility (Still Works)
```python
# Existing code continues to work unchanged
from backend.agents.analyst_crew import AnalystCrew

analyst = AnalystCrew()
result = analyst.analyze_vulnerabilities(target_ip, nmap_result)
```

### Full Orchestration
```python
from backend.orchestrator import SecurityOrchestrator
from backend.models import ScanRequest

# Professional security assessment
orchestrator = SecurityOrchestrator()

request = ScanRequest(
    target="192.168.1.100",
    scan_type="comprehensive",
    enable_exploitation=True
)

result = await orchestrator.execute_security_assessment(request)
```

## 🎯 Key Features

### 🔍 Advanced CVE Detection
- **Zerologon (CVE-2020-1472)**: Domain Controller compromise
- **EternalBlue (CVE-2017-0144)**: SMB remote code execution
- **BlueKeep (CVE-2019-0708)**: RDP vulnerability
- **Log4Shell (CVE-2021-44228)**: Java logging vulnerability
- **PrintNightmare (CVE-2021-34527)**: Windows Print Spooler
- **SMBGhost (CVE-2020-0796)**: SMBv3 compression

### 📊 Enterprise Reporting
- Executive summaries for C-level stakeholders
- Technical implementation details
- Business risk assessments with financial impact
- Regulatory compliance considerations
- Actionable remediation roadmaps

### 🏗️ Professional Architecture
- **Modular Design**: Easy to maintain and extend
- **YAML Configuration**: Version-controlled settings
- **Memory-Enabled Agents**: Better contextual analysis
- **Fallback Mechanisms**: Reliable operation
- **100% Backwards Compatible**: No breaking changes

## 📈 System Status Check

```python
from backend.orchestrator import SecurityOrchestrator

orchestrator = SecurityOrchestrator()
status = orchestrator.get_orchestrator_status()

print("🤖 CrewAI Status:")
print(f"Agents Available: {status['crewai']['agents_count']}")
print(f"OpenAI Configured: {'✅' if status['config']['openai_configured'] else '❌'}")
print(f"Serper Configured: {'✅' if status['config']['serper_configured'] else '⚠️ Optional'}")
```

## 🔄 Migration Guide

### No Changes Required
Your existing code will continue to work without any modifications:

```python
# This still works exactly the same
from backend.agents.analyst_crew import AnalystCrew
analyst = AnalystCrew()
result = analyst.analyze_vulnerabilities(target, nmap_result)
```

### Gradual Migration
When ready, migrate to the new CrewAI system for enhanced capabilities:

```python
# New enhanced approach
from backend.crews import SecurityAssessmentCrew
crew = SecurityAssessmentCrew()
result = crew.analyze_target(target, nmap_result)
```

## 🗂️ API Keys Setup

### OpenAI API (Required)
1. Visit [OpenAI Platform](https://platform.openai.com/)
2. Create API key
3. Add to `.env`: `OPENAI_API_KEY=sk-...`

### Serper API (Optional - Enhances Web Search)
1. Visit [Serper.dev](https://serper.dev/)
2. Get free API key
3. Add to `.env`: `SERPER_API_KEY=...`

## 🧹 Project Cleanup

**Note**: This branch has been cleaned up to remove redundant files. See [FINAL_CLEANUP_REPORT.md](FINAL_CLEANUP_REPORT.md) for details on removed files.

### Removed Files (~85KB)
- Legacy documentation files (`*_FIX.md`, `*_CHANGELOG.md`)
- Development scripts (`*.sh`)
- Test files (`frontend_test_section.html`)

### Core Files Retained
- ✅ **README.md** (this file) - Primary documentation
- ✅ **CHANGELOG.md** - Complete version history
- ✅ **FINAL_CLEANUP_REPORT.md** - Cleanup documentation
- ✅ All functional code and configuration files

## 🚀 What Makes This Special?

### 1. **Official CrewAI Best Practices**
- Follows CrewAI documentation patterns exactly
- YAML-based configuration for maintainability
- Sequential task execution with context sharing

### 2. **Enterprise Grade**
- Professional agent personas with extensive backstories
- Business-focused risk assessments
- Executive-level reporting
- Comprehensive error handling

### 3. **Zero Breaking Changes**
- All existing code continues to work
- Gradual migration path available
- Legacy wrappers maintain compatibility

### 4. **Modular & Extensible**
- Add new agents through YAML configuration
- Utility classes for common operations
- Clean separation of concerns

## 📚 Documentation

- **[CHANGELOG.md](CHANGELOG.md)**: Complete version history with migration examples
- **[FINAL_CLEANUP_REPORT.md](FINAL_CLEANUP_REPORT.md)**: Project cleanup details
- **[agents.yaml](backend/agents.yaml)**: Agent configurations
- **[tasks.yaml](backend/tasks.yaml)**: Task definitions

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open Pull Request

## 🛡️ Security & Ethics

- **Authorized Testing Only**: Use only on systems you own or have explicit permission to test
- **API Key Security**: Store keys securely using environment variables
- **Responsible Disclosure**: Report vulnerabilities responsibly
- **Educational Purpose**: Designed for learning and authorized security assessments

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Issues**: Use GitHub Issues for bug reports and feature requests
- **Documentation**: Check this README and linked documents
- **API Issues**: Verify your OpenAI API key and credits
- **Configuration**: Review `.env.example` for proper setup

---

**🎉 Ready to explore enterprise-grade security assessment with AI agents? Get started with the setup instructions above!**

> **Professional Security Assessment Framework** - Now powered by CrewAI multi-agent collaboration
