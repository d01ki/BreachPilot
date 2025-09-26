# BreachPilot Professional Security Assessment Framework

## CrewAI Redesign - Enterprise Edition

BreachPilot has been completely redesigned using **CrewAI** multi-agent AI framework following official best practices for professional enterprise security assessments.

## 🚀 New Architecture

### CrewAI Multi-Agent System

The new architecture uses specialized AI agents working collaboratively:

- **Vulnerability Hunter**: Elite CVE discovery specialist
- **CVE Research Specialist**: Technical analysis and validation expert  
- **Security Analyst**: Business risk assessment and prioritization
- **Penetration Tester**: Exploitation strategy development
- **Report Writer**: Professional security documentation

### YAML Configuration

- `backend/agents.yaml` - Agent definitions with roles, goals, and backstories
- `backend/tasks.yaml` - Task definitions with context and workflows
- `backend/crew.py` - Main crew orchestration logic

## 📁 Project Structure

```
breachpilot/
├── backend/
│   ├── crews/                    # New CrewAI implementation
│   │   ├── security_crew.py      # Main security assessment crew
│   │   ├── legacy_crew.py        # Backwards compatibility wrapper
│   │   ├── main.py              # Orchestrator and example usage
│   │   └── utils/               # Utility classes
│   │       ├── cve_processor.py  # CVE processing and analysis
│   │       └── target_analyzer.py # Target system analysis
│   ├── agents.yaml              # Agent configuration
│   ├── tasks.yaml               # Task definitions
│   ├── config.py                # Updated configuration
│   ├── orchestrator.py          # Updated main orchestrator
│   └── ...
├── requirements.txt             # Updated dependencies
├── .env.example                # Environment template
└── README.md
```

## 🔧 Installation & Setup

### 1. Environment Setup

```bash
# Clone repository
git clone https://github.com/d01ki/BreachPilot.git
cd BreachPilot

# Switch to new branch
git checkout crewai-redesign-professional

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

Required environment variables:

```env
# Required for CrewAI
OPENAI_API_KEY=your_openai_api_key_here

# Optional for enhanced web search
SERPER_API_KEY=your_serper_api_key_here

# LLM Configuration
LLM_MODEL=gpt-4
LLM_TEMPERATURE=0.1
```

### 3. API Keys Setup

- **OpenAI API**: Required for CrewAI agents - Get from [OpenAI Platform](https://platform.openai.com/)
- **Serper API**: Optional for web search - Get from [Serper.dev](https://serper.dev/)

## 🎯 Usage

### Basic Usage

```python
from backend.crews import SecurityAssessmentCrew
from backend.models import NmapResult

# Initialize crew
crew = SecurityAssessmentCrew()

# Run assessment
result = crew.analyze_target("192.168.1.100", nmap_result)

print(f"Found {len(result.identified_cves)} vulnerabilities")
print(f"Risk Level: {result.risk_assessment}")
```

### Full Orchestration

```python
from backend.orchestrator import SecurityOrchestrator
from backend.models import ScanRequest

# Initialize orchestrator
orchestrator = SecurityOrchestrator()

# Create scan request
request = ScanRequest(
    target="192.168.1.100",
    scan_type="comprehensive",
    enable_exploitation=True
)

# Execute assessment
result = await orchestrator.execute_security_assessment(request)
```

### Legacy Compatibility

```python
# Existing code continues to work
from backend.agents.analyst_crew import AnalystCrew

analyst = AnalystCrew()
result = analyst.analyze_vulnerabilities(target_ip, nmap_result)
```

## 🔬 Key Features

### Professional CVE Analysis
- **Zerologon (CVE-2020-1472)** detection for Domain Controllers
- **EternalBlue (CVE-2017-0144)** analysis for SMB services
- **BlueKeep (CVE-2019-0708)** assessment for RDP services
- **Log4Shell (CVE-2021-44228)** detection for web applications
- Version-based vulnerability mapping

### Enterprise Reporting
- Executive summaries for C-level stakeholders
- Technical details for implementation teams
- Business risk assessments and financial impact
- Compliance and regulatory considerations

### Multi-Agent Collaboration
- Sequential task execution with context sharing
- Memory-enabled agents for better analysis
- Specialized tools per agent type
- Fallback mechanisms for reliability

## 🏗️ Architecture Benefits

### Modular Design
- **Separated concerns**: Each component has a specific responsibility
- **Easy maintenance**: Update individual agents without affecting others
- **Extensible**: Add new agents and tasks easily

### YAML Configuration
- **Version controlled**: Configuration changes tracked in git
- **Environment specific**: Different configs for dev/staging/prod
- **Non-developer friendly**: Security experts can modify behavior

### Professional Standards
- **Enterprise ready**: Built for large-scale security assessments
- **Reliable**: Comprehensive error handling and fallback mechanisms
- **Auditable**: Detailed logging and traceability

## 📊 Component Status

```python
# Check system status
orchestrator = SecurityOrchestrator()
status = orchestrator.get_orchestrator_status()

print("System Status:")
print(f"CrewAI: {'✅' if status['crewai']['crew_available'] else '❌'}")
print(f"OpenAI: {'✅' if status['config']['openai_configured'] else '❌'}")
print(f"Agents: {status['crewai']['agents_count']}")
```

## 🔄 Migration Guide

The new implementation maintains backwards compatibility:

### Existing Code
```python
# This continues to work unchanged
from backend.agents.analyst_crew import AnalystCrew
analyst = AnalystCrew()
result = analyst.analyze_vulnerabilities(target, nmap_result)
```

### New Recommended Approach
```python
# Use new modular implementation
from backend.crews import SecurityAssessmentCrew
crew = SecurityAssessmentCrew()
result = crew.analyze_target(target, nmap_result)
```

## 🛡️ Security Considerations

- **API Keys**: Store securely using environment variables
- **Network Access**: Ensure proper network segmentation for scanning
- **Logging**: Configure appropriate log levels for production
- **Rate Limiting**: Monitor API usage to avoid rate limits

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Issues**: Use GitHub Issues for bug reports and feature requests
- **Documentation**: Check the `docs/` folder for detailed documentation
- **Community**: Join our Discord server for community support

---

**Note**: This is a professional security assessment tool. Use responsibly and only on systems you own or have explicit permission to test.
