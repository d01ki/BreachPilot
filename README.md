# BreachPilot v2.0 - AI-Assisted Penetration Testing Platform

![BreachPilot Logo](https://img.shields.io/badge/BreachPilot-v2.0-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**BreachPilot** is an advanced AI-powered penetration testing automation platform that combines traditional security scanning with cutting-edge artificial intelligence. Specializing in CVE-2020-1472 (Zerologon) vulnerability assessment, it provides comprehensive automated testing with professional AI-generated reports.

## 🚀 Key Features

### 🤖 AI-Powered Analysis
- **CrewAI Multi-Agent System**: Specialized AI agents for different testing phases
- **Claude AI Integration**: Professional report generation and advanced reasoning
- **Intelligent Vulnerability Assessment**: Automated threat prioritization and analysis
- **Natural Language Processing**: Executive summaries and business impact analysis

### 🔍 Advanced Reconnaissance
- **Smart Network Scanning**: Nmap + NSE scripts with AI interpretation
- **Service Enumeration**: Automated service version detection and analysis
- **Active Directory Detection**: Specialized DC and Kerberos service identification
- **Vulnerability Pattern Recognition**: AI-driven security weakness identification

### 🎯 Exploit Research & Execution
- **Automated PoC Discovery**: GitHub and ExploitDB integration
- **Intelligent Exploit Ranking**: Multi-factor scoring algorithms
- **Controlled Exploitation**: Safe testing environment execution
- **Real-time Result Analysis**: AI-powered success/failure determination

### 📊 Professional Reporting
- **Claude-Generated Reports**: Comprehensive documentation with executive summaries
- **Multi-Format Output**: Professional PDF and Markdown reports
- **Business Impact Analysis**: Risk assessment and remediation guidance
- **Visual Dashboard**: Real-time progress tracking and results visualization

## 🏗️ Architecture

### Core Components
```
BreachPilot/
├── src/
│   ├── agents/
│   │   ├── ai_orchestrator.py      # Central AI coordination
│   │   ├── scan_agent.py           # Network reconnaissance
│   │   ├── poc_agent.py            # Exploit research
│   │   ├── exploit_agent.py        # Controlled exploitation  
│   │   └── report_agent.py         # AI report generation
│   └── utils/
│       └── config.py               # Configuration management
├── templates/                      # Web UI templates
├── static/                         # Frontend assets
└── reports/                        # Generated reports
```

### AI Agent Pipeline
1. **Vulnerability Scan Analyst** - Network analysis and threat identification
2. **Exploit Research Specialist** - PoC discovery and evaluation
3. **Exploit Execution Analyst** - Result analysis and impact assessment
4. **Security Report Writer** - Comprehensive documentation generation

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- Nmap (for network scanning)
- Git (for PoC repository cloning)

### Quick Start
```bash
# Clone the repository
git clone https://github.com/d01ki/BreachPilot.git
cd BreachPilot

# Switch to development branch
git checkout feature/dev_v2

# Install dependencies
pip install -r requirements.txt

# Configure API keys (see Configuration section)
export ANTHROPIC_API_KEY="your-claude-api-key"
export OPENAI_API_KEY="your-openai-api-key"  # Optional
export GITHUB_TOKEN="your-github-token"      # Optional

# Run the application
python app.py
```

### Docker Installation (Coming Soon)
```bash
docker run -p 5000:5000 -e ANTHROPIC_API_KEY=your-key d01ki/breachpilot:v2
```

## ⚙️ Configuration

### Required API Keys

#### 1. Anthropic Claude API (Required)
- **Purpose**: AI report generation and analysis
- **Get Key**: [console.anthropic.com](https://console.anthropic.com/)
- **Usage**: Primary AI model for vulnerability analysis

#### 2. OpenAI API (Optional)
- **Purpose**: Supplementary analysis and cross-validation
- **Get Key**: [platform.openai.com](https://platform.openai.com/api-keys)
- **Usage**: Additional reasoning capabilities

#### 3. GitHub Token (Optional)
- **Purpose**: Enhanced PoC discovery and research
- **Get Token**: [github.com/settings/tokens](https://github.com/settings/tokens)
- **Scope**: `read:public_repo`

### Web UI Configuration
1. Navigate to `http://localhost:5000/settings`
2. Enter your API keys
3. Use "Save & Test APIs" to verify configuration
4. Return to home page to start testing

## 🎯 Usage

### Basic Penetration Test
1. **Configure APIs**: Set up required API keys in Settings
2. **Target Selection**: Enter IP address or hostname
3. **Authorization**: Check "LAB ENVIRONMENT ONLY" if authorized
4. **Execute**: Click "Start Test" to begin automated assessment
5. **Monitor**: Real-time progress tracking with AI pipeline visualization
6. **Results**: Comprehensive reports with executive summaries

### Advanced Features
- **Real-time Progress**: Live updates of AI agent activities
- **Detailed Analysis**: Tab-based results with technical findings
- **Professional Reports**: Executive-ready documentation
- **API Integration**: RESTful endpoints for automation

## 🔒 CVE-2020-1472 (Zerologon) Specialization

### Detection Capabilities
- ✅ **Kerberos Service Detection** (Port 88/tcp)
- ✅ **Domain Controller Identification** 
- ✅ **Netlogon RPC Analysis**
- ✅ **Vulnerability Confirmation**

### Automated Assessment
- **CVSS 10.0 Risk Rating**: Critical severity highlighting
- **Business Impact Analysis**: Domain compromise implications
- **Remediation Guidance**: Microsoft patch recommendations
- **Professional Documentation**: Executive and technical reports

## 🤖 AI Agents Overview

### Vulnerability Scan Analyst
```python
Role: "Vulnerability Scan Analyst"
Goal: "Analyze network scan results to identify potential security vulnerabilities"
Tools: [ScanAnalysisTool]
```

### Exploit Research Specialist  
```python
Role: "Exploit Research Specialist"
Goal: "Research and evaluate Proof of Concept exploits for identified vulnerabilities"
Tools: [PoCSearchTool]
```

### Exploit Execution Analyst
```python
Role: "Exploit Execution Analyst" 
Goal: "Analyze exploit execution results to determine success and provide insights"
Tools: [ExploitAnalysisTool]
```

### Security Report Writer
```python
Role: "Security Report Writer"
Goal: "Generate comprehensive penetration testing reports"
Tools: [Claude API Direct Integration]
```

## 📊 Web Interface

### Modern UI Features
- **Glass Morphism Design**: Modern, professional interface
- **Real-time Updates**: Live progress tracking via WebSocket-like polling
- **Responsive Layout**: Mobile-friendly design
- **Dark Theme**: Eye-friendly professional appearance
- **Interactive Results**: Tabbed interface for detailed analysis

### Dashboard Components
- **Configuration Status**: API key validation indicators
- **Progress Pipeline**: Visual AI agent workflow tracking
- **Results Visualization**: Professional report presentation
- **Recent Tests**: Historical assessment overview

## 🔧 Development

### Technology Stack
- **Backend**: Flask (Python)
- **AI Framework**: CrewAI + Anthropic Claude + OpenAI
- **Frontend**: TailwindCSS + Vanilla JavaScript
- **Scanning**: python-nmap + NSE scripts
- **Reporting**: WeasyPrint (PDF) + Markdown

### Project Structure
```
BreachPilot/
├── app.py                    # Main Flask application
├── requirements.txt          # Python dependencies
├── AGENTS.md                # AI agent documentation
├── src/
│   ├── agents/              # AI agent implementations
│   └── utils/               # Utility functions
├── templates/               # Jinja2 templates
│   ├── base.html           # Base template
│   ├── index.html          # Home page
│   ├── settings.html       # Configuration
│   ├── status.html         # Progress tracking
│   ├── results.html        # Detailed results
│   └── error.html          # Error pages
└── static/                 # Static assets
```

### Contributing
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 🛡️ Security & Ethics

### Responsible Usage
- **⚠️ LAB ENVIRONMENTS ONLY**: Never test against unauthorized systems
- **📋 Proper Authorization**: Ensure legal permission before testing
- **🔒 Data Protection**: All processing occurs locally
- **🎯 Controlled Exploitation**: Safe, sandboxed testing environment

### Legal Compliance
- Penetration testing authorization required
- Responsible vulnerability disclosure
- Compliance with local cybersecurity laws
- Professional ethical standards

## 📈 Performance

### Scalability Features
- **Asynchronous Processing**: Background job execution
- **Resource Management**: Efficient memory and CPU usage
- **Progress Tracking**: Real-time status updates
- **Error Recovery**: Graceful failure handling

### Optimization
- **API Rate Limiting**: Respectful service usage
- **Caching**: Intelligent result storage
- **Parallel Processing**: Where applicable
- **Resource Cleanup**: Automatic job management

## 🐛 Troubleshooting

### Common Issues

#### API Configuration
```bash
# Verify API key format
export ANTHROPIC_API_KEY="sk-ant-api03-..."  # Must start with sk-ant-
export OPENAI_API_KEY="sk-..."               # Must start with sk-
```

#### Network Scanning
```bash
# Ensure Nmap is installed
nmap --version

# Check network connectivity
ping target-ip
```

#### Dependencies
```bash
# Install missing packages
pip install --upgrade -r requirements.txt

# Check Python version
python --version  # Should be 3.8+
```

### Debug Mode
```bash
export FLASK_DEBUG=true
python app.py
```

## 📚 Documentation

- **[AI Agents Guide](AGENTS.md)**: Comprehensive agent documentation
- **[API Reference](docs/api.md)**: RESTful endpoint documentation
- **[Configuration Guide](docs/config.md)**: Setup and customization
- **[Security Guidelines](docs/security.md)**: Best practices and ethics

## 🗺️ Roadmap

### v2.1 (Upcoming)
- [ ] Additional CVE support (EternalBlue, BlueKeep)
- [ ] Advanced AI model integration (GPT-4, Claude-3)
- [ ] Cloud deployment options
- [ ] Team collaboration features

### v3.0 (Future)
- [ ] Machine learning model training
- [ ] Automated patch management
- [ ] Threat intelligence integration
- [ ] Advanced behavioral analysis

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Acknowledgments

- **Anthropic**: Claude AI integration and advanced reasoning
- **CrewAI**: Multi-agent framework and collaboration
- **OpenAI**: Supplementary AI capabilities
- **Nmap Project**: Network scanning foundation
- **Security Community**: Vulnerability research and disclosure

## 📞 Support

- **GitHub Issues**: [Report bugs and feature requests](https://github.com/d01ki/BreachPilot/issues)
- **Documentation**: [Comprehensive guides and tutorials](docs/)
- **Community**: [Discord/Slack community channels](#)

---

**⚠️ IMPORTANT DISCLAIMER**: BreachPilot is designed for authorized penetration testing in laboratory environments only. Users are responsible for ensuring proper authorization and compliance with applicable laws and regulations. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.

**🔬 RESEARCH PURPOSE**: This tool is developed for cybersecurity research, education, and authorized security assessments. It aims to improve defensive capabilities through automated vulnerability identification and assessment.
