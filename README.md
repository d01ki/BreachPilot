# Professional BreachPilot - AI-Powered Security Assessment Framework

## 🚀 Quick Start

### Installation & Setup
```bash
git clone https://github.com/d01ki/BreachPilot.git
cd BreachPilot
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python3 app.py
```

### Basic Configuration
```bash
# Optional: Set up CrewAI (for advanced features)
export OPENAI_API_KEY="your_openai_api_key_here"

# The application will work with fallback functionality even without AI keys
```

## 🎯 Professional Features

### Core Capabilities
- **Network Service Discovery**: Comprehensive port scanning and service enumeration
- **Professional CVE Analysis**: Expert-level vulnerability assessment (max 5 CVEs per scan)
- **Business Impact Assessment**: Executive-level risk evaluation and CVSS scoring
- **CrewAI Integration**: Multi-agent AI collaboration for enhanced analysis
- **Automated Reporting**: Professional security assessment reports

### Security Assessment Workflow
1. **Network Discovery**: Identify open services and system fingerprints
2. **Vulnerability Analysis**: Professional CVE identification with technical details
3. **Exploit Research**: Automated PoC discovery and validation
4. **Proof of Concept Execution**: Controlled exploit testing (optional)
5. **Professional Reporting**: Executive and technical documentation

## 🔧 Configuration

### Environment Variables
```bash
# Optional - for enhanced AI features
OPENAI_API_KEY=your_openai_key_here
LLM_MODEL=gpt-4
LLM_TEMPERATURE=0.1

# Application settings
DEBUG_MODE=false
LOG_LEVEL=INFO
DATA_DIR=./data
```

## 📊 Usage Examples

### Basic Security Assessment
```bash
# Start the application
python3 app.py

# Navigate to http://localhost:8000
# Enter target IP address
# Run assessment workflow
```

### Advanced Features
- **CVE Limitation**: Maximum 5 professionally analyzed CVEs per assessment
- **Business Context**: Each vulnerability includes business impact assessment
- **Technical Depth**: Detailed technical analysis with remediation guidance
- **Professional Reporting**: Automated generation of executive and technical reports

## 🛡️ Security & Compliance

### Professional Standards
- Industry-standard vulnerability assessment methodologies
- CVSS v3.1 scoring and risk classification
- Professional documentation and reporting
- Executive-level business impact analysis

**BreachPilot represents a complete transformation from a basic tool to a professional security assessment platform, suitable for enterprise engagements, security consulting, and academic research.**