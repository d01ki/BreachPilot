# BreachPilot - Professional Security Assessment Framework

🛡️ Enterprise-grade penetration testing framework powered by CrewAI multi-agent collaboration.

## ✨ Features

- **Real Network Scanning**: Integrated nmap for comprehensive port and service discovery
- **AI-Powered Analysis**: CrewAI multi-agent system for intelligent vulnerability assessment
- **Clean UI**: Modern, streamlined interface for professional security testing
- **Production Ready**: Real IP scanning with proper error handling
- **Automated Workflow**: Seamless integration from scanning to reporting

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- nmap installed on your system
- OpenAI API key

### Installation

```bash
# Clone the repository
git clone https://github.com/d01ki/BreachPilot.git
cd BreachPilot
git checkout crewai-redesign-professional

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your OpenAI API key
```

### Configuration

Edit `.env` file:

```env
OPENAI_API_KEY=your_openai_api_key_here
LLM_MODEL=gpt-4o-mini
SERPER_API_KEY=optional_for_web_search
```

### Running

```bash
# Start the application
python app.py

# Or use uvicorn directly
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

Access the web interface at: http://localhost:8000

## 📖 Usage

1. **Start a Scan**
   - Enter target IP address (e.g., 192.168.1.100)
   - Click "スキャン開始" (Start Scan)

2. **Network Scan**
   - Click "実行" (Execute) in the Network Scan section
   - Wait for nmap to discover services and ports

3. **Vulnerability Analysis**
   - After network scan completes, click "実行" in Vulnerability Analysis
   - CrewAI agents will analyze discovered services
   - AI will identify potential CVEs and security issues

4. **Download Results**
   - Click "結果をダウンロード" to export assessment results as JSON

## 🏗️ Architecture

```
BreachPilot/
├── app.py                 # Main application entry point
├── backend/
│   ├── main.py           # FastAPI application
│   ├── orchestrator.py   # Security assessment orchestrator
│   ├── config.py         # Configuration management
│   ├── models.py         # Data models
│   ├── scanners/
│   │   └── nmap_scanner.py  # Real nmap integration
│   ├── crews/
│   │   └── security_crew.py # CrewAI agents
│   └── agents/
│       └── ...           # Individual agent definitions
├── frontend/
│   ├── index.html        # Web interface
│   └── static/
│       └── app.js        # Vue.js application
└── data/                 # Scan results storage
```

## 🤖 CrewAI Agents

1. **Vulnerability Hunter** - Discovers security vulnerabilities
2. **CVE Research Specialist** - Researches CVE details
3. **Security Analyst** - Analyzes risk and impact
4. **Penetration Tester** - Evaluates exploitability
5. **Report Writer** - Generates comprehensive reports

## 🔧 API Endpoints

- `POST /api/scan/start` - Start security assessment
- `POST /api/scan/{session_id}/nmap` - Execute nmap scan
- `POST /api/scan/{session_id}/analyze` - Run vulnerability analysis
- `GET /api/scan/{session_id}/status` - Check scan status
- `GET /api/scan/{session_id}/results` - Get complete results
- `GET /health` - Health check
- `GET /status` - System status

## 📝 Configuration Options

### Environment Variables

- `OPENAI_API_KEY` - OpenAI API key (required)
- `LLM_MODEL` - LLM model to use (default: gpt-4o-mini)
- `SERPER_API_KEY` - Serper API for web search (optional)
- `DEBUG` - Enable debug mode (default: false)
- `LOG_LEVEL` - Logging level (default: INFO)
- `NMAP_TIMEOUT` - Nmap scan timeout in seconds (default: 300)
- `ASSESSMENT_TIMEOUT` - Analysis timeout in seconds (default: 600)

## 🛠️ Development

### Running in Development Mode

```bash
# Enable debug mode
export DEBUG=true

# Start with auto-reload
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=backend
```

## 🔒 Security Considerations

- **Authorization**: Always ensure proper authorization before scanning
- **Legal**: Only scan systems you own or have explicit permission to test
- **Network**: Be aware of network policies and IDS/IPS systems
- **Rate Limiting**: Adjust scan intensity to avoid overwhelming targets

## 📊 Output Format

Results are exported in JSON format:

```json
{
  "session_id": "scan_20250102_120000_192_168_1_100",
  "target_ip": "192.168.1.100",
  "timestamp": "2025-01-02T12:00:00Z",
  "network_scan": {
    "services": [...],
    "open_ports": [...],
    "os_detection": {...}
  },
  "vulnerability_analysis": {
    "identified_cves": [...],
    "risk_assessment": {...},
    "recommendations": [...]
  },
  "execution_time": 120.5
}
```

## 🐛 Troubleshooting

### Nmap Not Found

```bash
# Install nmap
# Ubuntu/Debian
sudo apt-get install nmap

# macOS
brew install nmap

# Windows
# Download from https://nmap.org/download.html
```

### OpenAI API Error

- Verify API key is correct in `.env`
- Check API key has sufficient credits
- Ensure proper network connectivity

### Port Already in Use

```bash
# Change port in app.py or use environment variable
export PORT=8080
python app.py
```

## 📚 Documentation

- API Documentation: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- System Status: http://localhost:8000/status

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is for educational and authorized security testing purposes only.

## ⚠️ Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. Unauthorized access to computer systems is illegal.

## 🔗 Links

- [CrewAI Documentation](https://docs.crewai.com/)
- [Nmap Documentation](https://nmap.org/book/man.html)
- [OpenAI API](https://platform.openai.com/docs/)

## 📧 Support

For issues and questions:
- Open an issue on GitHub
- Check existing documentation
- Review closed issues for solutions

---

**Version**: 2.0.0  
**Architecture**: CrewAI Multi-Agent System  
**Status**: Production Ready
