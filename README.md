# BreachPilot Professional - CrewAI Security Assessment

## Quick Start

```bash
# 1. Setup
git clone https://github.com/d01ki/BreachPilot.git
cd BreachPilot
git checkout crewai-redesign-professional
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Add your OpenAI API key to .env

# 3. Run
python app.py
# Open: http://localhost:8000
```

## Features

- **🤖 5 AI Agents**: Elite security experts using CrewAI
- **🔍 CVE Detection**: Zerologon, EternalBlue, BlueKeep, Log4Shell
- **📊 Business Reports**: Executive summaries and risk analysis
- **🌐 Web Interface**: User-friendly dashboard
- **📚 REST API**: Complete documentation at `/docs`

## API Example

```bash
# Start scan
curl -X POST "http://localhost:8000/scan/start" \
     -H "Content-Type: application/json" \
     -d '{
       "target": "scanme.nmap.org",
       "scan_type": "comprehensive"
     }'

# Check status: /scan/{id}/status
# Get results: /scan/{id}/results
```

## Requirements

- Python 3.8+
- OpenAI API key (required)
- 2GB RAM

## License

MIT License
