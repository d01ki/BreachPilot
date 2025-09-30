# Installation Guide - Attack Scenario Generation

## System Requirements

- **OS**: Linux (Ubuntu 20.04+, Kali, Debian) or macOS
- **Python**: 3.9 or higher
- **Docker**: Latest version (for sandbox execution)
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Disk**: 10GB free space

## Quick Installation

### 1. Clone Repository
```bash
git clone https://github.com/d01ki/BreachPilot.git
cd BreachPilot

# Checkout attack scenario feature branch
git checkout feature/attack-scenario-generator
```

### 2. Install Dependencies
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install system tools
sudo apt update
sudo apt install -y nmap docker.io

# Add user to docker group (avoid sudo)
sudo usermod -aG docker $USER
newgrp docker
```

### 3. Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit .env file
nano .env
```

**Required Configuration**:
```bash
# OpenAI API Key (optional, for LLM scenario generation)
OPENAI_API_KEY=sk-your-key-here

# Allowed targets (CRITICAL - only these IPs can be tested)
ALLOWED_TARGETS=192.168.1.0/24,10.0.0.0/8

# Data directory
DATA_DIR=./data
REPORTS_DIR=./reports
```

### 4. Configure Allowed Targets (IMPORTANT)

**Edit** `backend/api/scenario_routes.py`:

```python
scenario_orchestrator = ScenarioOrchestrator(
    allowed_targets=[
        "192.168.1.100",      # Specific IP
        "192.168.1.0/24",     # Subnet
        "10.0.0.0/8",         # Large network
    ],
    use_llm=True
)
```

⚠️ **Only these targets can be attacked!**

### 5. Start Application
```bash
# Start server
python app.py

# Or with uvicorn directly
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### 6. Verify Installation
```bash
# Check API health
curl http://localhost:8000/health

# Check Docker
docker ps

# Check Nmap
nmap --version
```

## Docker Setup (For Sandbox Execution)

### Install Docker
```bash
# Ubuntu/Debian
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker
```

### Test Docker
```bash
# Run test container
docker run hello-world

# Verify user permissions
docker ps
```

## Troubleshooting

### Issue: Docker permission denied
```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Or run with sudo (not recommended)
sudo python app.py
```

### Issue: Nmap not found
```bash
# Install Nmap
sudo apt install nmap

# Verify installation
which nmap
```

### Issue: Port 8000 already in use
```bash
# Use different port
uvicorn backend.main:app --host 0.0.0.0 --port 8001
```

### Issue: OpenAI API key not working
```bash
# LLM is optional - tool works without it
# Rule-based scenario generation will be used

# Verify API key
echo $OPENAI_API_KEY
```

## Testing the Installation

### Run Sample Scan
```bash
# Start scan against allowed target
curl -X POST http://localhost:8000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"target_ip": "192.168.1.100"}'

# Run Nmap
curl -X POST http://localhost:8000/api/scan/{session_id}/nmap

# Generate attack graph
curl -X POST http://localhost:8000/api/scenario/{session_id}/generate-graph
```

### Expected Output
```json
{
  "success": true,
  "attack_graph": {
    "total_nodes": 10,
    "total_vulnerabilities": 2
  }
}
```

## Next Steps

1. **Read Documentation**: [ATTACK_SCENARIO_GENERATION.md](docs/ATTACK_SCENARIO_GENERATION.md)
2. **Try Demo Workflow**: [README_ARSENAL.md](README_ARSENAL.md)
3. **Review API**: [API_REFERENCE.md](docs/API_REFERENCE.md)

## Security Considerations

### Before First Use

1. ✅ Configure `ALLOWED_TARGETS` whitelist
2. ✅ Verify Docker isolation
3. ✅ Review generated scenarios before approval
4. ✅ Test on isolated lab environment first
5. ✅ Obtain written authorization for all targets

### Production Deployment

```bash
# Use reverse proxy (nginx)
# Enable HTTPS
# Implement authentication
# Restrict network access
# Enable audit logging
```

## Support

- **Issues**: https://github.com/d01ki/BreachPilot/issues
- **Discussions**: https://github.com/d01ki/BreachPilot/discussions
- **Documentation**: [docs/](docs/)