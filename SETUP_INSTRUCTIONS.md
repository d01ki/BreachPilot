# BreachPilot Attack Scenario Generation - Setup Instructions

## 🚀 Quick Setup (Automated)

```bash
# 1. Clone and switch to feature branch
git clone https://github.com/d01ki/BreachPilot.git
cd BreachPilot
git checkout feature/attack-scenario-generator

# 2. Run automated setup
chmod +x setup_local.sh
./setup_local.sh

# 3. Configure allowed targets (IMPORTANT!)
nano backend/api/scenario_routes.py
# Edit lines 29-35 to add your test network IPs

# 4. Start application
python app.py

# 5. Test (in another terminal)
chmod +x test_workflow.sh
./test_workflow.sh 192.168.1.100  # Replace with your test VM IP
```

## 📋 Manual Setup (Step by Step)

### Step 1: Get the Code

```bash
# Navigate to your BreachPilot directory
cd BreachPilot

# Fetch latest changes
git fetch origin

# Switch to the new feature branch
git checkout feature/attack-scenario-generator

# Pull latest updates
git pull origin feature/attack-scenario-generator

# Verify you're on the right branch
git branch
# Should show: * feature/attack-scenario-generator
```

### Step 2: Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate  # Windows

# Verify activation
which python
# Should show: /path/to/BreachPilot/venv/bin/python
```

### Step 3: Install Dependencies

```bash
# Upgrade pip
pip install --upgrade pip

# Install all requirements
pip install -r requirements.txt

# Verify installation
python3 -c "import fastapi; import langchain; import pydantic; print('✅ Dependencies OK')"
```

### Step 4: Install System Requirements

```bash
# Check Nmap
nmap --version

# If not installed:
# Ubuntu/Debian:
sudo apt-get update
sudo apt-get install nmap

# macOS:
brew install nmap

# Check Docker (optional, for sandbox execution)
docker --version

# If not installed:
# Ubuntu/Debian:
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# macOS:
brew install docker

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Test Docker
docker run hello-world
```

### Step 5: Configure Environment (Optional)

```bash
# Create .env file for OpenAI API (optional)
cp .env.example .env

# Edit .env and add your API key
nano .env

# Add this line:
OPENAI_API_KEY=sk-your-openai-api-key-here

# Note: Tool works without OpenAI API key (uses rule-based generation)
```

### Step 6: Configure Allowed Targets (CRITICAL!)

```bash
# Edit the API routes file
nano backend/api/scenario_routes.py

# Find lines 29-35 and edit:
```

```python
scenario_orchestrator = ScenarioOrchestrator(
    allowed_targets=[
        "192.168.1.0/24",     # Your test network
        "10.0.0.0/8",         # Internal network
        "192.168.1.100",      # Specific test VM
        # Add your authorized targets here!
    ],
    use_llm=False  # Set to True if you have OPENAI_API_KEY
)
```

**⚠️ CRITICAL**: Only add IPs you own or have written permission to test!

### Step 7: Start the Application

```bash
# Start BreachPilot
python app.py

# You should see:
# INFO:     Started server process [xxxxx]
# INFO:     Application startup complete.
# INFO:     Uvicorn running on http://0.0.0.0:8000
```

### Step 8: Verify Installation

```bash
# In a new terminal

# 1. Health check
curl http://localhost:8000/health
# Expected: {"status":"healthy","version":"2.0-arsenal"}

# 2. Check features
curl http://localhost:8000/ | jq
# Should show "Attack Scenario Generation (NEW)" in features

# 3. View API docs
# Open in browser: http://localhost:8000/docs
```

### Step 9: Run Test Workflow

```bash
# Make test script executable
chmod +x test_workflow.sh

# Run full workflow test
./test_workflow.sh 192.168.1.100

# Replace 192.168.1.100 with your test VM IP
```

## ✅ Expected Test Results

Successful workflow should show:

```
✅ API is running
✅ Session created: [session-id]
✅ Nmap complete: X open ports found
✅ Analysis complete: Y CVEs identified
✅ Attack graph generated:
   - Nodes: 10-20
   - Vulnerabilities: 1-5
   - Entry points: 1-3
✅ Generated 3-5 attack scenarios
✅ Scenario approved
✅ Synthesized 3-6 PoCs
```

## 🔧 Troubleshooting

### Issue: ModuleNotFoundError

```bash
# Solution: Reinstall dependencies
pip install -r requirements.txt
```

### Issue: Permission denied (Docker)

```bash
# Solution: Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

### Issue: Port 8000 already in use

```bash
# Solution: Use different port
uvicorn backend.main:app --host 0.0.0.0 --port 8001
```

### Issue: Nmap not found

```bash
# Solution: Install Nmap
# Ubuntu/Debian:
sudo apt-get install nmap

# macOS:
brew install nmap
```

### Issue: Target not authorized

```bash
# Solution: Add target to whitelist
nano backend/api/scenario_routes.py
# Edit allowed_targets list (lines 29-35)
```

## 📚 Next Steps

After successful setup:

1. **Read Documentation**
   - `README_ARSENAL.md` - Arsenal demo guide
   - `docs/ATTACK_SCENARIO_GENERATION.md` - Complete feature docs
   - `docs/DEMO_SCRIPT.md` - 5-minute demo script

2. **Test Features**
   - Generate attack graphs
   - Create attack scenarios
   - Approve and synthesize PoCs
   - (Optional) Execute in sandbox

3. **Prepare for Demo**
   - Practice full workflow
   - Prepare backup materials
   - Test on isolated lab environment

## 🎯 Quick Reference

### Essential Commands

```bash
# Start application
python app.py

# Health check
curl http://localhost:8000/health

# Run test workflow
./test_workflow.sh [TARGET_IP]

# View API docs
open http://localhost:8000/docs

# Stop application
Ctrl+C
```

### Directory Structure

```
BreachPilot/
├── backend/
│   ├── scenario/              # New: Attack scenario generation
│   │   ├── attack_graph_builder.py
│   │   ├── scenario_generator.py
│   │   ├── poc_synthesizer.py
│   │   └── sandbox_executor.py
│   ├── api/
│   │   └── scenario_routes.py # New: 12 API endpoints
│   └── scenario_orchestrator.py
├── docs/
│   ├── ATTACK_SCENARIO_GENERATION.md
│   └── DEMO_SCRIPT.md
├── README_ARSENAL.md
├── setup_local.sh             # Automated setup
└── test_workflow.sh           # Integration test
```

## ⚠️ Safety Reminders

1. **Only test authorized targets**
   - Configure whitelist in `backend/api/scenario_routes.py`
   - Obtain written permission for all targets
   - Use isolated lab environments

2. **Review before execution**
   - Approve scenarios manually (Human-in-the-loop)
   - Review generated PoC code
   - Understand what will be executed

3. **Use sandbox isolation**
   - Docker provides resource limits
   - Network isolation recommended
   - Monitor execution logs

## 📞 Support

- **Issues**: https://github.com/d01ki/BreachPilot/issues
- **Pull Request**: https://github.com/d01ki/BreachPilot/pull/7
- **Documentation**: See `/docs` directory

## 🎉 Ready!

You're now ready to use BreachPilot's Attack Scenario Generation feature!

**Next**: Run `./test_workflow.sh [YOUR_TEST_IP]` to verify everything works.