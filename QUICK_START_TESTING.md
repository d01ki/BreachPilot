# Quick Start Testing Guide

## Pre-Requisites

### 1. System Requirements
```bash
# Check Python version (3.9+ required)
python3 --version

# Check Docker
docker --version

# Check Nmap
nmap --version
```

### 2. Install Dependencies
```bash
cd BreachPilot
git checkout feature/attack-scenario-generator

# Install Python packages
pip install -r requirements.txt

# Verify installation
python3 -c "import langchain; import fastapi; print('Dependencies OK')"
```

### 3. Configuration

#### A. Create .env file (Optional - for LLM)
```bash
cp .env.example .env
nano .env

# Add (optional):
OPENAI_API_KEY=sk-your-key-here
```

#### B. Configure Allowed Targets (CRITICAL)
```bash
nano backend/api/scenario_routes.py

# Edit lines 23-26:
scenario_orchestrator = ScenarioOrchestrator(
    allowed_targets=[
        "192.168.1.100",      # Your test VM
        "192.168.1.0/24",     # Or your test network
    ],
    use_llm=False  # Set False if no OpenAI key
)
```

#### C. Docker Setup
```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Test Docker
docker run hello-world
```

## Test Workflow

### Step 1: Start Application
```bash
# Terminal 1: Start BreachPilot
python app.py

# Expected output:
# INFO: Application startup complete.
# INFO: Uvicorn running on http://0.0.0.0:8000
```

### Step 2: Health Check
```bash
# Terminal 2: Test API
curl http://localhost:8000/health

# Expected:
# {"status":"healthy","version":"2.0-arsenal"}
```

### Step 3: Create Scan Session
```bash
# Replace with your test target
TARGET="192.168.1.100"

curl -X POST http://localhost:8000/api/scan/start \
  -H "Content-Type: application/json" \
  -d "{\"target_ip\": \"$TARGET\"}" | jq

# Save session_id from response
SID="paste-session-id-here"
```

### Step 4: Run Nmap Scan
```bash
curl -X POST http://localhost:8000/api/scan/$SID/nmap | jq

# Expected: List of open ports and services
# Should take 10-30 seconds
```

### Step 5: Run CVE Analysis
```bash
curl -X POST http://localhost:8000/api/scan/$SID/analyze | jq

# Expected: List of CVEs with CVSS scores
# Should take 5-15 seconds
```

### Step 6: Generate Attack Graph
```bash
curl -X POST http://localhost:8000/api/scenario/$SID/generate-graph | jq

# Expected output:
# {
#   "success": true,
#   "attack_graph": {
#     "total_nodes": 10-20,
#     "total_vulnerabilities": 1-5,
#     "entry_points": 1-3
#   }
# }
```

### Step 7: Generate Attack Scenarios
```bash
curl -X POST http://localhost:8000/api/scenario/$SID/generate-scenarios | jq

# Expected: 3-5 scenarios with success probabilities
# Should take 2-5 seconds (rule-based) or 10-30 seconds (LLM)
```

### Step 8: View Scenario Details
```bash
# List all scenarios
curl http://localhost:8000/api/scenario/$SID/scenarios | jq

# Get specific scenario (replace SCENARIO_ID)
curl http://localhost:8000/api/scenario/$SID/scenarios/SCENARIO_ID | jq
```

### Step 9: Approve Scenario
```bash
# Replace SCENARIO_ID with actual ID from step 8
SCENARIO_ID="scenario_abc123"

curl -X POST http://localhost:8000/api/scenario/$SID/scenarios/$SCENARIO_ID/approve \
  -H "Content-Type: application/json" \
  -d '{"approved_by": "tester@example.com"}' | jq

# Expected:
# {
#   "success": true,
#   "status": "approved"
# }
```

### Step 10: Synthesize PoCs
```bash
curl -X POST http://localhost:8000/api/scenario/$SID/scenarios/$SCENARIO_ID/synthesize-pocs | jq

# Expected: List of generated Python files
# Should take 1-3 seconds
```

### Step 11: Execute Scenario (Optional - requires Docker)
```bash
# WARNING: This will execute PoCs in Docker
# Only run on authorized test targets!

curl -X POST http://localhost:8000/api/scenario/$SID/scenarios/$SCENARIO_ID/execute \
  -H "Content-Type: application/json" \
  -d '{"timeout": 600}' | jq

# Expected: Execution logs and success/failure status
# Should take 2-10 minutes depending on scenario
```

### Step 12: View Execution Logs
```bash
curl http://localhost:8000/api/scenario/$SID/scenarios/$SCENARIO_ID/execution-logs | jq

# Expected: Full execution logs
```

## Troubleshooting

### Issue 1: "Session not found"
**Cause**: Invalid session ID
**Fix**: 
```bash
# List all sessions
ls data/session_*.json

# Or create new session
curl -X POST http://localhost:8000/api/scan/start \
  -d '{"target_ip": "192.168.1.100"}'
```

### Issue 2: "Nmap scan must be completed first"
**Cause**: Trying to generate graph without scan data
**Fix**: Run steps in order (nmap → analyze → graph)

### Issue 3: "Target not authorized for testing"
**Cause**: Target not in whitelist
**Fix**: Edit `backend/api/scenario_routes.py` and add target to `allowed_targets`

### Issue 4: "Attack graph must be generated first"
**Cause**: Skipped graph generation step
**Fix**: Run `POST /api/scenario/$SID/generate-graph` first

### Issue 5: "Scenario must be approved before PoC synthesis"
**Cause**: Trying to synthesize PoCs without approval
**Fix**: Run approval endpoint first

### Issue 6: "Docker permission denied"
**Cause**: User not in docker group
**Fix**:
```bash
sudo usermod -aG docker $USER
newgrp docker
# Or run with sudo (not recommended)
```

### Issue 7: "ModuleNotFoundError: No module named 'langchain'"
**Cause**: Missing dependencies
**Fix**:
```bash
pip install -r requirements.txt
```

### Issue 8: No scenarios generated
**Cause**: No vulnerabilities found or LLM error
**Fix**: 
- Check if CVE analysis found vulnerabilities
- Set `use_llm=False` if OpenAI key not available
- Check application logs for errors

## Expected Results

### Successful Test Run
```
✅ Health check passed
✅ Session created
✅ Nmap found 3-10 open ports
✅ CVE analysis found 1-5 vulnerabilities
✅ Attack graph: 10-20 nodes
✅ Generated 3-5 scenarios
✅ Scenario approved
✅ PoCs synthesized: 3-6 files
✅ (Optional) Execution completed
```

### Typical Timeline
- Total workflow: 1-5 minutes (without execution)
- With execution: 3-15 minutes (depends on scenario)

## Minimal Test (No Target Required)

If you don't have a test target, you can test the API structure:

```bash
# Test health
curl http://localhost:8000/health

# Test docs
open http://localhost:8000/docs

# Check API structure
curl http://localhost:8000/ | jq
```

## Full Integration Test Script

Save as `test_workflow.sh`:

```bash
#!/bin/bash
set -e

echo "🚀 Testing BreachPilot Attack Scenario Generation"

TARGET="192.168.1.100"
echo "📍 Target: $TARGET"

# 1. Create session
echo "\n1️⃣ Creating session..."
RESPONSE=$(curl -s -X POST http://localhost:8000/api/scan/start \
  -H "Content-Type: application/json" \
  -d "{\"target_ip\": \"$TARGET\"}")
SID=$(echo $RESPONSE | jq -r '.session_id')
echo "   Session ID: $SID"

# 2. Nmap scan
echo "\n2️⃣ Running Nmap scan..."
curl -s -X POST http://localhost:8000/api/scan/$SID/nmap > /dev/null
echo "   ✅ Nmap complete"

# 3. CVE analysis
echo "\n3️⃣ Running CVE analysis..."
curl -s -X POST http://localhost:8000/api/scan/$SID/analyze > /dev/null
echo "   ✅ Analysis complete"

# 4. Generate graph
echo "\n4️⃣ Generating attack graph..."
GRAPH=$(curl -s -X POST http://localhost:8000/api/scenario/$SID/generate-graph)
NODES=$(echo $GRAPH | jq -r '.attack_graph.total_nodes')
echo "   ✅ Graph generated: $NODES nodes"

# 5. Generate scenarios
echo "\n5️⃣ Generating attack scenarios..."
SCENARIOS=$(curl -s -X POST http://localhost:8000/api/scenario/$SID/generate-scenarios)
COUNT=$(echo $SCENARIOS | jq -r '.total_scenarios')
echo "   ✅ Generated $COUNT scenarios"

# 6. Get first scenario ID
SCENARIO_ID=$(echo $SCENARIOS | jq -r '.scenarios[0].scenario_id')
echo "   First scenario: $SCENARIO_ID"

# 7. Approve scenario
echo "\n6️⃣ Approving scenario..."
curl -s -X POST http://localhost:8000/api/scenario/$SID/scenarios/$SCENARIO_ID/approve \
  -H "Content-Type: application/json" \
  -d '{"approved_by": "test@example.com"}' > /dev/null
echo "   ✅ Scenario approved"

# 8. Synthesize PoCs
echo "\n7️⃣ Synthesizing PoCs..."
POCS=$(curl -s -X POST http://localhost:8000/api/scenario/$SID/scenarios/$SCENARIO_ID/synthesize-pocs)
POC_COUNT=$(echo $POCS | jq -r '.synthesized_pocs.total_pocs')
echo "   ✅ Synthesized $POC_COUNT PoCs"

echo "\n✅ Full workflow test PASSED!"
echo "\n📊 Summary:"
echo "   - Session: $SID"
echo "   - Graph nodes: $NODES"
echo "   - Scenarios: $COUNT"
echo "   - PoCs generated: $POC_COUNT"
```

Run with:
```bash
chmod +x test_workflow.sh
./test_workflow.sh
```

## Next Steps

After successful testing:
1. ✅ Review generated scenarios
2. ✅ Inspect synthesized PoC code
3. ✅ Test execution on isolated VM
4. ✅ Practice demo workflow
5. ✅ Prepare backup demo materials