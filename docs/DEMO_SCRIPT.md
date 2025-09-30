# Arsenal Demo Script - BreachPilot

## Pre-Demo Setup (10 minutes)

### Environment
- **Attacker Machine**: Kali Linux with BreachPilot
- **Target Machine**: Windows Server 2016 (192.168.1.100)
  - Vulnerable to CVE-2020-1472 (Zerologon)
  - SMB exposed (port 445)
  - LDAP exposed (port 389)

### Start Services
```bash
# Terminal 1: Start BreachPilot
cd ~/BreachPilot
python app.py

# Terminal 2: Keep for API calls
cd ~/BreachPilot

# Verify target is up
ping 192.168.1.100
```

### Test Run (Before Booth Opens)
```bash
# Full workflow test
./test_demo.sh 192.168.1.100

# Verify all steps work
# Save session_id for backup
```

---

## Demo Script (5 Minutes)

### Opening (30 seconds)

**Say**:  
*"Hi! I'm demonstrating BreachPilot - an AI tool that automates penetration testing. It takes scan results and generates complete attack scenarios with success probabilities. Let me show you..."*

**Action**: Point to screen showing terminal and target VM

---

### Step 1: Start Scan (30 seconds)

**Say**:  
*"First, I'll scan this Windows Server. It's a test VM in my lab."*

**Type**:
```bash
# Start scan session
curl -X POST http://localhost:8000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"target_ip": "192.168.1.100"}' | jq

# Copy session_id
export SID="paste_session_id_here"
```

**Say while typing**:  
*"Session created. Now running Nmap..."*

**Type**:
```bash
# Run Nmap scan
curl -X POST http://localhost:8000/api/scan/$SID/nmap | jq
```

**Say while waiting**:  
*"Nmap is scanning ports and services... Found SMB on 445, LDAP on 389..."*

---

### Step 2: CVE Analysis (20 seconds)

**Say**:  
*"Now let's analyze vulnerabilities..."*

**Type**:
```bash
curl -X POST http://localhost:8000/api/scan/$SID/analyze | jq
```

**Say while results appear**:  
*"Found 3 CVEs including CVE-2020-1472 - that's Zerologon, critical vulnerability. CVSS 10.0!"*

---

### Step 3: Generate Attack Graph (15 seconds)

**Say**:  
*"Now watch this - BreachPilot will build an attack graph from these results..."*

**Type**:
```bash
curl -X POST http://localhost:8000/api/scenario/$SID/generate-graph | jq
```

**Say while results appear**:  
*"Attack graph generated in under 1 second. 15 nodes, 3 vulnerabilities, 2 entry points identified."*

**Point to output**:  
*"See these entry points? That's where an attacker could get in."*

---

### Step 4: Generate Attack Scenarios (20 seconds)

**Say**:  
*"Now the AI generates complete attack scenarios..."*

**Type**:
```bash
curl -X POST http://localhost:8000/api/scenario/$SID/generate-scenarios | jq
```

**Say while results appear**:  
*"Generated 5 attack scenarios in 3 seconds! Look at this..."*

**Point to screen**:  
*"Scenario 1: 'Direct Exploitation of CVE-2020-1472'  
- Success probability: 85%  
- Estimated time: 8 minutes  
- Risk level: CRITICAL  
- 4 steps with MITRE ATT&CK techniques"*

**Say**:  
*"These aren't guesses - probabilities based on CVSS scores and exploitability metrics."*

---

### Step 5: View Scenario Details (30 seconds)

**Say**:  
*"Let's look at the attack plan..."*

**Type**:
```bash
# Get first scenario
curl http://localhost:8000/api/scenario/$SID/scenarios | jq '.scenarios[0]'
```

**Point to steps**:  
*"Step 1: Confirm vulnerability (90% success)  
Step 2: Acquire PoC (80% success)  
Step 3: Execute exploit (85% success)  
Step 4: Establish persistence (70% success)"*

**Say**:  
*"Each step has prerequisites, tools needed, and success indicators. This is the roadmap."*

---

### Step 6: Human Approval (20 seconds)

**Say**:  
*"Important: Human must approve before execution. This prevents reckless automation."*

**Type**:
```bash
# Approve scenario (replace scenario_id)
curl -X POST http://localhost:8000/api/scenario/$SID/scenarios/SCENARIO_ID/approve \
  -H "Content-Type: application/json" \
  -d '{"approved_by": "demo@blackhat.com"}' | jq
```

**Say**:  
*"Approved. Now we can synthesize the PoC code..."*

---

### Step 7: PoC Synthesis (20 seconds)

**Say**:  
*"Watch - it'll auto-generate Python exploit code..."*

**Type**:
```bash
curl -X POST http://localhost:8000/api/scenario/$SID/scenarios/SCENARIO_ID/synthesize-pocs | jq
```

**Say while results appear**:  
*"Generated 4 Python scripts in 2 seconds!"*

**Open file** (prepared in advance):
```bash
cat /tmp/breachpilot_pocs_*/step_3_T1210.py | head -20
```

**Say**:  
*"This is actual runnable Python code. Template-based generation."*

---

### Step 8: Sandbox Execution (1-2 minutes)

**Say**:  
*"Final step - execute in isolated Docker sandbox..."*

**Type**:
```bash
curl -X POST http://localhost:8000/api/scenario/$SID/scenarios/SCENARIO_ID/execute \
  -H "Content-Type: application/json" \
  -d '{"timeout": 600}' | jq
```

**Say while executing**:  
*"Running in Docker container... resource-limited... network isolated..."*

**When logs appear**:  
*"Look - live execution logs:  
- Step 1: Vulnerability confirmed ✓  
- Step 2: PoC acquired ✓  
- Step 3: Exploit executing..."*

**If successful**:  
*"Success! Exploitation complete. All logged for audit."*

**If failed** (backup):  
*"In this case it failed, but we have full logs to debug. Let me show you a pre-recorded successful run..."*

---

### Closing (30 seconds)

**Say**:  
*"So what did we just see?  
1. Scan → 3 vulnerabilities  
2. Attack graph → 15 nodes  
3. 5 scenarios generated with success rates  
4. Human approval checkpoint  
5. Auto-generated Python PoCs  
6. Safe sandbox execution

From reconnaissance to exploitation in under 5 minutes."*

**Point to screen**:  
*"This is all open source on GitHub - d01ki/BreachPilot.  
Check out the Arsenal branch: feature/attack-scenario-generator"*

**Final hook**:  
*"Automated pentesting with human safety controls. That's BreachPilot. Questions?"*

---

## Handling Questions

### Q: "How does this compare to Metasploit?"
**A**: "Metasploit requires manual module selection and exploitation. BreachPilot automates the entire chain - from scan to attack plan to PoC generation. Plus it gives you quantitative success probabilities."

### Q: "Can I use this on my company's network?"
**A**: "Only with proper authorization. You must configure the target whitelist in the code and get written permission. It's designed for authorized pentests, red team exercises, and training."

### Q: "What if the LLM makes mistakes?"
**A**: "That's why we have human-in-the-loop approval! Every scenario must be reviewed before execution. Plus the tool works fine without LLM - rule-based generation is very reliable."

### Q: "Is it really 85% accurate?"
**A**: "On vulnerable test systems, yes. Success depends on target configuration, network conditions, and vulnerability details. The probability is calculated from CVSS metrics and historical exploit data."

### Q: "How do I install it?"
**A**: "Clone the GitHub repo, checkout the feature branch, pip install requirements, and run. Takes about 2 minutes. Docker recommended for sandbox execution."

---

## Backup Plans

### If Network Fails
- Show pre-recorded video
- Walk through code architecture
- Display screenshots of successful run
- Explain concepts with diagrams

### If Target VM Crashes
- Use backup session_id
- Show pre-generated scenarios
- Demonstrate PoC code
- Focus on visualization

### If Demo Fails Completely
- Have slides ready
- Show GitHub repo
- Code walkthrough
- Architecture discussion

---

## Post-Demo

### If People Are Interested
- Share GitHub link
- Offer to answer detailed questions
- Explain contribution process
- Mention roadmap

### Collect Feedback
- What features interest them?
- What improvements needed?
- Would they use it?
- Any concerns?

---

## Demo Booth Setup

### Hardware
- Laptop (attacker)
- Extra monitor (for audience)
- Target VM (can be same laptop)
- Backup phone hotspot

### Software
- BreachPilot running
- Terminal with large font
- jq installed for pretty JSON
- tmux for multiple terminals

### Marketing Materials
- QR code to GitHub
- Feature list handout
- Architecture diagram
- Contact info

---

**Break a leg! 🎭**