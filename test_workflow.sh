#!/bin/bash

# BreachPilot Attack Scenario Generation - Full Workflow Test
# This script tests the complete attack scenario generation pipeline

set -e

echo "🚀 BreachPilot Attack Scenario Generation - Full Workflow Test"
echo "================================================================"

# Configuration
TARGET="${1:-192.168.1.100}"  # Default target or from argument
BASE_URL="http://localhost:8000"

echo "📍 Target: $TARGET"
echo "🌐 API URL: $BASE_URL"
echo ""

# Check if API is running
echo "🔍 Checking API health..."
if curl -s "$BASE_URL/health" > /dev/null 2>&1; then
    echo "   ✅ API is running"
else
    echo "   ❌ API is not running"
    echo "   Start with: python app.py"
    exit 1
fi

# 1. Create session
echo -e "\n1️⃣ Creating scan session..."
RESPONSE=$(curl -s -X POST "$BASE_URL/api/scan/start" \
  -H "Content-Type: application/json" \
  -d "{\"target_ip\": \"$TARGET\"}")

if echo "$RESPONSE" | grep -q "session_id"; then
    SID=$(echo "$RESPONSE" | jq -r '.session_id')
    echo "   ✅ Session created: $SID"
else
    echo "   ❌ Failed to create session"
    echo "   Response: $RESPONSE"
    exit 1
fi

# 2. Nmap scan
echo -e "\n2️⃣ Running Nmap scan..."
echo "   (This may take 30-60 seconds)"
NMAP_RESULT=$(curl -s -X POST "$BASE_URL/api/scan/$SID/nmap")

if echo "$NMAP_RESULT" | grep -q "open_ports"; then
    PORT_COUNT=$(echo "$NMAP_RESULT" | jq -r '.open_ports | length')
    echo "   ✅ Nmap complete: $PORT_COUNT open ports found"
else
    echo "   ❌ Nmap scan failed"
    echo "   Response: $NMAP_RESULT"
    exit 1
fi

# 3. CVE analysis
echo -e "\n3️⃣ Running CVE analysis..."
ANALYSIS_RESULT=$(curl -s -X POST "$BASE_URL/api/scan/$SID/analyze")

if echo "$ANALYSIS_RESULT" | grep -q "identified_cves"; then
    CVE_COUNT=$(echo "$ANALYSIS_RESULT" | jq -r '.identified_cves | length')
    echo "   ✅ Analysis complete: $CVE_COUNT CVEs identified"
else
    echo "   ⚠️  CVE analysis completed (no CVEs found or error)"
    CVE_COUNT=0
fi

# 4. Generate attack graph
echo -e "\n4️⃣ Generating attack graph..."
GRAPH=$(curl -s -X POST "$BASE_URL/api/scenario/$SID/generate-graph")

if echo "$GRAPH" | grep -q "attack_graph"; then
    NODES=$(echo "$GRAPH" | jq -r '.attack_graph.total_nodes')
    VULNS=$(echo "$GRAPH" | jq -r '.attack_graph.total_vulnerabilities')
    ENTRIES=$(echo "$GRAPH" | jq -r '.attack_graph.entry_points')
    echo "   ✅ Attack graph generated:"
    echo "      - Nodes: $NODES"
    echo "      - Vulnerabilities: $VULNS"
    echo "      - Entry points: $ENTRIES"
else
    echo "   ❌ Failed to generate attack graph"
    echo "   Response: $GRAPH"
    exit 1
fi

# 5. Generate scenarios
echo -e "\n5️⃣ Generating attack scenarios..."
SCENARIOS=$(curl -s -X POST "$BASE_URL/api/scenario/$SID/generate-scenarios")

if echo "$SCENARIOS" | grep -q "total_scenarios"; then
    COUNT=$(echo "$SCENARIOS" | jq -r '.total_scenarios')
    echo "   ✅ Generated $COUNT attack scenarios"
    
    if [ "$COUNT" -gt 0 ]; then
        # Display scenario details
        echo -e "\n   📋 Scenario Details:"
        for i in $(seq 0 $((COUNT - 1))); do
            NAME=$(echo "$SCENARIOS" | jq -r ".scenarios[$i].name")
            PROB=$(echo "$SCENARIOS" | jq -r ".scenarios[$i].overall_success_probability")
            STEPS=$(echo "$SCENARIOS" | jq -r ".scenarios[$i].steps")
            RISK=$(echo "$SCENARIOS" | jq -r ".scenarios[$i].risk_level")
            PROB_PERCENT=$(printf "%.0f" $(echo "$PROB * 100" | bc))
            
            echo "      $((i + 1)). $NAME"
            echo "         Success: ${PROB_PERCENT}% | Steps: $STEPS | Risk: $RISK"
        done
        
        # Get first scenario ID
        SCENARIO_ID=$(echo "$SCENARIOS" | jq -r '.scenarios[0].scenario_id')
        SCENARIO_NAME=$(echo "$SCENARIOS" | jq -r '.scenarios[0].name')
        
        # 6. Approve scenario
        echo -e "\n6️⃣ Approving first scenario: $SCENARIO_NAME"
        APPROVE_RESULT=$(curl -s -X POST "$BASE_URL/api/scenario/$SID/scenarios/$SCENARIO_ID/approve" \
          -H "Content-Type: application/json" \
          -d '{"approved_by": "test@example.com"}')
        
        if echo "$APPROVE_RESULT" | grep -q "success"; then
            echo "   ✅ Scenario approved"
        else
            echo "   ❌ Failed to approve scenario"
            exit 1
        fi
        
        # 7. Synthesize PoCs
        echo -e "\n7️⃣ Synthesizing PoCs..."
        POCS=$(curl -s -X POST "$BASE_URL/api/scenario/$SID/scenarios/$SCENARIO_ID/synthesize-pocs")
        
        if echo "$POCS" | grep -q "synthesized_pocs"; then
            POC_COUNT=$(echo "$POCS" | jq -r '.synthesized_pocs.total_pocs')
            WORKSPACE=$(echo "$POCS" | jq -r '.synthesized_pocs.workspace_dir')
            echo "   ✅ Synthesized $POC_COUNT PoCs"
            echo "      Workspace: $WORKSPACE"
            
            # Display PoC details
            if [ "$POC_COUNT" -gt 0 ]; then
                echo -e "\n   📝 Generated PoCs:"
                for i in $(seq 0 $((POC_COUNT - 1))); do
                    FILENAME=$(echo "$POCS" | jq -r ".synthesized_pocs.pocs[$i].filename")
                    TECHNIQUE=$(echo "$POCS" | jq -r ".synthesized_pocs.pocs[$i].technique")
                    echo "      - $FILENAME (Technique: $TECHNIQUE)"
                done
            fi
        else
            echo "   ❌ Failed to synthesize PoCs"
            exit 1
        fi
        
        # 8. Execution (optional, commented out for safety)
        echo -e "\n8️⃣ Scenario execution (skipped for safety)"
        echo "   ⚠️  To execute, uncomment the execution block in this script"
        echo "   ⚠️  WARNING: Only execute on authorized test targets!"
        
        # Uncomment below to enable execution
        # echo -e "\n8️⃣ Executing scenario in sandbox..."
        # EXEC_RESULT=$(curl -s -X POST "$BASE_URL/api/scenario/$SID/scenarios/$SCENARIO_ID/execute" \
        #   -H "Content-Type: application/json" \
        #   -d '{"timeout": 600}')
        # 
        # if echo "$EXEC_RESULT" | grep -q "success"; then
        #     SUCCESS=$(echo "$EXEC_RESULT" | jq -r '.execution_result.success')
        #     if [ "$SUCCESS" = "true" ]; then
        #         echo "   ✅ Execution successful"
        #     else
        #         echo "   ⚠️  Execution completed but failed"
        #     fi
        # else
        #     echo "   ❌ Execution error"
        # fi
        
    else
        echo "   ⚠️  No scenarios generated (target may have no exploitable vulnerabilities)"
        POC_COUNT=0
    fi
else
    echo "   ❌ Failed to generate scenarios"
    echo "   Response: $SCENARIOS"
    exit 1
fi

# Summary
echo -e "\n========================================"
echo "✅ Full Workflow Test COMPLETED"
echo "========================================"
echo -e "\n📊 Summary:"
echo "   - Session ID: $SID"
echo "   - Open ports: $PORT_COUNT"
echo "   - CVEs found: $CVE_COUNT"
echo "   - Graph nodes: $NODES"
echo "   - Scenarios generated: $COUNT"
if [ "$COUNT" -gt 0 ]; then
    echo "   - PoCs synthesized: $POC_COUNT"
fi

echo -e "\n📖 Next Steps:"
echo "   - View results: curl http://localhost:8000/api/scan/$SID/results | jq"
echo "   - View scenarios: curl http://localhost:8000/api/scenario/$SID/scenarios | jq"
echo "   - View graph: curl http://localhost:8000/api/scenario/$SID/attack-graph | jq"

echo -e "\n🎉 Arsenal feature is working!"
