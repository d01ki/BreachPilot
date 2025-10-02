#!/bin/bash

# PDF Download Test Script
# This script tests the PDF download functionality

echo "🔧 Testing PDF Download Functionality"
echo "======================================"

# Set target IP for testing
TARGET_IP="192.168.1.100"
BASE_URL="http://localhost:8000"

echo "📁 Creating test report files..."

# Create data and reports directories
mkdir -p data/reports
mkdir -p data

# Create sample NMAP results
cat > "data/${TARGET_IP}_nmap.json" << 'EOF'
{
  "target_ip": "192.168.1.100",
  "status": "completed",
  "open_ports": [
    {
      "port": 80,
      "protocol": "TCP",
      "service": "http",
      "product": "Apache HTTP Server",
      "version": "2.4.41"
    },
    {
      "port": 445,
      "protocol": "TCP", 
      "service": "microsoft-ds",
      "product": "Microsoft Windows Server 2019",
      "version": "10.0"
    }
  ],
  "services": [
    {
      "port": 80,
      "name": "http",
      "product": "Apache HTTP Server",
      "version": "2.4.41"
    },
    {
      "port": 445,
      "name": "microsoft-ds",
      "product": "Microsoft Windows Server 2019"
    }
  ]
}
EOF

# Create sample vulnerability analysis results
cat > "data/${TARGET_IP}_analysis.json" << 'EOF'
{
  "target_ip": "192.168.1.100",
  "identified_cves": [
    {
      "cve_id": "CVE-2020-1472",
      "severity": "critical",
      "cvss_score": 10.0,
      "affected_service": "Microsoft Windows Netlogon",
      "description": "Zerologon elevation of privilege vulnerability",
      "exploit_available": true
    },
    {
      "cve_id": "CVE-2021-34527",
      "severity": "high", 
      "cvss_score": 8.8,
      "affected_service": "Print Spooler Service",
      "description": "PrintNightmare remote code execution vulnerability",
      "exploit_available": true
    }
  ]
}
EOF

# Create sample exploit results
cat > "data/${TARGET_IP}_exploits.json" << 'EOF'
{
  "results": [
    {
      "cve_id": "CVE-2020-1472",
      "target_ip": "192.168.1.100",
      "success": true,
      "exploit_command": "python3 zerologon_professional.py DC01 192.168.1.100",
      "execution_output": "[+] SUCCESS! Authentication bypass achieved!",
      "evidence": ["Netlogon RPC accessible", "Authentication bypass successful"]
    }
  ]
}
EOF

echo "✅ Sample data files created"

# Function to test API endpoint
test_endpoint() {
    local endpoint="$1"
    local description="$2"
    
    echo "🔍 Testing: $description"
    echo "   Endpoint: $endpoint"
    
    response=$(curl -s -w "%{http_code}" -o /dev/null "$endpoint")
    
    if [ "$response" = "200" ]; then
        echo "   ✅ SUCCESS (HTTP $response)"
    elif [ "$response" = "404" ]; then
        echo "   ❌ NOT FOUND (HTTP $response)"
    else
        echo "   ⚠️  UNEXPECTED (HTTP $response)"
    fi
    echo
}

# Start the tests
echo "🚀 Starting API endpoint tests..."
echo

# Test if server is running
echo "📡 Checking if BreachPilot server is running..."
if curl -s "$BASE_URL/" > /dev/null; then
    echo "   ✅ Server is running"
else
    echo "   ❌ Server is not running. Please start the server with: python3 app.py"
    exit 1
fi
echo

# Test report listing endpoint
test_endpoint "$BASE_URL/api/reports/list/$TARGET_IP" "Report listing"

# Test HTML report download
test_endpoint "$BASE_URL/api/reports/download/html/$TARGET_IP" "HTML report download"

# Test PDF report download  
test_endpoint "$BASE_URL/api/reports/download/pdf/$TARGET_IP" "PDF report download"

# Test JSON data download
test_endpoint "$BASE_URL/api/reports/download/json/$TARGET_IP" "JSON data download"

# Test static file serving
test_endpoint "$BASE_URL/reports/" "Static reports directory"

echo "🔧 Manual testing steps:"
echo "1. Start BreachPilot: python3 app.py"
echo "2. Open browser: http://localhost:8000"
echo "3. Enter IP: $TARGET_IP"
echo "4. Click 'Initialize Assessment'"
echo "5. Run NMAP scan"
echo "6. Run vulnerability analysis"  
echo "7. Generate report"
echo "8. Test 'Download PDF' button"
echo

echo "📋 Direct download URLs to test:"
echo "HTML Report: $BASE_URL/api/reports/download/html/$TARGET_IP"
echo "PDF Report:  $BASE_URL/api/reports/download/pdf/$TARGET_IP"
echo "JSON Data:   $BASE_URL/api/reports/download/json/$TARGET_IP"
echo "Report List: $BASE_URL/api/reports/list/$TARGET_IP"
echo

echo "🐛 If downloads fail, check:"
echo "1. Server logs for errors"
echo "2. File permissions in data/reports directory"
echo "3. WeasyPrint installation: pip install weasyprint"
echo "4. Browser console for JavaScript errors"
echo

echo "🔧 Test completed!"
