#!/bin/bash

echo "🔧 BreachPilot PDF Download Fix - Immediate Test"
echo "=============================================="

# Set variables
TARGET_IP="192.168.1.100"
BASE_URL="http://localhost:8000"

# Create directories
echo "📁 Creating directories..."
mkdir -p data/reports
mkdir -p frontend/static

# Create a working app.js with fixed download
echo "📝 Creating fixed frontend/static/app.js..."
cat > frontend/static/app.js << 'EOF'
const { createApp } = Vue;

createApp({
    data() {
        return {
            targetIp: '',
            sessionId: null,
            reportResult: null,
            reportGenerating: false
        }
    },
    
    methods: {
        async startScan() {
            if (!this.targetIp) return;
            try {
                const response = await axios.post('/api/scan/start', {
                    target_ip: this.targetIp
                });
                this.sessionId = response.data.session_id;
                console.log('Session started:', this.sessionId);
            } catch (error) {
                alert('Failed to start: ' + error.message);
            }
        },
        
        async generateReport() {
            this.reportGenerating = true;
            try {
                const response = await axios.post(`/api/scan/${this.sessionId}/report`);
                this.reportResult = response.data;
                alert('Report generated successfully!');
            } catch (error) {
                alert('Failed to generate report: ' + error.message);
            } finally {
                this.reportGenerating = false;
            }
        },
        
        // WORKING DOWNLOAD METHOD
        downloadReport() {
            if (!this.targetIp) {
                alert('Enter IP address first');
                return;
            }
            
            const pdfUrl = `/download/pdf/${this.targetIp}`;
            console.log('Downloading from:', pdfUrl);
            
            // Simple direct download
            window.location.href = pdfUrl;
        },
        
        viewReport() {
            if (!this.targetIp) {
                alert('Enter IP address first');
                return;
            }
            
            window.open(`/download/html/${this.targetIp}`, '_blank');
        },
        
        createTestFiles() {
            if (!this.targetIp) {
                alert('Enter IP address first');
                return;
            }
            
            fetch(`/test/create/${this.targetIp}`)
                .then(response => response.json())
                .then(data => {
                    console.log('Test files created:', data);
                    alert('Test files created! You can now download.');
                    this.reportResult = { generated: true };
                })
                .catch(error => {
                    alert('Failed to create test files: ' + error.message);
                });
        }
    }
}).mount('#app');
EOF

echo "✅ Fixed app.js created"

# Test the server
echo "🧪 Testing server connectivity..."
if curl -s "$BASE_URL/" > /dev/null 2>&1; then
    echo "✅ Server is running"
    
    # Create test files
    echo "📄 Creating test files..."
    curl -s "$BASE_URL/test/create/$TARGET_IP" > /dev/null
    
    # Test endpoints
    echo "🔍 Testing download endpoints..."
    
    # Test PDF download
    echo "Testing PDF download..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/download/pdf/$TARGET_IP")
    if [ "$HTTP_CODE" = "200" ]; then
        echo "✅ PDF download works (HTTP $HTTP_CODE)"
    else
        echo "❌ PDF download failed (HTTP $HTTP_CODE)"
    fi
    
    # Test HTML download
    echo "Testing HTML download..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/download/html/$TARGET_IP")
    if [ "$HTTP_CODE" = "200" ]; then
        echo "✅ HTML download works (HTTP $HTTP_CODE)"
    else
        echo "❌ HTML download failed (HTTP $HTTP_CODE)"
    fi
    
else
    echo "❌ Server is not running"
    echo "Please start the server with: python3 app.py"
    echo ""
    echo "Then test manually:"
    echo "1. Open browser: http://localhost:8000"
    echo "2. Enter IP: $TARGET_IP"  
    echo "3. Click 'Create Test Files' button"
    echo "4. Click 'Download PDF' button"
fi

echo ""
echo "🎯 MANUAL TEST STEPS:"
echo "===================="
echo "1. Start server: python3 app.py"
echo "2. Open: http://localhost:8000"
echo "3. Enter IP: $TARGET_IP"
echo "4. Click 'Create Test Files'"
echo "5. Click 'Download PDF'"
echo ""
echo "📁 Files should be in: data/reports/"
ls -la data/reports/ 2>/dev/null || echo "No files yet - run the test first"

echo ""
echo "🔗 Direct URLs to test:"
echo "PDF: $BASE_URL/download/pdf/$TARGET_IP"
echo "HTML: $BASE_URL/download/html/$TARGET_IP"
echo "Create: $BASE_URL/test/create/$TARGET_IP"
