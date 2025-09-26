#!/bin/bash

# BreachPilot PDF Download Fix - Quick Test Script
echo "🚀 BreachPilot PDF Download Test Script"
echo "========================================"

TARGET_IP="192.168.1.100"
BASE_URL="http://localhost:8000"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_step() {
    echo -e "\n${BLUE}📋 $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Test 1: Check server status
print_step "Step 1: Checking server status"
if curl -s "$BASE_URL" > /dev/null; then
    print_success "Server is running at $BASE_URL"
else
    print_error "Server is not running. Please start the server with: python3 app.py"
    exit 1
fi

# Test 2: Create test reports
print_step "Step 2: Creating test reports"
RESPONSE=$(curl -s "$BASE_URL/api/reports/test/$TARGET_IP")
if echo "$RESPONSE" | grep -q "successfully"; then
    print_success "Test reports created successfully"
    echo "$RESPONSE" | jq .
else
    print_error "Failed to create test reports"
    echo "$RESPONSE"
fi

# Test 3: List available reports
print_step "Step 3: Checking available reports"
LIST_RESPONSE=$(curl -s "$BASE_URL/api/reports/list/$TARGET_IP")
echo "$LIST_RESPONSE" | jq .

if echo "$LIST_RESPONSE" | grep -q "pdf"; then
    print_success "PDF report is available"
else
    print_warning "PDF report not found"
fi

if echo "$LIST_RESPONSE" | grep -q "html"; then
    print_success "HTML report is available"
else
    print_warning "HTML report not found"
fi

# Test 4: Test PDF download endpoint
print_step "Step 4: Testing PDF download endpoint"
PDF_URL="$BASE_URL/api/reports/download/pdf/$TARGET_IP"
echo "Testing URL: $PDF_URL"

# Check if PDF endpoint responds
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$PDF_URL")
echo "HTTP Status: $HTTP_STATUS"

if [ "$HTTP_STATUS" = "200" ]; then
    print_success "PDF endpoint is working"
    
    # Download PDF and check size
    TEMP_PDF="/tmp/test_security_report.pdf"
    curl -s "$PDF_URL" -o "$TEMP_PDF"
    
    if [ -f "$TEMP_PDF" ]; then
        FILE_SIZE=$(wc -c < "$TEMP_PDF")
        if [ "$FILE_SIZE" -gt 0 ]; then
            print_success "PDF downloaded successfully (${FILE_SIZE} bytes)"
            
            # Check if it's a real PDF
            FILE_TYPE=$(file "$TEMP_PDF" | grep -o "PDF")
            if [ "$FILE_TYPE" = "PDF" ]; then
                print_success "Downloaded file is a valid PDF"
            else
                print_warning "Downloaded file might not be a valid PDF"
                echo "File type: $(file "$TEMP_PDF")"
            fi
        else
            print_error "Downloaded PDF is empty"
        fi
        
        # Clean up
        rm -f "$TEMP_PDF"
    else
        print_error "Failed to download PDF"
    fi
    
elif [ "$HTTP_STATUS" = "404" ]; then
    print_error "PDF not found (404) - Report may not have been generated"
else
    print_error "PDF endpoint failed with status: $HTTP_STATUS"
fi

# Test 5: Test HTML download endpoint
print_step "Step 5: Testing HTML download endpoint"
HTML_URL="$BASE_URL/api/reports/download/html/$TARGET_IP"
echo "Testing URL: $HTML_URL"

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$HTML_URL")
echo "HTTP Status: $HTTP_STATUS"

if [ "$HTTP_STATUS" = "200" ]; then
    print_success "HTML endpoint is working"
    
    # Download HTML and check content
    TEMP_HTML="/tmp/test_security_report.html"
    curl -s "$HTML_URL" -o "$TEMP_HTML"
    
    if [ -f "$TEMP_HTML" ] && [ -s "$TEMP_HTML" ]; then
        FILE_SIZE=$(wc -c < "$TEMP_HTML")
        print_success "HTML downloaded successfully (${FILE_SIZE} bytes)"
        
        # Check for expected HTML content
        if grep -q "Security Assessment Report" "$TEMP_HTML"; then
            print_success "HTML contains expected content"
        else
            print_warning "HTML may not contain expected content"
        fi
        
        rm -f "$TEMP_HTML"
    else
        print_error "Failed to download HTML or file is empty"
    fi
else
    print_error "HTML endpoint failed with status: $HTTP_STATUS"
fi

# Test 6: Browser compatibility test
print_step "Step 6: Browser compatibility test"
echo "Testing browser-compatible URLs:"
echo "  📄 PDF: $BASE_URL/api/reports/download/pdf/$TARGET_IP"
echo "  🌐 HTML: $BASE_URL/api/reports/download/html/$TARGET_IP"
echo "  📋 List: $BASE_URL/api/reports/list/$TARGET_IP"

# Final summary
print_step "Summary"
echo "✅ If all tests passed, your PDF download functionality is working correctly!"
echo ""
echo "🖥️  To test in browser:"
echo "   1. Open: $BASE_URL"
echo "   2. Enter target IP: $TARGET_IP"
echo "   3. Click 'Initialize Assessment'"
echo "   4. Click 'Generate Report'"
echo "   5. Click 'Download PDF'"
echo ""
echo "🔧 Troubleshooting:"
echo "   - If PDF generation fails, install: pip install weasyprint"
echo "   - If WeasyPrint fails, install: pip install reportlab"
echo "   - Check server logs for detailed error messages"
echo ""
echo "📁 Report files are saved in: data/reports/"
echo "🌐 Direct access via: $BASE_URL/reports/"

# Check dependencies
print_step "Dependency Check"
echo "Checking PDF generation dependencies..."

python3 -c "
try:
    import weasyprint
    print('✅ WeasyPrint is available')
except ImportError:
    try:
        import reportlab
        print('✅ ReportLab is available (fallback)')
    except ImportError:
        print('❌ No PDF libraries available - install weasyprint or reportlab')
"

echo ""
echo "🎉 Test completed! Check the results above."
