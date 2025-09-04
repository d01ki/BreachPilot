#!/bin/bash
# BreachPilot installation script

set -e

echo "🚀 Installing BreachPilot..."

# Check Python version
if ! python3 -c 'import sys; assert sys.version_info >= (3, 10)' 2>/dev/null; then
    echo "❌ Python 3.10+ is required"
    exit 1
fi

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "⚠️  nmap is not installed. Installing..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y nmap
    elif command -v yum &> /dev/null; then
        sudo yum install -y nmap
    elif command -v pacman &> /dev/null; then
        sudo pacman -S nmap
    else
        echo "❌ Please install nmap manually"
        exit 1
    fi
fi

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

# Install in development mode
echo "🔧 Installing BreachPilot in development mode..."
pip install -e .

echo "✅ Installation completed!"
echo ""
echo "🚀 Quick start:"
echo "  export ANTHROPIC_API_KEY='your-api-key'"
echo "  breachpilot --target scanme.nmap.org"
echo ""
echo "📖 For more information, see README.md"