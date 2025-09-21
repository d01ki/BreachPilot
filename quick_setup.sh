#!/bin/bash

echo "🚀 BreachPilot Quick Setup"
echo "=========================="
echo ""

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Python version: $python_version"

# Create virtual environment if not exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo ""
echo "Installing dependencies..."
pip install fastapi==0.104.1
pip install uvicorn==0.24.0
pip install websockets==12.0
pip install python-nmap==0.7.1
pip install shodan==1.31.0
pip install python-whois==0.9.4
pip install dnspython==2.4.2
pip install requests==2.31.0
pip install beautifulsoup4==4.12.2
pip install markdown==3.5.1
pip install reportlab==4.0.7
pip install jinja2==3.1.2
pip install pydantic==2.5.0
pip install python-dotenv==1.0.0
pip install aiofiles==23.2.1
pip install langchain-openai==0.2.8

# Install CrewAI last to handle dependencies
echo ""
echo "Installing CrewAI..."
pip install crewai==0.80.0

echo ""
echo "✅ Installation complete!"
echo ""
echo "To run the application:"
echo "  source venv/bin/activate"
echo "  python3 app.py"
