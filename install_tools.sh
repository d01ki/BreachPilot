#!/bin/bash

# BreachPilot Tool Installation Script
# Automated installation of penetration testing tools

set -e  # Exit on any error

echo "🚀 BreachPilot Tool Installation Script"
echo "========================================"

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    echo "Detected OS: Linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="darwin"
    echo "Detected OS: macOS"
else
    echo "❌ Unsupported OS: $OSTYPE"
    echo "Manual installation required. Please check the documentation."
    exit 1
fi

# Check if running as root (for Linux)
if [[ $OS == "linux" && $EUID -eq 0 ]]; then
    echo "⚠️  Running as root. This script will install system packages."
    SUDO=""
else
    SUDO="sudo"
fi

# Update package manager
echo "📦 Updating package manager..."
if [[ $OS == "linux" ]]; then
    $SUDO apt-get update -y
elif [[ $OS == "darwin" ]]; then
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew update
fi

# Function to install a tool
install_tool() {
    local tool_name=$1
    local install_cmd=$2
    
    echo "🔧 Installing $tool_name..."
    
    if command -v $tool_name &> /dev/null; then
        echo "✅ $tool_name is already installed"
        return 0
    fi
    
    eval $install_cmd
    
    if command -v $tool_name &> /dev/null; then
        echo "✅ Successfully installed $tool_name"
    else
        echo "❌ Failed to install $tool_name"
        return 1
    fi
}

# Essential tools installation
echo ""
echo "📋 Installing Essential Tools..."
echo "================================"

if [[ $OS == "linux" ]]; then
    install_tool "nmap" "$SUDO apt-get install -y nmap"
    install_tool "curl" "$SUDO apt-get install -y curl"
    install_tool "whois" "$SUDO apt-get install -y whois"
    install_tool "dnsutils" "$SUDO apt-get install -y dnsutils"  # includes nslookup
    
    echo ""
    echo "📋 Installing Optional Penetration Testing Tools..."
    echo "=================================================="
    
    # Ask user for optional tools
    read -p "Install Nikto web scanner? (y/N): " install_nikto
    if [[ $install_nikto =~ ^[Yy]$ ]]; then
        install_tool "nikto" "$SUDO apt-get install -y nikto"
    fi
    
    read -p "Install Dirb directory scanner? (y/N): " install_dirb
    if [[ $install_dirb =~ ^[Yy]$ ]]; then
        install_tool "dirb" "$SUDO apt-get install -y dirb"
    fi
    
    read -p "Install SMB client tools? (y/N): " install_smb
    if [[ $install_smb =~ ^[Yy]$ ]]; then
        install_tool "smbclient" "$SUDO apt-get install -y smbclient"
    fi
    
    read -p "Install Metasploit Framework? (y/N): " install_msf
    if [[ $install_msf =~ ^[Yy]$ ]]; then
        echo "⚠️  Installing Metasploit Framework (this may take a while)..."
        curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | $SUDO bash
        if command -v msfconsole &> /dev/null; then
            echo "✅ Metasploit Framework installed successfully"
        else
            echo "❌ Metasploit installation failed"
        fi
    fi

elif [[ $OS == "darwin" ]]; then
    install_tool "nmap" "brew install nmap"
    install_tool "curl" "brew install curl"
    install_tool "whois" "brew install whois"
    
    echo ""
    echo "📋 Installing Optional Penetration Testing Tools..."
    echo "=================================================="
    
    read -p "Install Nikto web scanner? (y/N): " install_nikto
    if [[ $install_nikto =~ ^[Yy]$ ]]; then
        install_tool "nikto" "brew install nikto"
    fi
    
    read -p "Install Dirb directory scanner? (y/N): " install_dirb
    if [[ $install_dirb =~ ^[Yy]$ ]]; then
        install_tool "dirb" "brew install dirb"
    fi
    
    read -p "Install SMB client tools? (y/N): " install_smb
    if [[ $install_smb =~ ^[Yy]$ ]]; then
        install_tool "smbclient" "brew install samba"
    fi
    
    read -p "Install Metasploit Framework? (y/N): " install_msf
    if [[ $install_msf =~ ^[Yy]$ ]]; then
        echo "⚠️  Installing Metasploit Framework (this may take a while)..."
        install_tool "msfconsole" "brew install metasploit"
    fi
fi

# Python requirements
echo ""
echo "📋 Installing Python Requirements..."
echo "==================================="

# Check if pip is available
if command -v pip3 &> /dev/null; then
    echo "Installing Python packages..."
    pip3 install --user anthropic openai requests beautifulsoup4 lxml
    echo "✅ Python packages installed"
else
    echo "⚠️  pip3 not found. Please install Python packages manually:"
    echo "pip3 install anthropic openai requests beautifulsoup4 lxml"
fi

# Tool verification
echo ""
echo "🔍 Verifying Tool Installation..."
echo "================================="

tools_to_check=("nmap" "curl" "whois")

if command -v nikto &> /dev/null; then
    tools_to_check+=("nikto")
fi

if command -v dirb &> /dev/null; then
    tools_to_check+=("dirb")
fi

if command -v smbclient &> /dev/null; then
    tools_to_check+=("smbclient")
fi

if command -v msfconsole &> /dev/null; then
    tools_to_check+=("msfconsole")
fi

echo ""
installed_count=0
for tool in "${tools_to_check[@]}"; do
    if command -v $tool &> /dev/null; then
        version_info=$($tool --version 2>/dev/null | head -n1 || echo "Version check failed")
        echo "✅ $tool: $version_info"
        ((installed_count++))
    else
        echo "❌ $tool: Not found"
    fi
done

echo ""
echo "📊 Installation Summary"
echo "======================"
echo "✅ Installed tools: $installed_count/${#tools_to_check[@]}"

if [[ $installed_count -eq ${#tools_to_check[@]} ]]; then
    echo "🎉 All tools installed successfully!"
else
    echo "⚠️  Some tools failed to install. Check the errors above."
fi

# Environment setup
echo ""
echo "🔧 Environment Setup"
echo "==================="

# Create .env file if it doesn't exist
if [[ ! -f .env ]]; then
    echo "Creating .env file for configuration..."
    cat > .env << EOF
# BreachPilot Configuration
BREACHPILOT_DEMO_MODE=true
ANTHROPIC_API_KEY=your_api_key_here
OPENAI_API_KEY=your_api_key_here
GITHUB_TOKEN=your_token_here
FLASK_DEBUG=false
PORT=5000
EOF
    echo "✅ .env file created. Please edit it with your API keys."
else
    echo "✅ .env file already exists"
fi

# Final instructions
echo ""
echo "🎯 Next Steps"
echo "============="
echo "1. Edit the .env file with your API keys:"
echo "   - ANTHROPIC_API_KEY (for Claude AI)"
echo "   - OPENAI_API_KEY (for GPT AI)"
echo "   - GITHUB_TOKEN (optional)"
echo ""
echo "2. Start BreachPilot:"
echo "   python3 app.py"
echo ""
echo "3. Open your browser and go to:"
echo "   http://localhost:5000"
echo ""
echo "4. For tool status, visit:"
echo "   http://localhost:5000/tools-status"
echo ""
echo "🚀 Happy ethical hacking with BreachPilot!"
echo ""

# Ask if user wants to start BreachPilot now
read -p "Start BreachPilot now? (y/N): " start_now
if [[ $start_now =~ ^[Yy]$ ]]; then
    echo "Starting BreachPilot..."
    if [[ -f app.py ]]; then
        python3 app.py
    else
        echo "❌ app.py not found in current directory"
        echo "Please navigate to the BreachPilot directory and run: python3 app.py"
    fi
fi
