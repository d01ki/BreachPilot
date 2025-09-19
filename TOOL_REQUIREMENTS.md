# 🔧 Tool Installation and Requirements

## ⚡ Quick Setup

### Automated Installation (Recommended)
```bash
# Make the script executable
chmod +x install_tools.sh

# Run the installation script
./install_tools.sh
```

### Manual Installation

#### Essential Tools (Required)
```bash
# Ubuntu/Debian
sudo apt-get install -y nmap curl whois dnsutils

# macOS
brew install nmap curl whois

# Windows
# Download tools from official websites
```

#### Optional Tools (Enhanced Features)
```bash
# Ubuntu/Debian
sudo apt-get install -y nikto dirb smbclient

# macOS
brew install nikto dirb samba

# Metasploit Framework (Optional)
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | sudo bash
```

## 🛠️ Tool Status Check

### Via Web Interface
Visit `http://localhost:5000/tools-status` after starting BreachPilot to:
- Check tool installation status
- Get installation commands
- Download installation scripts

### Via API
```bash
# Check tool status
curl http://localhost:5000/api/tools/status

# Get installation script
curl http://localhost:5000/api/tools/install-script
```

## 🎯 Tool Categories

### **Essential Tools** (Required for basic functionality)
| Tool | Purpose | Installation |
|------|---------|-------------|
| `nmap` | Network discovery and security auditing | `apt install nmap` / `brew install nmap` |
| `curl` | HTTP requests and data transfer | `apt install curl` / `brew install curl` |
| `whois` | Domain registration information | `apt install whois` / `brew install whois` |
| `nslookup` | DNS lookup utility | `apt install dnsutils` / Pre-installed |

### **Optional Tools** (Enhanced capabilities)
| Tool | Purpose | Installation |
|------|---------|-------------|
| `nikto` | Web vulnerability scanner | `apt install nikto` / `brew install nikto` |
| `dirb` | Web directory/file brute-forcer | `apt install dirb` / `brew install dirb` |
| `smbclient` | SMB/CIFS client | `apt install smbclient` / `brew install samba` |
| `msfconsole` | Metasploit penetration testing framework | [Metasploit Installation](https://www.metasploit.com/) |

## 🔐 Security Modes

### Demo Mode (Default)
- **Environment**: `BREACHPILOT_DEMO_MODE=true`
- **Behavior**: Safe simulations with realistic outputs
- **Tools**: Simulated execution for security
- **Use Case**: Demonstrations, learning, BlackHat Arsenal

### Production Mode
- **Environment**: `BREACHPILOT_DEMO_MODE=false`
- **Behavior**: Real tool execution (safe commands only)
- **Tools**: Actual nmap, whois, nslookup execution
- **Use Case**: Authorized penetration testing

## 🚨 Important Security Notes

### Safe Command Execution
- Only whitelisted tools are executed
- Dangerous options are automatically filtered
- Commands run with limited privileges
- Timeout protection prevents hanging

### Blacklisted Patterns
```python
dangerous_patterns = [
    "--script", "-oA", "-oG", "--interactive",
    "rm ", "del ", "format", "mkfs", "dd if="
]
```

### Tool Availability Detection
The system automatically:
1. **Checks** if tools are installed
2. **Verifies** tool functionality
3. **Falls back** to simulation if unavailable
4. **Provides** installation instructions

## 🔍 Troubleshooting

### Tool Not Found
```
Error: Tool 'nmap' is not installed
Solution: Run ./install_tools.sh or install manually
```

### Permission Denied
```bash
# Fix permissions for installation script
chmod +x install_tools.sh

# Install with appropriate permissions
sudo ./install_tools.sh  # Linux
./install_tools.sh       # macOS
```

### Tool Check Failures
```python
# Check tool status programmatically
from src.utils.tool_checker import get_tool_checker
checker = get_tool_checker()
status = checker.check_all_tools()
print(status)
```

## 🎭 Agent Tool Mapping

Each AI agent has access to specific tools:

### **RECON_SPECIALIST**
- `nmap` (comprehensive/quick scans)
- `nslookup` (DNS enumeration)
- `whois` (domain information)
- `ping` (connectivity testing)

### **VULNERABILITY_ANALYST**
- `nmap --script vuln` (vulnerability scanning)
- `nikto` (web vulnerability detection)
- `dirb` (directory brute-forcing)

### **EXPLOIT_ENGINEER**
- `msfconsole` (Metasploit framework)
- Custom exploit scripts
- Payload generation tools

### **POST_EXPLOIT_SPECIALIST**
- `smbclient` (SMB enumeration)
- User enumeration tools
- Privilege checking utilities

## 🚀 Quick Start Commands

```bash
# 1. Clone and setup
git clone <repository>
cd BreachPilot

# 2. Install tools
./install_tools.sh

# 3. Configure API keys
cp .env.example .env
# Edit .env with your API keys

# 4. Start BreachPilot
python3 app.py

# 5. Check tool status
curl http://localhost:5000/api/tools/status
```

## 💡 Pro Tips

### Performance Optimization
- Install tools locally for faster execution
- Use SSD storage for tool databases
- Configure adequate RAM for Metasploit

### Custom Tool Integration
```python
# Add custom tools to agent definitions
custom_tools = {
    "custom_scanner": {
        "cmd": "python3 custom_scanner.py {target}",
        "description": "Custom vulnerability scanner",
        "timeout": 180
    }
}
```

### Environment Variables
```bash
# Tool execution control
export BREACHPILOT_DEMO_MODE=false
export BREACHPILOT_TOOL_TIMEOUT=300
export BREACHPILOT_MAX_WORKERS=4
```