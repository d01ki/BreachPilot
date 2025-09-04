# Installation Guide

## Prerequisites

### System Requirements
- **OS**: Linux (Kali Linux recommended), macOS, or WSL2 on Windows
- **Python**: 3.10 or higher
- **Memory**: At least 4GB RAM
- **Network**: Internet connection for CVE lookups and AI processing

### Required Tools
- **Nmap**: For network scanning
- **Git**: For repository management

## Installation Methods

### Method 1: Quick Install (Recommended)

```bash
# Clone repository
git clone https://github.com/d01ki/BreachPilot.git
cd BreachPilot

# Run installation script
chmod +x scripts/install.sh
./scripts/install.sh
```

### Method 2: Manual Installation

#### Step 1: Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y nmap python3 python3-pip python3-venv git
```

**CentOS/RHEL:**
```bash
sudo yum install -y nmap python3 python3-pip git
```

**macOS (with Homebrew):**
```bash
brew install nmap python3 git
```

#### Step 2: Setup Python Environment

```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt

# Install BreachPilot
pip install -e .
```

#### Step 3: Configuration

```bash
# Set Claude API key
export ANTHROPIC_API_KEY="your-claude-api-key-here"

# Add to shell profile for persistence
echo 'export ANTHROPIC_API_KEY="your-claude-api-key-here"' >> ~/.bashrc
source ~/.bashrc
```

## Getting API Keys

### Claude API Key
1. Visit [Anthropic Console](https://console.anthropic.com/)
2. Sign up or log in
3. Navigate to API Keys section
4. Create a new API key
5. Copy and set as environment variable

## Verification

### Test Installation
```bash
# Check if breachpilot command is available
breachpilot --help

# Run demo scan
./scripts/demo.sh
```

### Run Tests
```bash
# Run test suite
./scripts/test.sh
```