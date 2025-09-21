# 🔧 Troubleshooting Guide

## Installation Issues

### Issue: `ModuleNotFoundError: No module named 'whois'`

**Solution:**
```bash
pip install python-whois==0.9.4
```

### Issue: Dependency conflict with crewai-tools

**Error:**
```
The conflict is caused by:
    The user requested crewai-tools==0.12.0
    crewai 0.80.0 depends on crewai-tools>=0.14.0
```

**Solution 1: Use quick_setup.sh (Recommended)**
```bash
chmod +x quick_setup.sh
./quick_setup.sh
```

**Solution 2: Manual installation**
```bash
# Remove old virtual environment
rm -rf venv

# Create new virtual environment
python3 -m venv venv
source venv/bin/activate

# Install packages individually
pip install --upgrade pip
pip install fastapi uvicorn websockets
pip install python-nmap shodan python-whois dnspython
pip install requests beautifulsoup4 markdown reportlab
pip install jinja2 pydantic python-dotenv aiofiles
pip install langchain-openai

# Install CrewAI last
pip install crewai==0.80.0
```

**Solution 3: Use updated requirements.txt**
```bash
# Pull latest changes
git pull origin feature/dev_v2

# Install
pip install -r requirements.txt
```

## Runtime Issues

### Issue: `ImportError` or `ModuleNotFoundError` when running app.py

**Solution:**
Make sure you're in the virtual environment:
```bash
source venv/bin/activate
python3 app.py
```

### Issue: Port 8000 already in use

**Solution:**
```bash
# Find and kill process using port 8000
lsof -ti:8000 | xargs kill -9

# Or run on different port
uvicorn backend.main:app --host 0.0.0.0 --port 8001
```

### Issue: Permission denied for Nmap

**Solution:**
Run with sudo for full Nmap capabilities:
```bash
sudo python3 app.py
```

## API Issues

### Issue: OpenAI API key error

**Solution:**
1. Copy `.env.example` to `.env`
2. Add your OpenAI API key:
```bash
cp .env.example .env
nano .env  # Edit and add: OPENAI_API_KEY=sk-...
```

### Issue: Shodan API error

**Solution:**
Shodan is optional. If you have a key, add it to `.env`:
```bash
SHODAN_API_KEY=your_key_here
```

Otherwise, OSINT will work without Shodan data.

## Quick Fix Commands

### Reinstall all dependencies

```bash
# Remove virtual environment
rm -rf venv

# Recreate
python3 -m venv venv
source venv/bin/activate

# Use quick setup
chmod +x quick_setup.sh
./quick_setup.sh
```

### Reset everything

```bash
# Remove all generated files
rm -rf venv/ data/ reports/ __pycache__/ backend/__pycache__/

# Reinstall
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Setup environment
cp .env.example .env
# Edit .env with your API keys

# Run
python3 app.py
```

## Contact

If issues persist, please create an issue on GitHub with:
1. Error message
2. Python version (`python3 --version`)
3. OS information
4. Steps to reproduce
