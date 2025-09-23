# 🔧 Troubleshooting Guide

## Installation Issues

### Issue: `ModuleNotFoundError: No module named 'whois'`

**Solution:**
```bash
pip install python-whois==0.9.4
```

### Issue: CFFI Version Mismatch Error

**Error:**
```
Exception: Version mismatch: this is the 'cffi' package version 2.0.0, located in '/path/to/venv/lib/python3.12/site-packages/cffi/api.py'.  When we import the top-level '_cffi_backend' extension module, we get version 1.16.0, located in '/usr/lib/python3/dist-packages/_cffi_backend.cpython-312-x86_64-linux-gnu.so'.  The two versions should be equal; check your installation.
```

**Solution 1: Use automatic fix script (Recommended)**
```bash
# Make the script executable
chmod +x fix_dependencies.sh

# Run the fix script (make sure you're in your virtual environment)
source venv/bin/activate
./fix_dependencies.sh
```

**Solution 2: Manual fix**
```bash
# Activate virtual environment
source venv/bin/activate

# Uninstall conflicting packages
pip uninstall -y cffi pycryptodome cryptodome impacket

# Clear pip cache
pip cache purge

# Install compatible versions in specific order
pip install "cffi>=1.16.0,<2.0.0"
pip install "pycryptodome>=3.19.0"
pip install "impacket>=0.12.0"

# Reinstall requirements
pip install -r requirements.txt
```

**Solution 3: Fresh virtual environment**
```bash
# Remove old virtual environment
rm -rf venv

# Create new virtual environment
python3 -m venv venv
source venv/bin/activate

# Install requirements with fixed versions
pip install -r requirements.txt
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

## Exploit Execution Issues

### Issue: PoC execution fails with import errors

**Common Causes:**
1. CFFI version mismatch (see above)
2. Missing dependencies in PoC code
3. Python path issues

**Solution:**
```bash
# First, fix CFFI if needed
./fix_dependencies.sh

# Then check the exploit executor environment
python3 -c "
from backend.exploiter.exploit_executor import ExploitExecutor
executor = ExploitExecutor()
env_check = executor._check_environment()
print('Environment status:', env_check)
"
```

### Issue: Exploit execution timeout

**Solution:**
The system has built-in timeouts for safety. If legitimate exploits are timing out, you can modify the timeout values in `backend/exploiter/exploit_executor.py`.

## Quick Fix Commands

### Complete dependency fix
```bash
# Automatic fix (recommended)
chmod +x fix_dependencies.sh
source venv/bin/activate
./fix_dependencies.sh
```

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

## Environment Verification

### Test critical imports
```bash
python3 -c "
import sys
print(f'Python: {sys.version}')

try:
    import cffi; print(f'✅ CFFI: {cffi.__version__}')
except Exception as e: print(f'❌ CFFI: {e}')

try:
    from Cryptodome.Cipher import ARC4; print('✅ Cryptodome: OK')
except Exception as e: print(f'❌ Cryptodome: {e}')

try:
    import impacket; print(f'✅ Impacket: {getattr(impacket, \"__version__\", \"unknown\")}')
except Exception as e: print(f'❌ Impacket: {e}')

try:
    from impacket.dcerpc.v5 import nrpc; print('✅ Impacket modules: OK')
except Exception as e: print(f'❌ Impacket modules: {e}')
"
```

## Contact

If issues persist, please create an issue on GitHub with:
1. Error message
2. Python version (`python3 --version`)
3. OS information
4. Steps to reproduce
5. Output from environment verification script
