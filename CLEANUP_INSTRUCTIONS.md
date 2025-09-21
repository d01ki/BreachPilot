# 🗑️ Old Files Cleanup Instructions

## Files to Delete

The following files and directories are from the old implementation and need to be removed:

### Files
- ❌ `api_realtime_endpoints.py` - Old API endpoints
- ❌ `requirements_realtime.txt` - Redundant requirements  
- ❌ `run.py` - Old entry point (replaced by `app.py`)

### Directories
- ❌ `breachpilot/` - Old implementation
- ❌ `core/` - Old core module
- ❌ `src/` - Old source directory
- ❌ `templates/` - Old templates

## Automated Cleanup

### Option 1: Using the cleanup script

```bash
chmod +x cleanup.sh
./cleanup.sh

# Then commit the changes
git add -A
git commit -m "Remove old implementation files"
git push origin feature/dev_v2
```

### Option 2: Manual deletion

```bash
# Remove old files
git rm -f api_realtime_endpoints.py
git rm -f requirements_realtime.txt
git rm -f run.py

# Remove old directories
git rm -rf breachpilot/
git rm -rf core/
git rm -rf src/
git rm -rf templates/

# Commit and push
git commit -m "Remove old implementation files"
git push origin feature/dev_v2
```

## ✅ After Cleanup

The final project structure should look like:

```
BreachPilot/
├── backend/                 # ✅ New implementation
│   ├── agents/
│   ├── exploiter/
│   ├── report/
│   ├── scanners/
│   ├── config.py
│   ├── main.py
│   ├── models.py
│   └── orchestrator.py
├── frontend/                # ✅ Web UI
│   ├── index.html
│   └── static/
│       └── app.js
├── data/                    # ✅ Scan results
├── reports/                 # ✅ Generated reports
├── app.py                   # ✅ Main entry point (NEW)
├── requirements.txt
├── .env.example
├── cleanup.sh
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## 🚀 Running the Application

After cleanup, run the application with:

```bash
python3 app.py
```

Then access the web interface at: http://localhost:8000/ui
