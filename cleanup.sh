#!/bin/bash

# BreachPilot v2.0 - Cleanup Script
# Remove old/unused files from previous implementation

echo "🧹 Cleaning up old files..."

# Remove old files
echo "Removing old implementation files..."
rm -f api_realtime_endpoints.py 2>/dev/null && echo "✓ Removed api_realtime_endpoints.py"
rm -f requirements_realtime.txt 2>/dev/null && echo "✓ Removed requirements_realtime.txt"
rm -f run.py 2>/dev/null && echo "✓ Removed run.py"

# Remove old directories
echo ""
echo "Removing old directories..."
rm -rf breachpilot/ 2>/dev/null && echo "✓ Removed breachpilot/"
rm -rf core/ 2>/dev/null && echo "✓ Removed core/"
rm -rf src/ 2>/dev/null && echo "✓ Removed src/"
rm -rf templates/ 2>/dev/null && echo "✓ Removed templates/"

echo ""
echo "✅ Cleanup complete!"
echo ""
echo "To commit these changes:"
echo "  git add -A"
echo "  git commit -m 'Remove old implementation files'"
echo "  git push origin feature/dev_v2"
