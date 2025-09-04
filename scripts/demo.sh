#!/bin/bash
# BreachPilot demo script

set -e

echo "🎭 Running BreachPilot Demo..."
echo "Target: scanme.nmap.org (safe test target)"
echo ""

# Check if ANTHROPIC_API_KEY is set
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "⚠️  ANTHROPIC_API_KEY environment variable is not set"
    echo "Please set your Claude API key:"
    echo "  export ANTHROPIC_API_KEY='your-api-key'"
    exit 1
fi

# Run demo
echo "🚀 Starting demo scan..."
python3 examples/demo_scan.py

echo ""
echo "✅ Demo completed!"
echo "📄 Check demo_report.md for results"