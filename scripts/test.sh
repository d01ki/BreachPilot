#!/bin/bash
# BreachPilot test script

set -e

echo "🧪 Running BreachPilot tests..."

# Install test dependencies
echo "📦 Installing test dependencies..."
pip install pytest pytest-cov pytest-mock

# Run tests with coverage
echo "🏃 Running tests..."
pytest tests/ -v --cov=breachpilot --cov-report=html --cov-report=term-missing

echo "✅ All tests passed!"
echo "📊 Coverage report generated in htmlcov/"