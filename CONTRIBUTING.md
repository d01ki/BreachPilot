# Contributing to BreachPilot

## Welcome Contributors! 🎉

We're excited that you're interested in contributing to BreachPilot! This project aims to make penetration testing more accessible, educational, and safe through AI-powered automation.

## Getting Started

### Prerequisites

- Python 3.10+
- Git
- Basic understanding of:
  - Cybersecurity concepts
  - Python development
  - Command-line tools
  - AI/LLM concepts (helpful)

### Development Setup

1. **Fork and Clone**

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/BreachPilot.git
cd BreachPilot

# Add upstream remote
git remote add upstream https://github.com/d01ki/BreachPilot.git
```

2. **Development Environment**

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate

# Install development dependencies
pip install -r requirements.txt
pip install -e .

# Install test dependencies
pip install pytest pytest-cov pytest-mock black flake8 isort
```

3. **Environment Configuration**

```bash
# Set up API key
export ANTHROPIC_API_KEY="your-development-api-key"

# Enable debug mode
export BREACHPILOT_DEBUG=1
```

## Contributing Guidelines

### Code Style

```bash
# Format code
black breachpilot/
isort breachpilot/

# Check style
flake8 breachpilot/ --max-line-length=88
```

### Testing

All new code must include unit tests:

```python
def test_basic_functionality():
    # Test implementation
    assert result == expected
```

### Security Standards

- **Input Validation**: Always validate user inputs
- **Error Handling**: Don't expose sensitive information
- **Logging**: Log security-relevant events
- **Dependencies**: Keep dependencies updated

## Pull Request Process

1. **Sync with upstream**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run all tests**
   ```bash
   pytest tests/ -v
   ```

3. **Check code quality**
   ```bash
   black --check breachpilot/
   flake8 breachpilot/
   isort --check-only breachpilot/
   ```

## Security Considerations

### Responsible Development

- **No Malicious Code**: Never contribute code intended for unauthorized use
- **Educational Focus**: Ensure contributions support learning objectives
- **Safe Defaults**: Implement conservative, safe-by-default behaviors
- **User Consent**: Require explicit user approval for risky operations

## Getting Help

- GitHub Discussions for general questions
- GitHub Issues for bug reports and features
- Code review comments for implementation details

Thank you for contributing to BreachPilot! 🛡️✨