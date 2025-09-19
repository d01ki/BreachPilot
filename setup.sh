#!/bin/bash

# BreachPilot Setup Script
# Automated setup for development and production environments

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        warn "Running as root. Some operations may not work as expected."
    fi
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &> /dev/null; then
            OS="ubuntu"
        elif command -v yum &> /dev/null; then
            OS="rhel"
        else
            OS="linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        OS="unknown"
    fi
    info "Detected OS: $OS"
}

# Install system dependencies
install_system_deps() {
    log "Installing system dependencies..."
    
    case $OS in
        ubuntu)
            sudo apt-get update
            sudo apt-get install -y \
                python3 \
                python3-pip \
                python3-venv \
                nmap \
                nikto \
                whois \
                dnsutils \
                curl \
                wget \
                git \
                sqlite3 \
                docker.io \
                docker-compose
            ;;
        rhel)
            sudo yum update -y
            sudo yum install -y \
                python3 \
                python3-pip \
                nmap \
                nikto \
                whois \
                bind-utils \
                curl \
                wget \
                git \
                sqlite \
                docker \
                docker-compose
            ;;
        macos)
            if ! command -v brew &> /dev/null; then
                error "Homebrew is required for macOS installation. Install from https://brew.sh"
            fi
            brew install python3 nmap nikto whois curl wget git sqlite docker docker-compose
            ;;
        *)
            warn "Unknown OS. Please install dependencies manually:"
            echo "Required: python3, pip, nmap, nikto, whois, curl, wget, git, sqlite3"
            ;;
    esac
}

# Create Python virtual environment
setup_python_env() {
    log "Setting up Python virtual environment..."
    
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
        log "Virtual environment created"
    fi
    
    source venv/bin/activate
    pip install --upgrade pip
    
    if [[ -f "requirements.txt" ]]; then
        pip install -r requirements.txt
        log "Python dependencies installed"
    else
        warn "requirements.txt not found. Installing basic dependencies..."
        pip install flask anthropic openai requests
    fi
}

# Setup configuration
setup_config() {
    log "Setting up configuration..."
    
    if [[ ! -f ".env" ]]; then
        cat > .env << EOF
# BreachPilot Environment Configuration
BREACHPILOT_ENV=development
BREACHPILOT_DEMO_MODE=true
BREACHPILOT_REAL_TOOLS=false

# API Keys (replace with your actual keys)
ANTHROPIC_API_KEY=your_anthropic_api_key_here
OPENAI_API_KEY=your_openai_api_key_here

# Database (for production)
DB_PASSWORD=breachpilot123
EOF
        log "Environment file created (.env)"
        warn "Please edit .env file and add your API keys"
    fi
    
    # Create necessary directories
    mkdir -p reports data logs
    log "Directories created"
}

# Setup database
setup_database() {
    log "Initializing database..."
    
    if [[ -f "venv/bin/activate" ]]; then
        source venv/bin/activate
    fi
    
    python3 -c "
from config import get_config_manager
from src.tools.tool_database import get_tool_database

# Initialize configuration
config_manager = get_config_manager()
config_manager.save_config()

# Initialize tool database
tool_db = get_tool_database()

print('Database initialized successfully')
" 2>/dev/null || warn "Database initialization failed. Will initialize on first run."
}

# Validate installation
validate_installation() {
    log "Validating installation..."
    
    if [[ -f "venv/bin/activate" ]]; then
        source venv/bin/activate
    fi
    
    python3 -c "
from config import DeploymentValidator
print(DeploymentValidator.generate_deployment_report())
" 2>/dev/null || warn "Validation failed. Manual check required."
}

# Start services
start_services() {
    local mode=$1
    
    log "Starting BreachPilot in $mode mode..."
    
    case $mode in
        development)
            if [[ -f "venv/bin/activate" ]]; then
                source venv/bin/activate
            fi
            export BREACHPILOT_ENV=development
            export FLASK_ENV=development
            export FLASK_DEBUG=1
            python3 app.py
            ;;
        docker)
            docker-compose up -d
            log "BreachPilot started with Docker"
            info "Access the application at http://localhost:5000"
            ;;
        production)
            if [[ -f "venv/bin/activate" ]]; then
                source venv/bin/activate
            fi
            export BREACHPILOT_ENV=production
            export FLASK_ENV=production
            python3 app.py
            ;;
        *)
            error "Unknown mode: $mode. Use development, docker, or production"
            ;;
    esac
}

# Display help
show_help() {
    cat << EOF
BreachPilot Setup Script

Usage: $0 [COMMAND]

Commands:
    install         Install system dependencies and setup environment
    setup           Setup Python environment and configuration
    validate        Validate installation and readiness
    start [MODE]    Start BreachPilot (development|docker|production)
    stop            Stop Docker services
    clean           Clean up generated files
    help            Show this help message

Examples:
    $0 install              # Full installation
    $0 setup                # Setup only (after install)
    $0 start development    # Start in development mode
    $0 start docker         # Start with Docker
    $0 validate             # Check installation

EOF
}

# Main execution
main() {
    check_root
    detect_os
    
    case "${1:-help}" in
        install)
            install_system_deps
            setup_python_env
            setup_config
            setup_database
            validate_installation
            log "Installation completed successfully!"
            info "Run '$0 start development' to start BreachPilot"
            ;;
        setup)
            setup_python_env
            setup_config
            setup_database
            log "Setup completed!"
            ;;
        validate)
            validate_installation
            ;;
        start)
            start_services "${2:-development}"
            ;;
        stop)
            docker-compose down
            log "Docker services stopped"
            ;;
        clean)
            log "Cleaning up..."
            rm -rf venv reports/* data/* logs/*
            docker-compose down -v 2>/dev/null || true
            log "Cleanup completed"
            ;;
        help|*)
            show_help
            ;;
    esac
}

# Run main function with all arguments
main "$@"