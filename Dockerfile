# BreachPilot - Multi-Agent Penetration Testing Platform

FROM python:3.11-slim

# Install system dependencies for penetration testing tools
RUN apt-get update && apt-get install -y \
    nmap \
    nikto \
    whois \
    dnsutils \
    curl \
    wget \
    git \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p reports data logs

# Set permissions
RUN chmod +x setup.sh

# Expose port
EXPOSE 5000

# Environment variables
ENV BREACHPILOT_ENV=production
ENV BREACHPILOT_DEMO_MODE=true
ENV BREACHPILOT_REAL_TOOLS=false

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5000/health || exit 1

# Run application
CMD ["python", "app.py"]