#!/usr/bin/env python3
"""
Simple test runner for BreachPilot
This file helps test the application without all dependencies
"""

import os
import sys
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Set up basic environment
os.environ.setdefault("FLASK_DEBUG", "true")
os.environ.setdefault("FLASK_SECRET_KEY", "bp-test-secret")

def create_minimal_templates():
    """Create minimal templates for testing"""
    templates_dir = Path("templates")
    templates_dir.mkdir(exist_ok=True)
    
    # Basic HTML template
    html_template = '''<!DOCTYPE html>
<html>
<head>
    <title>BreachPilot - {{title|default("Test")}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; }
        .progress { background: #f0f0f0; border-radius: 4px; height: 20px; }
        .progress-bar { background: #007bff; height: 100%; border-radius: 4px; transition: width 0.3s; }
    </style>
</head>
<body>
    <div class="container">
        {% block content %}
        <h1>BreachPilot Test Mode</h1>
        <p>This is a minimal test template.</p>
        {% endblock %}
    </div>
</body>
</html>'''
    
    # Create individual templates
    templates = {
        "base.html": html_template,
        "index.html": '''{% extends "base.html" %}
{% block content %}
<h1>🚀 BreachPilot - Enhanced Multi-Agent Penetration Testing</h1>

<div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
    <h2>🔍 Traditional Penetration Test</h2>
    <form action="/start" method="post" style="margin: 20px 0;">
        <div style="margin: 10px 0;">
            <label>Target IP/Hostname:</label><br>
            <input type="text" name="target" placeholder="10.10.10.40" style="padding: 8px; width: 300px;">
        </div>
        <div style="margin: 10px 0;">
            <label><input type="checkbox" name="authorize"> I authorize this test</label>
        </div>
        <button type="submit" class="button">Start Test</button>
    </form>
    
    <h3>Demo Scenarios:</h3>
    <ul>
        <li><strong>10.10.10.40</strong> - Legacy Windows Server (EternalBlue)</li>
        <li><strong>10.10.10.75</strong> - Apache Struts Web Server</li>
        <li><strong>10.10.10.14</strong> - Domain Controller (Zerologon)</li>
    </ul>
</div>

<div style="background: #e7f3ff; padding: 20px; border-radius: 8px; margin: 20px 0;">
    <h2>🤖 Attack Chain Orchestrator</h2>
    <a href="/attack-chain" class="button">Launch Attack Chain</a>
</div>

<div style="background: #fff3cd; padding: 20px; border-radius: 8px; margin: 20px 0;">
    <h2>⚙️ Settings</h2>
    <a href="/settings" class="button">Configure API Keys</a>
</div>
{% endblock %}''',
        
        "status.html": '''{% extends "base.html" %}
{% block content %}
<h1>Test Status: {{job_id}}</h1>
<div style="margin: 20px 0;">
    <div class="progress">
        <div class="progress-bar" style="width: {{progress|default(0)}}%"></div>
    </div>
    <p>Status: {{status}} | Phase: {{phase}} | Progress: {{progress|default(0)}}%</p>
</div>

<div id="status-content">
    <p>Job ID: {{job_id}}</p>
    <p>This is test mode - real status updates would appear here.</p>
</div>

<script>
function updateStatus() {
    fetch('/api/job/{{job_id}}')
        .then(response => response.json())
        .then(data => {
            document.querySelector('.progress-bar').style.width = data.progress + '%';
            if (data.status === 'completed') {
                document.getElementById('status-content').innerHTML += '<p><strong>✅ Test completed!</strong></p>';
            }
        })
        .catch(error => console.log('Status update error:', error));
}
setInterval(updateStatus, 2000);
</script>
{% endblock %}''',
        
        "settings.html": '''{% extends "base.html" %}
{% block content %}
<h1>⚙️ Settings</h1>
<form action="/settings" method="post">
    <div style="margin: 15px 0;">
        <label>OpenAI API Key:</label><br>
        <input type="password" name="openai_api_key" style="padding: 8px; width: 400px;">
    </div>
    <div style="margin: 15px 0;">
        <label>Anthropic API Key:</label><br>
        <input type="password" name="anthropic_api_key" style="padding: 8px; width: 400px;">
    </div>
    <div style="margin: 15px 0;">
        <label>GitHub Token:</label><br>
        <input type="password" name="github_token" style="padding: 8px; width: 400px;">
    </div>
    <button type="submit" class="button">Save Settings</button>
</form>
<a href="/" class="button" style="background: #6c757d; margin-left: 10px;">Back to Home</a>
{% endblock %}''',
        
        "attack_chain.html": '''{% extends "base.html" %}
{% block content %}
<h1>🤖 Attack Chain Orchestrator</h1>
<div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
    <h2>Create New Attack Chain</h2>
    <div style="margin: 10px 0;">
        <label>Target:</label><br>
        <input type="text" id="target" placeholder="10.10.10.40" style="padding: 8px; width: 300px;">
    </div>
    <div style="margin: 10px 0;">
        <label>Objective:</label><br>
        <select id="objective" style="padding: 8px; width: 300px;">
            <option value="domain_compromise">Domain Compromise</option>
            <option value="data_exfiltration">Data Exfiltration</option>
            <option value="privilege_escalation">Privilege Escalation</option>
        </select>
    </div>
    <button onclick="createChain()" class="button">Create Attack Chain</button>
</div>

<div id="chain-status" style="margin: 20px 0;"></div>

<script>
let currentChainId = null;

function createChain() {
    const target = document.getElementById('target').value;
    const objective = document.getElementById('objective').value;
    
    fetch('/api/attack-chain/create', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({target, objective, enhanced: true})
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            currentChainId = data.chain_id;
            document.getElementById('chain-status').innerHTML = 
                '<p>✅ Attack chain created: ' + data.chain_id + '</p>' +
                '<button onclick="executeChain()" class="button">Execute Chain</button>';
        }
    });
}

function executeChain() {
    if (!currentChainId) return;
    
    fetch('/api/attack-chain/' + currentChainId + '/execute', {method: 'POST'})
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            document.getElementById('chain-status').innerHTML += '<p>🚀 Execution started...</p>';
            checkStatus();
        }
    });
}

function checkStatus() {
    if (!currentChainId) return;
    
    fetch('/api/attack-chain/' + currentChainId + '/status')
    .then(response => response.json())
    .then(data => {
        document.getElementById('chain-status').innerHTML += 
            '<p>Status: ' + data.status + '</p>';
        
        if (data.status === 'running') {
            setTimeout(checkStatus, 3000);
        }
    });
}
</script>
{% endblock %}''',
        
        "error.html": '''{% extends "base.html" %}
{% block content %}
<h1>Error {{code}}</h1>
<p>{{error}}</p>
<a href="/" class="button">Go Home</a>
{% endblock %}'''
    }
    
    for filename, content in templates.items():
        (templates_dir / filename).write_text(content)
    
    print(f"✅ Created {len(templates)} template files in {templates_dir}/")

def create_static_dir():
    """Create static directory"""
    static_dir = Path("static")
    static_dir.mkdir(exist_ok=True)
    print(f"✅ Created static directory: {static_dir}/")

def main():
    """Main test runner"""
    print("🚀 BreachPilot Test Runner")
    print("=" * 50)
    
    # Create necessary directories and files
    create_minimal_templates()
    create_static_dir()
    
    # Create reports directory
    Path("reports").mkdir(exist_ok=True)
    print("✅ Created reports directory")
    
    print("\n" + "=" * 50)
    print("🎯 Starting BreachPilot in test mode...")
    print("📝 Visit: http://localhost:5000")
    print("⚠️  Note: This is test mode with mock dependencies")
    print("=" * 50 + "\n")
    
    # Import and run the app
    try:
        from app import app
        app.run(host="0.0.0.0", port=5000, debug=True)
    except Exception as e:
        print(f"❌ Error starting app: {e}")
        print("💡 Make sure all files are in place:")
        print("   - app.py")
        print("   - enhanced_functions.py") 
        print("   - api_endpoints.py")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
