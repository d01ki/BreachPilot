"""
Simplified simulation - only port scan mock data
"""
import asyncio
from typing import Dict, Any


async def run_mock_port_scan(target: str) -> Dict[str, Any]:
    """Return only mock port scan data"""
    await asyncio.sleep(2)  # Simulate scanning
    
    return {
        "target": target,
        "scan_type": "quick",
        "ports": [
            {
                "port": "22",
                "protocol": "tcp",
                "state": "open",
                "service": "ssh",
                "version": "OpenSSH 7.4"
            },
            {
                "port": "80",
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "version": "Apache httpd 2.4.6"
            },
            {
                "port": "443",
                "protocol": "tcp",
                "state": "open",
                "service": "https",
                "version": "Apache httpd 2.4.6"
            },
            {
                "port": "3306",
                "protocol": "tcp",
                "state": "open",
                "service": "mysql",
                "version": "MySQL 5.7.30"
            },
            {
                "port": "8080",
                "protocol": "tcp",
                "state": "open",
                "service": "http-proxy",
                "version": "Tomcat 9.0.30"
            }
        ]
    }
