"""
Zerologon vulnerable environment mock scan
"""
import asyncio
from typing import Dict, Any


async def run_mock_port_scan(target: str) -> Dict[str, Any]:
    """Return Zerologon vulnerable environment port scan"""
    await asyncio.sleep(2)
    
    return {
        "target": target,
        "scan_type": "quick",
        "ports": [
            {
                "port": "88",
                "protocol": "tcp",
                "state": "open",
                "service": "kerberos",
                "version": "Microsoft Windows Kerberos"
            },
            {
                "port": "135",
                "protocol": "tcp",
                "state": "open",
                "service": "msrpc",
                "version": "Microsoft Windows RPC"
            },
            {
                "port": "139",
                "protocol": "tcp",
                "state": "open",
                "service": "netbios-ssn",
                "version": "Microsoft Windows netbios-ssn"
            },
            {
                "port": "389",
                "protocol": "tcp",
                "state": "open",
                "service": "ldap",
                "version": "Microsoft Windows Active Directory LDAP"
            },
            {
                "port": "445",
                "protocol": "tcp",
                "state": "open",
                "service": "microsoft-ds",
                "version": "Microsoft Windows Server 2016 - 2019 microsoft-ds"
            },
            {
                "port": "464",
                "protocol": "tcp",
                "state": "open",
                "service": "kpasswd5",
                "version": "Microsoft Windows Kerberos password change"
            },
            {
                "port": "593",
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "version": "Microsoft HTTPAPI httpd 2.0"
            },
            {
                "port": "636",
                "protocol": "tcp",
                "state": "open",
                "service": "ldapssl",
                "version": "Microsoft Windows Active Directory LDAP (SSL)"
            },
            {
                "port": "3268",
                "protocol": "tcp",
                "state": "open",
                "service": "ldap",
                "version": "Microsoft Windows Active Directory LDAP"
            },
            {
                "port": "3389",
                "protocol": "tcp",
                "state": "open",
                "service": "ms-wbt-server",
                "version": "Microsoft Terminal Services"
            }
        ]
    }
