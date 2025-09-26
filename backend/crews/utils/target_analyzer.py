#!/usr/bin/env python3
"""
Target Analysis Utilities for CrewAI Security Assessment
"""

import logging
from typing import Dict, Any, List

from backend.models import NmapResult

logger = logging.getLogger(__name__)

class TargetAnalyzer:
    """
    Handles target system analysis and data preparation for CrewAI tasks
    """
    
    def __init__(self):
        """
        Initialize target analyzer
        """
        self.high_risk_ports = {3389, 445, 139, 135, 22, 23, 21, 1433, 3306, 5432}
        self.dc_ports = {88, 389, 636, 3268, 3269, 53}
        self.web_ports = {80, 443, 8080, 8443, 8000}
        
    def prepare_target_data(self, target_ip: str, nmap_result: NmapResult) -> Dict[str, Any]:
        """
        Prepare target system data for task configuration
        
        Args:
            target_ip: Target IP address
            nmap_result: Nmap scan results
            
        Returns:
            Dictionary of target system information
        """
        # Extract service information
        services = []
        smb_services = []
        rdp_services = []
        web_services = []
        database_services = []
        dc_indicators = []
        
        if nmap_result.services:
            for service in nmap_result.services:
                port = service.get('port')
                service_name = service.get('name', '').lower()
                product = service.get('product', '')
                version = service.get('version', '')
                
                service_info = f"Port {port}: {service_name} ({product} {version})".strip()
                services.append(service_info)
                
                # Categorize services
                if port in [445, 139] or 'smb' in service_name:
                    smb_services.append(service_info)
                elif port == 3389 or 'rdp' in service_name or 'ms-wbt-server' in service_name:
                    rdp_services.append(service_info)
                elif port in self.web_ports or 'http' in service_name:
                    web_services.append(service_info)
                elif port in [1433, 3306, 5432] or any(db in service_name for db in ['mssql', 'mysql', 'postgresql']):
                    database_services.append(service_info)
                
                # Domain Controller indicators
                if port in self.dc_ports:
                    dc_indicators.append(f"DC Service: Port {port} ({service_name})")
        
        # Prepare open ports summary
        open_ports = [f"Port {service.get('port')}: {service.get('name')}" 
                     for service in nmap_result.services or []]
        
        return {
            'target_ip': target_ip,
            'open_ports': ', '.join(open_ports) if open_ports else 'No open ports detected',
            'os_info': nmap_result.os_detection or 'OS not determined',
            'services': ', '.join(services) if services else 'No services detected',
            'dc_indicators': ', '.join(dc_indicators) if dc_indicators else 'No DC indicators',
            'smb_services': ', '.join(smb_services) if smb_services else 'No SMB services',
            'rdp_services': ', '.join(rdp_services) if rdp_services else 'No RDP services',
            'web_services': ', '.join(web_services) if web_services else 'No web services',
            'database_services': ', '.join(database_services) if database_services else 'No database services'
        }
    
    def analyze_service_risks(self, nmap_result: NmapResult) -> Dict[str, Any]:
        """
        Analyze service-specific risks and categorize them
        
        Args:
            nmap_result: Nmap scan results
            
        Returns:
            Risk analysis summary
        """
        risk_analysis = {
            'high_risk_services': [],
            'medium_risk_services': [],
            'low_risk_services': [],
            'domain_controller_risk': False,
            'remote_access_risk': False,
            'web_exposure_risk': False,
            'database_exposure_risk': False
        }
        
        if not nmap_result.services:
            return risk_analysis
        
        for service in nmap_result.services:
            port = service.get('port')
            service_name = service.get('name', '').lower()
            
            service_info = f"Port {port}: {service_name}"
            
            # Categorize by risk level
            if port in self.high_risk_ports:
                risk_analysis['high_risk_services'].append(service_info)
            elif port in self.web_ports:
                risk_analysis['medium_risk_services'].append(service_info)
            else:
                risk_analysis['low_risk_services'].append(service_info)
            
            # Specific risk categories
            if port in self.dc_ports:
                risk_analysis['domain_controller_risk'] = True
            
            if port in [3389, 22, 23]:
                risk_analysis['remote_access_risk'] = True
            
            if port in self.web_ports:
                risk_analysis['web_exposure_risk'] = True
            
            if port in [1433, 3306, 5432]:
                risk_analysis['database_exposure_risk'] = True
        
        return risk_analysis
    
    def get_attack_surface_summary(self, nmap_result: NmapResult) -> str:
        """
        Generate attack surface summary
        
        Args:
            nmap_result: Nmap scan results
            
        Returns:
            Attack surface summary string
        """
        if not nmap_result.services:
            return "No services detected - minimal attack surface"
        
        risk_analysis = self.analyze_service_risks(nmap_result)
        
        summary_parts = []
        
        if risk_analysis['domain_controller_risk']:
            summary_parts.append("HIGH RISK: Domain Controller services detected")
        
        if risk_analysis['remote_access_risk']:
            summary_parts.append("HIGH RISK: Remote access services exposed")
        
        if risk_analysis['database_exposure_risk']:
            summary_parts.append("MEDIUM RISK: Database services exposed")
        
        if risk_analysis['web_exposure_risk']:
            summary_parts.append("MEDIUM RISK: Web services exposed")
        
        high_risk_count = len(risk_analysis['high_risk_services'])
        medium_risk_count = len(risk_analysis['medium_risk_services'])
        
        summary_parts.append(f"Attack Surface: {high_risk_count} high-risk, {medium_risk_count} medium-risk services")
        
        return "; ".join(summary_parts) if summary_parts else "Low risk attack surface detected"
