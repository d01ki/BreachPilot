    def _fallback_analysis(self, target_ip: str, nmap_result: NmapResult) -> AnalystResult:
        """Fallback analysis when CrewAI fails"""
        
        logger.warning("Using fallback vulnerability analysis")
        
        # Extract service data
        services_data = self._extract_service_data(nmap_result)
        
        # Generate CVEs using standard analysis
        cves = self._generate_professional_cves(services_data['services'])[:5]
        
        return AnalystResult(
            target_ip=target_ip,
            identified_cves=cves,
            risk_assessment=self._generate_risk_assessment(cves),
            priority_vulnerabilities=[cve.cve_id for cve in cves if cve.severity in ['Critical', 'High']]
        )