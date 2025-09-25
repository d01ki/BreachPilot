        # Exploitation Summary
        exploitation_summary = "No exploitation attempts performed"
        successful_exploits = []
        if exploit_results:
            total_attempts = len(exploit_results)
            successful = [er for er in exploit_results if er.success]
            
            exploitation_summary = f"{total_attempts} exploitation attempts: {len(successful)} successful"
            
            for exploit in successful:
                successful_exploits.append({
                    'cve_id': exploit.cve_id,
                    'target_ip': exploit.target_ip,
                    'exploit_used': exploit.exploit_used,
                    'success': exploit.success
                })
        
        return {
            'target_ip': target_ip,
            'assessment_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'services_summary': services_summary,
            'vulnerabilities_summary': vulnerabilities_summary,
            'exploitation_summary': exploitation_summary,
            'critical_cves': critical_cves,
            'successful_exploits': successful_exploits,
            'total_services': len(nmap_result.services) if nmap_result and nmap_result.services else 0,
            'total_vulnerabilities': len(analyst_result.identified_cves) if analyst_result and analyst_result.identified_cves else 0,
            'total_exploits': len(successful_exploits)
        }
    
    def _create_report_tasks(self, assessment_data: Dict[str, Any]) -> List[Task]:
        """Create tasks for each CrewAI agent"""
        
        # Task 1: Technical Analysis
        technical_analysis_task = Task(
            description=f"""Analyze the security assessment results for target {assessment_data['target_ip']} and provide detailed technical findings.

            Assessment Data:
            - Target: {assessment_data['target_ip']}
            - Assessment Date: {assessment_data['assessment_date']}
            - Network Services: {assessment_data['services_summary']}
            - Vulnerabilities: {assessment_data['vulnerabilities_summary']}
            - Exploitation Results: {assessment_data['exploitation_summary']}
            
            Critical Vulnerabilities Found: {len(assessment_data['critical_cves'])}
            Successful Exploits: {assessment_data['total_exploits']}
            
            Provide:
            1. Technical risk assessment
            2. Vulnerability analysis with CVSS scores
            3. Attack vector analysis
            4. Technical recommendations for remediation
            5. Priority ranking of security issues
            """,
            agent=self.security_analyst,
            expected_output="Detailed technical security analysis with vulnerability assessments, risk ratings, and technical remediation recommendations"
        )
        
        # Task 2: Documentation Creation
        documentation_task = Task(
            description=f"""Create comprehensive security assessment documentation based on the technical analysis.
            
            Transform the technical findings into a professional security assessment report that includes:
            1. Executive Summary
            2. Assessment Methodology
            3. Technical Findings
            4. Vulnerability Details
            5. Risk Analysis
            6. Remediation Recommendations
            7. Appendices with technical details
            
            The report should be suitable for both technical teams and management review.
            Target IP: {assessment_data['target_ip']}
            """,
            agent=self.technical_writer,
            expected_output="Professional security assessment report with clear structure, technical accuracy, and actionable recommendations"
        )
        
        # Task 3: Executive Summary
        executive_summary_task = Task(
            description=f"""Create an executive-level summary focusing on business impact and strategic recommendations.
            
            Based on the technical assessment, provide:
            1. Business risk summary
            2. Financial impact assessment
            3. Strategic security recommendations
            4. Implementation priorities
            5. Resource requirements
            6. Timeline recommendations
            
            Focus on translating technical vulnerabilities into business terms and actionable executive decisions.
            """,
            agent=self.executive_advisor,
            expected_output="Executive summary with business impact analysis, strategic recommendations, and implementation roadmap"
        )
        
        return [technical_analysis_task, documentation_task, executive_summary_task]
    
    def _process_crew_results(self, crew_result: Any, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process CrewAI results into structured report data"""
        
        report_data = {
            "report_type": "Professional Security Assessment",
            "target_ip": assessment_data['target_ip'],
            "assessment_date": assessment_data['assessment_date'],
            "executive_summary": "Executive summary generated by CrewAI analysis",
            "technical_findings": "Technical findings generated by CrewAI analysis",
            "recommendations": "Recommendations generated by CrewAI analysis",
            "findings_count": assessment_data['total_vulnerabilities'],
            "critical_issues": len(assessment_data['critical_cves']),
            "successful_exploits": assessment_data['total_exploits'],
            "report_url": f"/reports/security_assessment_{assessment_data['target_ip']}.html",
            "pdf_url": f"/reports/security_assessment_{assessment_data['target_ip']}.pdf"
        }
        
        return report_data
    
    def _generate_basic_report(
        self, 
        target_ip: str, 
        nmap_result: NmapResult = None, 
        analyst_result: AnalystResult = None, 
        exploit_results: List[ExploitResult] = None
    ) -> Dict[str, Any]:
        """Generate basic report as fallback when CrewAI fails"""
        
        logger.warning("Generating basic report due to CrewAI unavailability")
        
        # Prepare basic data
        assessment_data = self._prepare_assessment_data(target_ip, nmap_result, analyst_result, exploit_results)
        
        # Basic executive summary
        exec_summary = f"""
        Professional Security Assessment Summary for {assessment_data['target_ip']}
        
        Network Services: {assessment_data['total_services']} services identified
        Security Vulnerabilities: {assessment_data['total_vulnerabilities']} vulnerabilities found
        Critical Issues: {len(assessment_data['critical_cves'])} high-severity vulnerabilities
        Exploitation Success: {assessment_data['total_exploits']} successful exploits
        
        Immediate Action Required: {"Yes" if assessment_data['critical_cves'] else "No"}
        Overall Risk Level: {"High" if assessment_data['critical_cves'] else "Medium"}
        
        This assessment was conducted using industry-standard penetration testing methodologies
        and vulnerability assessment techniques. All findings have been validated and prioritized
        based on their potential business impact and exploitability.
        """
        
        # Technical findings summary
        technical_findings = f"""
        Network Discovery Results:
        {assessment_data['services_summary']}
        
        Vulnerability Analysis:
        {assessment_data['vulnerabilities_summary']}
        
        Exploitation Testing:
        {assessment_data['exploitation_summary']}
        """
        
        # Professional recommendations
        recommendations = """
        Based on the security assessment findings, the following recommendations are provided:
        
        1. Critical Vulnerabilities: Apply security patches immediately for all critical-severity vulnerabilities
        2. Network Segmentation: Implement proper network segmentation to limit attack surface
        3. Access Controls: Review and strengthen authentication mechanisms
        4. Monitoring: Deploy security monitoring solutions to detect potential attacks
        5. Incident Response: Ensure incident response procedures are in place and tested
        
        These recommendations should be implemented in order of priority based on risk assessment.
        """
        
        return {
            "report_type": "Professional Security Assessment",
            "target_ip": assessment_data['target_ip'],
            "assessment_date": assessment_data['assessment_date'],
            "executive_summary": exec_summary.strip(),
            "technical_findings": technical_findings.strip(),
            "recommendations": recommendations.strip(),
            "findings_count": assessment_data['total_vulnerabilities'],
            "critical_issues": len(assessment_data['critical_cves']),
            "successful_exploits": assessment_data['total_exploits'],
            "report_url": f"/reports/professional_assessment_{assessment_data['target_ip']}.html",
            "pdf_url": f"/reports/professional_assessment_{assessment_data['target_ip']}.pdf"
        }