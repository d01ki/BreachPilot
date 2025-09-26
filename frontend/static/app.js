const { createApp } = Vue;

createApp({
    data() {
        return {
            targetIp: '',
            sessionId: null,
            currentStep: null,
            nmapResult: null,
            analystResult: null,
            debugMode: false,
            showRawOutput: false,
            expandedCves: {},
            
            // PoC Search functionality
            selectedCves: [],
            pocResults: [],
            pocSearching: false,
            exploitResults: [],
            executingPocs: {},
            visiblePocCode: {},
            visibleExploitOutput: {},
            
            // Report generation
            reportGenerating: false,
            reportResult: null
        }
    },
    
    computed: {
        nmapComplete() { return !!this.nmapResult; },
        analysisComplete() { return !!this.analystResult; }
    },
    
    methods: {
        async startScan() {
            if (!this.targetIp) return;
            
            try {
                const response = await axios.post('/api/scan/start', {
                    target_ip: this.targetIp
                });
                this.sessionId = response.data.session_id;
                console.log('Security assessment session started:', this.sessionId);
            } catch (error) {
                console.error('Error starting assessment:', error);
                alert('Failed to start security assessment: ' + (error.response?.data?.detail || error.message));
            }
        },
        
        async runStep(step) {
            this.currentStep = step;
            try {
                let response;
                switch(step) {
                    case 'nmap':
                        response = await axios.post(`/api/scan/${this.sessionId}/nmap`);
                        this.nmapResult = response.data;
                        console.log('Network scan completed:', this.nmapResult);
                        break;
                    case 'analyze':
                        response = await axios.post(`/api/scan/${this.sessionId}/analyze`);
                        this.analystResult = response.data;
                        console.log('Vulnerability analysis completed:', this.analystResult);
                        break;
                }
                this.currentStep = null;
            } catch (error) {
                console.error(`Error executing ${step}:`, error);
                alert(`Failed to execute ${step}: ${error.response?.data?.detail || error.message}`);
                this.currentStep = null;
            }
        },
        
        // Status indicator methods
        getStatusClass(step) {
            if (this.currentStep === step) return 'status-running';
            
            switch(step) {
                case 'nmap':
                    return this.nmapComplete ? 'status-completed' : 'status-pending';
                case 'analyze':
                    return this.analysisComplete ? 'status-completed' : 'status-pending';
                default:
                    return 'status-pending';
            }
        },
        
        // Enhanced Service Info extraction
        getServiceInfo(nmapResult) {
            if (!nmapResult || !nmapResult.raw_output) return null;
            
            const match = nmapResult.raw_output.match(/Service Info:\\s*(.+?)(?:\\n|$)/);
            if (match) {
                const serviceInfo = match[1].trim();
                return serviceInfo
                    .replace(/Host:\\s*([^;]+)/g, '<strong>Host:</strong> $1')
                    .replace(/OS:\\s*([^;]+)/g, '<strong>Operating System:</strong> $1')
                    .replace(/CPE:\\s*([^;]+)/g, '<strong>Common Platform Enumeration:</strong> <code class="text-xs">$1</code>');
            }
            return null;
        },
        
        getOSInfo(nmapResult) {
            if (nmapResult?.os_detection?.name) {
                return nmapResult.os_detection.name;
            }
            
            if (nmapResult?.raw_output) {
                const match = nmapResult.raw_output.match(/OS:\\s*([^;,\\n]+)/);
                if (match) {
                    return match[1].trim();
                }
            }
            
            return 'Not Detected';
        },
        
        isDomainController(nmapResult) {
            if (nmapResult?.os_detection?.is_domain_controller) {
                return true;
            }
            
            if (nmapResult?.raw_output) {
                const dcIndicators = [
                    /microsoft.*windows.*server/i,
                    /domain.*controller/i,
                    /active.*directory/i,
                    /ldap/i,
                    /kerberos/i,
                    /port.*389.*open/i,
                    /port.*636.*open/i,
                    /port.*88.*open/i
                ];
                
                return dcIndicators.some(pattern => pattern.test(nmapResult.raw_output));
            }
            
            return false;
        },
        
        // CVE Analysis Methods
        getSeverityBadgeClass(severity) {
            const sev = severity?.toLowerCase();
            switch(sev) {
                case 'critical': return 'bg-red-600 text-white';
                case 'high': return 'bg-red-500 text-white';
                case 'medium': return 'bg-yellow-500 text-white';
                case 'low': return 'bg-green-500 text-white';
                default: return 'bg-gray-500 text-white';
            }
        },
        
        assessImpactLevel(cvssScore) {
            if (!cvssScore) return 'Assessment Required';
            if (cvssScore >= 9.0) return 'Critical Business Impact';
            if (cvssScore >= 7.0) return 'High Business Impact';
            if (cvssScore >= 4.0) return 'Medium Business Impact';
            return 'Low Business Impact';
        },
        
        formatTechnicalDetails(details) {
            if (!details) return '';
            
            let formatted = details
                .replace(/\\*\\*(.*?)\\*\\*/g, '<strong>$1</strong>')
                .replace(/\\*(.*?)\\*/g, '<em>$1</em>')
                .replace(/`(.*?)`/g, '<code class="bg-gray-200 px-1 rounded text-xs">$1</code>')
                .replace(/\\n\\n/g, '</p><p class="mt-3">')
                .replace(/\\n-\\s/g, '<br>• ')
                .replace(/\\n/g, '<br>');
            
            return `<p class="leading-relaxed">${formatted}</p>`;
        },
        
        formatLinkName(name) {
            const nameMap = {
                'nvd': 'NVD Database',
                'mitre': 'MITRE Corporation',
                'exploit-db': 'Exploit Database',
                'cve': 'CVE Details'
            };
            return nameMap[name.toLowerCase()] || name.toUpperCase();
        },
        
        // PoC Search Methods
        getSelectedCves() {
            return this.selectedCves;
        },
        
        async searchPoCs() {
            if (!this.selectedCves.length) {
                alert('Please select at least one CVE for exploit analysis');
                return;
            }
            
            this.pocSearching = true;
            try {
                const response = await axios.post(`/api/scan/${this.sessionId}/poc`, {
                    selected_cves: this.selectedCves,
                    limit: 4
                });
                this.pocResults = response.data;
                console.log('Exploit search results:', this.pocResults);
            } catch (error) {
                console.error('Error searching exploits:', error);
                alert('Failed to search exploits: ' + (error.response?.data?.detail || error.message));
            } finally {
                this.pocSearching = false;
            }
        },
        
        async executePoc(cveId, pocIndex) {
            const key = `${cveId}-${pocIndex}`;
            this.executingPocs[key] = true;
            
            try {
                const response = await axios.post(`/api/scan/${this.sessionId}/exploit/by_index`, {
                    cve_id: cveId,
                    poc_index: pocIndex,
                    target_ip: this.targetIp
                });
                
                this.exploitResults.push({
                    ...response.data,
                    cve_id: cveId,
                    poc_index: pocIndex
                });
                
                console.log('Exploit execution result:', response.data);
                
            } catch (error) {
                console.error('Error executing exploit:', error);
                alert('Failed to execute exploit: ' + (error.response?.data?.detail || error.message));
            } finally {
                this.executingPocs[key] = false;
            }
        },
        
        isExecuting(cveId, pocIndex) {
            const key = `${cveId}-${pocIndex}`;
            return !!this.executingPocs[key];
        },
        
        getExploitResult(cveId, pocIndex) {
            return this.exploitResults.find(r => r.cve_id === cveId && r.poc_index === pocIndex);
        },
        
        getExploitStatus(result) {
            if (!result) return 'pending';
            if (result.success) return 'success';
            if (result.error_details) return 'error';
            return 'failed';
        },
        
        getExploitStatusText(result) {
            if (!result) return 'Pending';
            if (result.success) return 'VULNERABLE - EXPLOIT SUCCESSFUL';
            if (result.error_details) return 'EXPLOIT FAILED - ' + result.error_details;
            if (result.execution_output && result.execution_output.includes('simulation')) return 'SIMULATION - NOT REAL EXPLOIT';
            return 'EXPLOIT FAILED';
        },
        
        getExploitStatusClass(result) {
            if (result && result.execution_output && result.execution_output.includes('simulation')) {
                return 'text-yellow-600 bg-yellow-50 border-yellow-200';
            }
            
            const status = this.getExploitStatus(result);
            switch (status) {
                case 'success': return 'text-green-600 bg-green-50 border-green-200';
                case 'error': return 'text-red-600 bg-red-50 border-red-200';
                case 'failed': return 'text-orange-600 bg-orange-50 border-orange-200';
                default: return 'text-gray-600 bg-gray-50 border-gray-200';
            }
        },
        
        // Report Generation Methods
        async generateReport() {
            this.reportGenerating = true;
            try {
                const response = await axios.post(`/api/scan/${this.sessionId}/report`);
                this.reportResult = response.data;
                console.log('Security assessment report generated:', this.reportResult);
            } catch (error) {
                console.error('Error generating report:', error);
                alert('Failed to generate report: ' + (error.response?.data?.detail || error.message));
            } finally {
                this.reportGenerating = false;
            }
        },
        
        // Enhanced download methods with proper error handling and fallbacks
        async viewReport() {
            if (!this.targetIp) {
                alert('Target IP not available');
                return;
            }
            
            try {
                // First check if reports are available
                const listResponse = await axios.get(`/api/reports/list/${this.targetIp}`);
                const availableReports = listResponse.data.reports;
                
                const htmlReport = availableReports.find(r => r.type === 'html');
                if (htmlReport) {
                    const reportUrl = htmlReport.download_url;
                    console.log('Opening HTML report:', reportUrl);
                    window.open(reportUrl, '_blank');
                } else {
                    alert('HTML report not found. Please generate a report first.');
                }
            } catch (error) {
                console.error('Error checking reports:', error);
                // Fallback to direct URL
                const reportUrl = `/api/reports/download/html/${this.targetIp}`;
                console.log('Fallback: Opening HTML report:', reportUrl);
                window.open(reportUrl, '_blank');
            }
        },
        
        async downloadReport() {
            if (!this.targetIp) {
                alert('Target IP not available');
                return;
            }
            
            try {
                console.log('Starting PDF download for:', this.targetIp);
                
                // First check if PDF report is available
                const listResponse = await axios.get(`/api/reports/list/${this.targetIp}`);
                const availableReports = listResponse.data.reports;
                console.log('Available reports:', availableReports);
                
                const pdfReport = availableReports.find(r => r.type === 'pdf');
                if (!pdfReport) {
                    // Try to find any report and suggest alternatives
                    if (availableReports.length > 0) {
                        const alternatives = availableReports.map(r => r.type).join(', ');
                        alert(`PDF report not found. Available formats: ${alternatives}. Please generate a report first or try a different format.`);
                    } else {
                        alert('No reports found. Please generate a report first.');
                    }
                    return;
                }
                
                const pdfUrl = pdfReport.download_url;
                console.log('PDF download URL:', pdfUrl);
                
                // Use the robust download method
                await this.downloadReportWithFetch(pdfUrl, `security_assessment_${this.targetIp}.pdf`);
                
            } catch (error) {
                console.error('Error in downloadReport:', error);
                
                // Fallback to direct download attempt
                console.log('Attempting fallback PDF download');
                const fallbackUrl = `/api/reports/download/pdf/${this.targetIp}`;
                
                try {
                    await this.downloadReportWithFetch(fallbackUrl, `security_assessment_${this.targetIp}.pdf`);
                } catch (fallbackError) {
                    console.error('Fallback download also failed:', fallbackError);
                    alert('PDF download failed. Please ensure a report has been generated and try again.');
                }
            }
        },
        
        async downloadReportWithFetch(url, filename) {
            try {
                console.log('Downloading from URL:', url);
                
                const response = await fetch(url, {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/pdf'
                    }
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const contentType = response.headers.get('content-type');
                console.log('Response content type:', contentType);
                
                // Get the file as a blob
                const blob = await response.blob();
                console.log('Downloaded blob size:', blob.size, 'bytes');
                
                if (blob.size === 0) {
                    throw new Error('Downloaded file is empty');
                }
                
                // Create download link
                const url_object = window.URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url_object;
                link.download = filename;
                
                // Trigger download
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                
                // Clean up
                window.URL.revokeObjectURL(url_object);
                
                console.log('PDF download completed successfully');
                
            } catch (error) {
                console.error('Download with fetch failed:', error);
                throw error;
            }
        },
        
        // Test method to create files for immediate testing
        async createTestFiles() {
            if (!this.targetIp) {
                alert('Please enter a target IP first');
                return;
            }
            
            try {
                console.log('Creating test files for:', this.targetIp);
                const response = await axios.get(`/api/reports/test/${this.targetIp}`);
                console.log('Test files created:', response.data);
                alert('Test files created successfully! You can now test the download buttons.');
                
                // Set report result so buttons become active
                this.reportResult = {
                    message: "Test report generated",
                    html_download_url: response.data.html_url,
                    pdf_download_url: response.data.pdf_url,
                    report_generated: true
                };
                
            } catch (error) {
                console.error('Error creating test files:', error);
                alert('Failed to create test files: ' + (error.response?.data?.detail || error.message));
            }
        },
        
        // UI Toggle Methods
        togglePocCode(cveId, pocIndex) {
            const key = `${cveId}-${pocIndex}`;
            this.visiblePocCode[key] = !this.visiblePocCode[key];
        },
        
        isPocCodeVisible(cveId, pocIndex) {
            const key = `${cveId}-${pocIndex}`;
            return !!this.visiblePocCode[key];
        },
        
        toggleExploitOutput(cveId, pocIndex) {
            const key = `${cveId}-${pocIndex}`;
            this.visibleExploitOutput[key] = !this.visibleExploitOutput[key];
        },
        
        isExploitOutputVisible(cveId, pocIndex) {
            const key = `${cveId}-${pocIndex}`;
            return !!this.visibleExploitOutput[key];
        },
        
        toggleCveDetails(cveId) {
            this.expandedCves[cveId] = !this.expandedCves[cveId];
        },
        
        // Enhanced CVE Link Utilities
        getLinkClass(linkName) {
            const name = linkName.toLowerCase();
            if (name.includes('nvd')) return 'bg-blue-100 text-blue-800 hover:bg-blue-200';
            if (name.includes('mitre')) return 'bg-purple-100 text-purple-800 hover:bg-purple-200';
            if (name.includes('exploit')) return 'bg-red-100 text-red-800 hover:bg-red-200';
            if (name.includes('cve')) return 'bg-gray-100 text-gray-800 hover:bg-gray-200';
            return 'bg-gray-100 text-gray-800 hover:bg-gray-200';
        },
        
        // Utility Methods
        getCvssClass(score) {
            if (!score) return 'cvss-info';
            if (score >= 9.0) return 'cvss-critical';
            if (score >= 7.0) return 'cvss-high';
            if (score >= 4.0) return 'cvss-medium';
            return 'cvss-low';
        },
        
        getPortRisk(port, service) {
            const highRiskPorts = [22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5985, 5986];
            const criticalServices = ['ssh', 'telnet', 'ftp', 'smtp', 'http', 'https', 'smb', 'rdp', 'winrm'];
            
            if (criticalServices.some(s => service?.toLowerCase().includes(s))) return 'HIGH';
            if (highRiskPorts.includes(parseInt(port))) return 'MEDIUM';
            return 'LOW';
        },
        
        getPortRiskClass(port, service) {
            const risk = this.getPortRisk(port, service);
            switch(risk) {
                case 'HIGH': return 'bg-red-500';
                case 'MEDIUM': return 'bg-yellow-500';
                default: return 'bg-green-500';
            }
        },
        
        formatTimestamp(timestamp) {
            if (!timestamp) return '';
            return new Date(timestamp * 1000).toLocaleString();
        },
        
        async downloadResults() {
            try {
                const response = await axios.get(`/api/scan/${this.sessionId}/results`);
                const data = {
                    scan_info: {
                        target_ip: this.targetIp,
                        session_id: this.sessionId,
                        timestamp: new Date().toISOString(),
                        assessment_type: 'Professional Security Assessment'
                    },
                    network_scan: this.nmapResult,
                    vulnerability_analysis: this.analystResult,
                    exploit_analysis: this.pocResults,
                    exploit_results: this.exploitResults
                };
                
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `security_assessment_raw_${this.targetIp}_${new Date().toISOString().split('T')[0]}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
            } catch (error) {
                console.error('Error downloading results:', error);
                alert('Failed to download results');
            }
        },
        
        reset() {
            // Reset all data
            this.targetIp = '';
            this.sessionId = null;
            this.currentStep = null;
            this.nmapResult = null;
            this.analystResult = null;
            this.debugMode = false;
            this.showRawOutput = false;
            this.expandedCves = {};
            
            // Reset PoC data
            this.selectedCves = [];
            this.pocResults = [];
            this.pocSearching = false;
            this.exploitResults = [];
            this.executingPocs = {};
            this.visiblePocCode = {};
            this.visibleExploitOutput = {};
            
            // Reset report data
            this.reportGenerating = false;
            this.reportResult = null;
        }
    },
    
    mounted() {
        console.log('BreachPilot Professional Security Assessment Framework loaded');
        console.log('Enhanced PDF download system active');
        console.log('Available endpoints:');
        console.log('  - PDF download: /api/reports/download/pdf/{target_ip}');
        console.log('  - HTML report: /api/reports/download/html/{target_ip}');
        console.log('  - List reports: /api/reports/list/{target_ip}');
        console.log('  - Test creation: /api/reports/test/{target_ip}');
    }
}).mount('#app');
