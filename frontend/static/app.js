const { createApp } = Vue;

createApp({
    data() {
        return {
            targetIp: '',
            sessionId: null,
            currentStep: null,
            osintResult: null,
            nmapResult: null,
            analystResult: null,
            debugMode: false,
            showRawOutput: false,
            expandedCves: {},
            autoScanActive: false,
            
            // PoC Search functionality
            selectedCves: [],
            pocResults: [],
            pocSearching: false,
            exploitResults: [],
            executingPocs: {},
            visiblePocCode: {},
            visibleExploitOutput: {}
        }
    },
    
    computed: {
        osintComplete() { return !!this.osintResult; },
        nmapComplete() { return !!this.nmapResult; },
        analysisComplete() { return !!this.analystResult; }
    },
    
    methods: {
        async startScan() {
            if (!this.targetIp) return;
            
            this.autoScanActive = true;
            try {
                const response = await axios.post('/api/scan/start', {
                    target_ip: this.targetIp
                });
                this.sessionId = response.data.session_id;
                console.log('🚀 Auto-scan started:', this.sessionId);
                
                // Start polling for auto-scan results
                this.pollResults();
            } catch (error) {
                console.error('Error starting scan:', error);
                alert('Failed to start scan');
                this.autoScanActive = false;
            }
        },
        
        async pollResults() {
            if (!this.sessionId) return;
            
            try {
                const response = await axios.get(`/api/scan/${this.sessionId}/results`);
                const data = response.data;
                
                // Update results as they become available
                if (data.osint_result && !this.osintResult) {
                    this.osintResult = data.osint_result;
                    console.log('✅ OSINT completed automatically');
                }
                
                if (data.nmap_result && !this.nmapResult) {
                    this.nmapResult = data.nmap_result;
                    console.log('✅ Nmap completed automatically');
                }
                
                // Update current step based on session status
                if (data.current_step) {
                    this.currentStep = data.current_step;
                }
                
                // Stop auto-scan when both OSINT and Nmap are complete
                if (this.osintResult && this.nmapResult) {
                    this.autoScanActive = false;
                    this.currentStep = 'analysis';
                    console.log('🎉 Auto-scan completed! Ready for CVE analysis.');
                    return;
                }
                
                // Continue polling if auto-scan is still active
                if (this.autoScanActive) {
                    setTimeout(() => this.pollResults(), 2000);
                }
                
            } catch (error) {
                console.error('Error polling results:', error);
                this.autoScanActive = false;
            }
        },
        
        async runStep(step) {
            this.currentStep = step;
            try {
                let response;
                switch(step) {
                    case 'osint':
                        response = await axios.post(`/api/scan/${this.sessionId}/osint`);
                        this.osintResult = response.data;
                        break;
                    case 'nmap':
                        response = await axios.post(`/api/scan/${this.sessionId}/nmap`);
                        this.nmapResult = response.data;
                        console.log('Nmap result received:', this.nmapResult);
                        break;
                    case 'analyze':
                        response = await axios.post(`/api/scan/${this.sessionId}/analyze`);
                        this.analystResult = response.data;
                        break;
                }
                this.currentStep = null;
            } catch (error) {
                console.error(`Error running ${step}:`, error);
                alert(`Failed to run ${step}`);
                this.currentStep = null;
            }
        },
        
        // Enhanced Service Info extraction
        getServiceInfo(nmapResult) {
            if (!nmapResult || !nmapResult.raw_output) return null;
            
            // Extract Service Info line from raw output
            const match = nmapResult.raw_output.match(/Service Info:\s*(.+?)(?:\n|$)/);
            if (match) {
                const serviceInfo = match[1].trim();
                // Format service info with icons and better display
                return serviceInfo
                    .replace(/Host:\s*([^;]+)/g, '<strong>🖥️ Host:</strong> $1')
                    .replace(/OS:\s*([^;]+)/g, '<strong>💻 OS:</strong> $1')
                    .replace(/CPE:\s*([^;]+)/g, '<strong>🔧 CPE:</strong> <code class="text-xs">$1</code>');
            }
            return null;
        },
        
        getOSInfo(nmapResult) {
            if (nmapResult?.os_detection?.name) {
                return nmapResult.os_detection.name;
            }
            
            // Extract from Service Info as fallback
            if (nmapResult?.raw_output) {
                const match = nmapResult.raw_output.match(/OS:\s*([^;,\n]+)/);
                if (match) {
                    return match[1].trim();
                }
            }
            
            return 'Unknown';
        },
        
        isDomainController(nmapResult) {
            // Check explicit DC detection
            if (nmapResult?.os_detection?.is_domain_controller) {
                return true;
            }
            
            // Check for common DC indicators in raw output
            if (nmapResult?.raw_output) {
                const dcIndicators = [
                    /microsoft.*windows.*server/i,
                    /domain.*controller/i,
                    /active.*directory/i,
                    /ldap/i,
                    /kerberos/i,
                    /port.*389.*open/i,  // LDAP
                    /port.*636.*open/i,  // LDAPS
                    /port.*88.*open/i    // Kerberos
                ];
                
                return dcIndicators.some(pattern => pattern.test(nmapResult.raw_output));
            }
            
            return false;
        },
        
        // PoC Search Methods
        getSelectedCves() {
            return this.selectedCves;
        },
        
        async searchPoCs() {
            if (!this.selectedCves.length) {
                alert('Please select at least one CVE');
                return;
            }
            
            this.pocSearching = true;
            try {
                const response = await axios.post(`/api/scan/${this.sessionId}/poc`, {
                    selected_cves: this.selectedCves,
                    limit: 4
                });
                this.pocResults = response.data;
                console.log('🔍 PoC search results:', this.pocResults);
                
                // Show notification for Zerologon auto-preparation
                const zerologonResult = this.pocResults.find(r => r.cve_id === 'CVE-2020-1472');
                if (zerologonResult && zerologonResult.available_pocs.some(p => p.source === 'BreachPilot Built-in')) {
                    console.log('🎯 Zerologon PoC auto-prepared and ready!');
                }
            } catch (error) {
                console.error('Error searching PoCs:', error);
                alert('Failed to search PoCs');
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
                
                // Store the result
                this.exploitResults.push({
                    ...response.data,
                    cve_id: cveId,
                    poc_index: pocIndex
                });
                
                console.log('🎯 PoC execution result:', response.data);
                
                // Special logging for Zerologon
                if (cveId === 'CVE-2020-1472') {
                    console.log('🏰 Zerologon execution completed!', response.data.success ? 'VULNERABLE!' : 'Not vulnerable');
                }
                
            } catch (error) {
                console.error('Error executing PoC:', error);
                alert('Failed to execute PoC');
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
        
        getLinkIcon(linkName) {
            const name = linkName.toLowerCase();
            if (name.includes('nvd')) return '🛡️';
            if (name.includes('mitre')) return '⚡';
            if (name.includes('exploit')) return '💥';
            if (name.includes('cve')) return '🔍';
            return '🔗';
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
        
        formatCveExplanation(explanation) {
            if (!explanation) return '';
            
            // Convert markdown-like formatting to HTML
            let formatted = explanation
                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                .replace(/\*(.*?)\*/g, '<em>$1</em>')
                .replace(/`(.*?)`/g, '<code class="bg-gray-200 px-1 rounded text-xs">$1</code>')
                .replace(/\n\n/g, '</p><p class="mt-3">')
                .replace(/\n-\s/g, '<br>• ')
                .replace(/\n/g, '<br>');
            
            return `<p class="leading-relaxed">${formatted}</p>`;
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
                        timestamp: new Date().toISOString()
                    },
                    osint_result: this.osintResult,
                    nmap_result: this.nmapResult,
                    analyst_result: this.analystResult,
                    poc_results: this.pocResults,
                    exploit_results: this.exploitResults
                };
                
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `breachpilot_results_${this.targetIp}_${new Date().toISOString().split('T')[0]}.json`;
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
            this.osintResult = null;
            this.nmapResult = null;
            this.analystResult = null;
            this.debugMode = false;
            this.showRawOutput = false;
            this.expandedCves = {};
            this.autoScanActive = false;
            
            // Reset PoC data
            this.selectedCves = [];
            this.pocResults = [];
            this.pocSearching = false;
            this.exploitResults = [];
            this.executingPocs = {};
            this.visiblePocCode = {};
            this.visibleExploitOutput = {};
        }
    },
    
    mounted() {
        console.log('🛡️ BreachPilot frontend loaded with enhanced features');
    }
}).mount('#app');
