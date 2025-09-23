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
            
            try {
                const response = await axios.post('/api/scan/start', {
                    target_ip: this.targetIp
                });
                this.sessionId = response.data.session_id;
                console.log('Scan started:', this.sessionId);
            } catch (error) {
                console.error('Error starting scan:', error);
                alert('Failed to start scan');
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
                console.log('PoC search results:', this.pocResults);
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
                
                console.log('PoC execution result:', response.data);
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
        
        // Utility Methods
        getCvssClass(score) {
            if (score >= 9.0) return 'bg-red-600';
            if (score >= 7.0) return 'bg-red-500';
            if (score >= 4.0) return 'bg-yellow-500';
            return 'bg-green-500';
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
                .replace(/`(.*?)`/g, '<code class="bg-gray-200 px-1 rounded">$1</code>')
                .replace(/\n\n/g, '</p><p class="mt-2">')
                .replace(/\n/g, '<br>');
            
            return `<p>${formatted}</p>`;
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
        console.log('BreachPilot frontend loaded');
        
        // Auto-refresh session status if we have a session
        if (this.sessionId) {
            setInterval(this.checkSessionStatus, 2000);
        }
    }
}).mount('#app');
