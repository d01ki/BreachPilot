const { createApp } = Vue;
const API_URL = window.location.origin;

createApp({
    data() {
        return {
            targetIp: '', sessionId: null, currentStep: '', loading: false,
            osintResult: null, nmapResult: null, analystResult: null,
            pocResults: [], exploitResults: [],
            osintComplete: false, nmapComplete: false, analysisComplete: false,
            selectedCves: [], pocSearchStarted: false, pocLimit: 4,
            expandedCves: {}, expandedCode: {}, expandedOutputs: {},
            debugMode: false, showRawOutput: false,
            executingPocs: new Set(),
        }
    },
    methods: {
        async startScan() {
            if (!this.targetIp) return;
            try {
                const res = await axios.post(`${API_URL}/api/scan/start`, { target_ip: this.targetIp });
                this.sessionId = res.data.session_id;
                this.startPolling();
                setTimeout(() => this.runStep('osint'), 500);
            } catch (error) {
                console.error('Failed to start scan:', error);
                alert('Failed to start scan: ' + (error.response?.data?.detail || error.message));
            }
        },
        
        async runStep(step) {
            this.currentStep = step;
            try {
                const url = `${API_URL}/api/scan/${this.sessionId}/${step === 'analyze' ? 'analyze' : step}`;
                console.log(`Running step: ${step}, URL: ${url}`);
                
                const res = await axios.post(url);
                console.log(`Step ${step} response:`, res.data);
                
                if (step === 'osint') { 
                    this.osintResult = res.data; 
                    this.osintComplete = true;
                }
                if (step === 'nmap') { 
                    this.nmapResult = res.data; 
                    this.nmapComplete = true;
                }
                if (step === 'analyze') { 
                    this.analystResult = res.data; 
                    this.analysisComplete = true;
                }
                this.currentStep = '';
            } catch (error) {
                console.error(`Step ${step} failed:`, error);
                this.currentStep = '';
                alert(`Step ${step} failed: ` + (error.response?.data?.detail || error.message));
            }
        },
        
        async searchPocs() {
            try {
                this.pocSearchStarted = true;
                this.currentStep = 'poc_search';
                
                const payload = {
                    selected_cves: this.selectedCves,
                    limit: parseInt(this.pocLimit)
                };
                
                console.log('Searching PoCs with payload:', payload);
                
                const res = await axios.post(`${API_URL}/api/scan/${this.sessionId}/poc`, payload);
                this.pocResults = res.data;
                
                console.log('PoC search completed:', this.pocResults);
                
                // Log summary
                const totalPocs = this.getTotalPoCs();
                const githubRepos = this.getGitHubRepos();
                console.log(`PoC Search Summary: ${totalPocs} total PoCs, ${githubRepos} GitHub repositories`);
                
                this.currentStep = '';
            } catch (error) {
                console.error('PoC search failed:', error);
                this.currentStep = '';
                alert('PoC search failed: ' + (error.response?.data?.detail || error.message));
            }
        },
        
        async executeSinglePoc(cveId, pocIndex) {
            const pocKey = `${cveId}_${pocIndex}`;
            if (this.executingPocs.has(pocKey)) {
                return;
            }
            
            this.executingPocs.add(pocKey);
            
            try {
                console.log(`Executing single PoC via git clone: ${cveId} #${pocIndex}`);
                
                const payload = {
                    cve_id: cveId,
                    poc_index: pocIndex,
                    target_ip: this.targetIp
                };
                
                const res = await axios.post(`${API_URL}/api/scan/${this.sessionId}/exploit/by_index`, payload);
                
                console.log(`Git clone execution result:`, res.data);
                
                this.updateExploitResult(res.data);
                
                if (res.data.success) {
                    this.showNotification(`✅ ${cveId} PoC #${pocIndex + 1} executed successfully via git clone!`, 'success');
                } else {
                    this.showNotification(`❌ ${cveId} PoC #${pocIndex + 1} failed: ${res.data.failure_reason || 'Unknown error'}`, 'error');
                }
                
            } catch (error) {
                console.error(`PoC execution failed:`, error);
                this.showNotification(`❌ PoC execution failed: ${error.response?.data?.detail || error.message}`, 'error');
            } finally {
                this.executingPocs.delete(pocKey);
            }
        },
        
        async executeAllPocs(cveId) {
            try {
                console.log(`Executing all PoCs via git clone for: ${cveId}`);
                
                const payload = {
                    cve_id: cveId,
                    target_ip: this.targetIp
                };
                
                const res = await axios.post(`${API_URL}/api/scan/${this.sessionId}/exploit/multi`, payload);
                
                console.log(`Multi-PoC git clone execution results:`, res.data);
                
                res.data.forEach(result => this.updateExploitResult(result));
                
                const successful = res.data.filter(r => r.success).length;
                const message = `${cveId}: ${successful}/${res.data.length} PoCs executed successfully via git clone`;
                this.showNotification(message, successful > 0 ? 'success' : 'error');
                
            } catch (error) {
                console.error(`Multi-PoC execution failed:`, error);
                this.showNotification(`❌ Multi-PoC execution failed: ${error.response?.data?.detail || error.message}`, 'error');
            }
        },
        
        updateExploitResult(newResult) {
            const existingIndex = this.exploitResults.findIndex(r => 
                r.cve_id === newResult.cve_id && r.poc_index === newResult.poc_index
            );
            
            if (existingIndex >= 0) {
                this.exploitResults[existingIndex] = newResult;
            } else {
                this.exploitResults.push(newResult);
            }
            
            this.exploitResults.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        },
        
        getExploitResultsForPoc(cveId, pocIndex) {
            return this.exploitResults.filter(r => 
                r.cve_id === cveId && (r.poc_index === pocIndex || r.poc_index === pocIndex + 1)
            );
        },
        
        async cleanupFiles() {
            try {
                await axios.delete(`${API_URL}/api/scan/${this.sessionId}/exploit_files?keep_successful=true`);
                this.showNotification('✅ Temporary git repositories cleaned up successfully', 'success');
            } catch (error) {
                console.error('File cleanup failed:', error);
                this.showNotification('❌ File cleanup failed', 'error');
            }
        },
        
        async downloadResults() {
            try {
                const results = {
                    session_id: this.sessionId,
                    target_ip: this.targetIp,
                    timestamp: new Date().toISOString(),
                    osint_result: this.osintResult,
                    nmap_result: this.nmapResult,
                    analyst_result: this.analystResult,
                    poc_results: this.pocResults,
                    exploit_results: this.exploitResults
                };
                
                const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `breachpilot_results_${this.targetIp}_${new Date().toISOString().split('T')[0]}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                
                this.showNotification('✅ Results downloaded successfully', 'success');
            } catch (error) {
                console.error('Download failed:', error);
                this.showNotification('❌ Download failed', 'error');
            }
        },
        
        showNotification(message, type = 'info') {
            const notification = document.createElement('div');
            notification.className = `fixed top-4 right-4 p-3 rounded shadow-lg z-50 ${
                type === 'success' ? 'bg-green-500 text-white' :
                type === 'error' ? 'bg-red-500 text-white' :
                'bg-blue-500 text-white'
            }`;
            notification.textContent = message;
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.remove();
            }, 5000);
        },
        
        getCvssClass(score) {
            if (!score) return 'bg-gray-500';
            if (score >= 9) return 'bg-red-600';
            if (score >= 7) return 'bg-orange-500';
            if (score >= 4) return 'bg-yellow-500';
            return 'bg-green-500';
        },
        
        getSourceBadgeClass(source) {
            const classes = {
                'GitHub Repository': 'bg-gray-800 text-white',
                'GitHub Code': 'bg-gray-700 text-white',
                'ExploitDB': 'bg-red-600 text-white',
                'PacketStorm': 'bg-orange-600 text-white'
            };
            return classes[source] || 'bg-blue-600 text-white';
        },
        
        getTotalPoCs() {
            return this.pocResults.reduce((total, result) => total + result.available_pocs.length, 0);
        },
        
        getGitHubRepos() {
            return this.pocResults.reduce((total, result) => 
                total + result.available_pocs.filter(poc => poc.source === 'GitHub Repository').length, 0);
        },
        
        toggleCode(cveId, pocIndex) {
            const key = `${cveId}_${pocIndex}`;
            this.expandedCode[key] = !this.expandedCode[key];
        },
        
        toggleExploitOutput(cveId, pocIndex) {
            const key = `${cveId}_${pocIndex}`;
            this.expandedOutputs[key] = !this.expandedOutputs[key];
        },
        
        formatTimestamp(timestamp) {
            return new Date(timestamp).toLocaleString();
        },
        
        async loadResults() {
            try {
                const res = await axios.get(`${API_URL}/api/scan/${this.sessionId}/results`);
                const r = res.data;
                
                if (r.osint_result && !this.osintComplete) {
                    this.osintResult = r.osint_result;
                    this.osintComplete = true;
                }
                if (r.nmap_result && !this.nmapComplete) {
                    this.nmapResult = r.nmap_result;
                    this.nmapComplete = true;
                }
                if (r.analyst_result && !this.analysisComplete) {
                    this.analystResult = r.analyst_result;
                    this.analysisComplete = true;
                }
                if (r.poc_results) {
                    if (!this.pocSearchStarted || JSON.stringify(r.poc_results) !== JSON.stringify(this.pocResults)) {
                        this.pocResults = r.poc_results;
                        if (r.poc_results.length > 0) {
                            this.pocSearchStarted = true;
                        }
                    }
                }
                if (r.exploit_results) {
                    r.exploit_results.forEach(newResult => {
                        const existingIndex = this.exploitResults.findIndex(existing => 
                            existing.cve_id === newResult.cve_id && 
                            existing.poc_index === newResult.poc_index &&
                            existing.timestamp === newResult.timestamp
                        );
                        
                        if (existingIndex < 0) {
                            this.exploitResults.push(newResult);
                        }
                    });
                    
                    this.exploitResults.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
                }
            } catch (error) {
                console.error('Failed to load results:', error);
            }
        },
        
        startPolling() {
            setInterval(() => {
                if (this.sessionId) {
                    this.loadResults();
                }
            }, 3000);
        },
        
        reset() {
            Object.assign(this.$data, this.$options.data());
        },
        
        toggleCveDetails(cveId) {
            this.expandedCves[cveId] = !this.expandedCves[cveId];
        },
        
        formatCveExplanation(explanation) {
            if (!explanation) return '';
            
            return explanation
                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                .replace(/\*(.*?)\*/g, '<em>$1</em>')
                .replace(/\n\n/g, '</p><p>')
                .replace(/\n/g, '<br>')
                .replace(/^/, '<p>')
                .replace(/$/, '</p>');
        },
        
        getPortRisk(port, service) {
            const highRiskPorts = [445, 3389, 135, 139, 88, 389, 636, 1433, 3306, 5432];
            const mediumRiskPorts = [80, 443, 21, 22, 23, 25, 53, 110, 143, 993, 995, 587, 465];
            
            if (highRiskPorts.includes(port)) return 'HIGH';
            if (mediumRiskPorts.includes(port)) return 'MED';
            return 'LOW';
        },
        
        getPortRiskClass(port, service) {
            const risk = this.getPortRisk(port, service);
            if (risk === 'HIGH') return 'bg-red-600';
            if (risk === 'MED') return 'bg-yellow-500';
            return 'bg-green-500';
        }
    },
    
    computed: {
        isExecutingPoc() {
            return (cveId, pocIndex) => {
                return this.executingPocs.has(`${cveId}_${pocIndex}`);
            };
        },
        
        successfulExploits() {
            return this.exploitResults.filter(r => r.success);
        },
        
        totalExploitAttempts() {
            return this.exploitResults.length;
        },
        
        exploitSuccessRate() {
            if (this.totalExploitAttempts === 0) return 0;
            return Math.round((this.successfulExploits.length / this.totalExploitAttempts) * 100);
        }
    },
    
    mounted() {
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('debug') === 'true') {
            this.debugMode = true;
        }
        
        const sessionFromUrl = urlParams.get('session');
        if (sessionFromUrl) {
            this.sessionId = sessionFromUrl;
            this.startPolling();
            this.loadResults();
        }
    }
}).mount('#app');
