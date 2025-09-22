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
            aiAgentStatus: 'Idle',  // Track AI agent status
            pocSearchProgress: '',  // Track search progress
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
                console.log(`🚀 Running ${step} with AI agents...`);
                
                const res = await axios.post(url);
                console.log(`✅ ${step} completed:`, res.data);
                
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
                    console.log(`📊 CVE Analysis found ${this.analystResult?.identified_cves?.length || 0} vulnerabilities`);
                }
                this.currentStep = '';
            } catch (error) {
                console.error(`❌ ${step} failed:`, error);
                this.currentStep = '';
                alert(`${step} failed: ` + (error.response?.data?.detail || error.message));
            }
        },
        
        async searchPocs() {
            try {
                this.pocSearchStarted = true;
                this.currentStep = 'poc_search';
                this.aiAgentStatus = 'Initializing AI Agents...';
                this.pocSearchProgress = 'Starting AI-powered PoC search...';
                
                const payload = {
                    selected_cves: this.selectedCves,
                    limit: parseInt(this.pocLimit)
                };
                
                console.log('🤖 Starting AI-enhanced PoC search:', payload);
                
                // Set progress updates
                const progressMessages = [
                    '🔍 AI agents analyzing CVE patterns...',
                    '🎯 Searching GitHub repositories...',
                    '📊 Evaluating PoC quality...',
                    '🤖 AI agents ranking exploits...',
                    '✅ Finalizing search results...'
                ];
                
                let progressIndex = 0;
                const progressInterval = setInterval(() => {
                    if (progressIndex < progressMessages.length) {
                        this.pocSearchProgress = progressMessages[progressIndex];
                        progressIndex++;
                    }
                }, 3000);
                
                const res = await axios.post(`${API_URL}/api/scan/${this.sessionId}/poc`, payload);
                
                clearInterval(progressInterval);
                
                console.log('🎯 AI-enhanced PoC search results:', res.data);
                
                if (Array.isArray(res.data)) {
                    this.pocResults = res.data;
                    this.aiAgentStatus = `✅ Found ${this.getTotalPoCs()} PoCs`;
                    this.pocSearchProgress = `Search complete! Found ${this.getGitHubRepos()} GitHub repositories`;
                    
                    // Force UI update
                    this.$forceUpdate();
                } else {
                    console.error('❌ Unexpected response format:', res.data);
                    this.pocResults = [];
                    this.aiAgentStatus = '❌ Search failed';
                }
                
                this.currentStep = '';
            } catch (error) {
                console.error('❌ AI PoC search failed:', error);
                this.currentStep = '';
                this.aiAgentStatus = '❌ AI agents error';
                this.pocSearchProgress = 'Search failed: ' + (error.response?.data?.detail || error.message);
            }
        },
        
        async executeSinglePoc(cveId, pocIndex) {
            const pocKey = `${cveId}_${pocIndex}`;
            if (this.executingPocs.has(pocKey)) return;
            
            this.executingPocs.add(pocKey);
            
            try {
                console.log(`🚀 Executing PoC via AI-enhanced git clone: ${cveId} #${pocIndex}`);
                
                const payload = {
                    cve_id: cveId,
                    poc_index: pocIndex,
                    target_ip: this.targetIp
                };
                
                const res = await axios.post(`${API_URL}/api/scan/${this.sessionId}/exploit/by_index`, payload);
                
                console.log(`🎯 Exploit execution result:`, res.data);
                
                this.updateExploitResult(res.data);
                
                if (res.data.success) {
                    this.showNotification(`✅ ${cveId} PoC #${pocIndex + 1} executed successfully!`, 'success');
                    this.createSuccessEffect(cveId, pocIndex);
                } else {
                    this.showNotification(`❌ ${cveId} PoC #${pocIndex + 1} failed: ${res.data.failure_reason || 'Unknown error'}`, 'error');
                }
                
            } catch (error) {
                console.error(`❌ PoC execution failed:`, error);
                this.showNotification(`❌ PoC execution failed: ${error.response?.data?.detail || error.message}`, 'error');
            } finally {
                this.executingPocs.delete(pocKey);
            }
        },
        
        async executeAllPocs(cveId) {
            try {
                console.log(`🚀 Executing all PoCs for: ${cveId}`);
                
                const payload = {
                    cve_id: cveId,
                    target_ip: this.targetIp
                };
                
                const res = await axios.post(`${API_URL}/api/scan/${this.sessionId}/exploit/multi`, payload);
                
                console.log(`🎯 Multi-PoC execution results:`, res.data);
                
                res.data.forEach(result => this.updateExploitResult(result));
                
                const successful = res.data.filter(r => r.success).length;
                const message = `${cveId}: ${successful}/${res.data.length} PoCs executed successfully`;
                this.showNotification(message, successful > 0 ? 'success' : 'error');
                
            } catch (error) {
                console.error(`❌ Multi-PoC execution failed:`, error);
                this.showNotification(`❌ Multi-PoC execution failed: ${error.response?.data?.detail || error.message}`, 'error');
            }
        },
        
        // Enhanced CVE display methods
        getCriticalCount() {
            if (!this.analystResult?.identified_cves) return 0;
            return this.analystResult.identified_cves.filter(cve => cve.cvss_score >= 9.0).length;
        },
        
        getHighCount() {
            if (!this.analystResult?.identified_cves) return 0;
            return this.analystResult.identified_cves.filter(cve => cve.cvss_score >= 7.0 && cve.cvss_score < 9.0).length;
        },
        
        getMediumCount() {
            if (!this.analystResult?.identified_cves) return 0;
            return this.analystResult.identified_cves.filter(cve => cve.cvss_score >= 4.0 && cve.cvss_score < 7.0).length;
        },
        
        getCveCardClass(cve) {
            if (cve.cvss_score >= 9.0) return 'border-red-500 bg-red-900 bg-opacity-20';
            if (cve.cvss_score >= 7.0) return 'border-orange-500 bg-orange-900 bg-opacity-20';
            if (cve.cvss_score >= 4.0) return 'border-yellow-500 bg-yellow-900 bg-opacity-20';
            return 'border-green-500 bg-green-900 bg-opacity-20';
        },
        
        getCvssLabel(score) {
            if (!score) return 'N/A';
            if (score >= 9.0) return `CRITICAL ${score}`;
            if (score >= 7.0) return `HIGH ${score}`;
            if (score >= 4.0) return `MEDIUM ${score}`;
            return `LOW ${score}`;
        },
        
        getCvssClass(score) {
            if (!score) return 'bg-gray-500 text-white';
            if (score >= 9.0) return 'bg-red-600 text-white vulnerability-critical';
            if (score >= 7.0) return 'bg-orange-500 text-white';
            if (score >= 4.0) return 'bg-yellow-500 text-black';
            return 'bg-green-500 text-white';
        },
        
        getRiskIcon(cve) {
            if (cve.cvss_score >= 9.0) return 'fas fa-skull';
            if (cve.cvss_score >= 7.0) return 'fas fa-exclamation-triangle';
            if (cve.cvss_score >= 4.0) return 'fas fa-exclamation-circle';
            return 'fas fa-info-circle';
        },
        
        createSuccessEffect(cveId, pocIndex) {
            // Create success visual effect
            const notification = document.createElement('div');
            notification.className = 'fixed top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 z-50 exploit-success p-8 rounded-lg text-center';
            notification.innerHTML = `
                <i class="fas fa-trophy text-4xl mb-4"></i>
                <div class="text-xl font-bold">EXPLOIT SUCCESSFUL!</div>
                <div class="text-sm">${cveId} PoC #${pocIndex + 1}</div>
            `;
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.remove();
            }, 3000);
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
        
        getSourceBadgeClass(source) {
            const classes = {
                'AI Recommended GitHub': 'bg-purple-600 text-white',
                'GitHub Repository': 'bg-gray-800 text-white',
                'GitHub Code': 'bg-gray-700 text-white',
                'AI Recommended ExploitDB': 'bg-red-700 text-white',
                'ExploitDB': 'bg-red-600 text-white',
                'PacketStorm': 'bg-orange-600 text-white'
            };
            return classes[source] || 'bg-blue-600 text-white';
        },
        
        showPocQuality(poc) {
            if (poc.ai_recommended) {
                return `🤖 AI Recommended (${Math.round((poc.ai_confidence || 0.5) * 100)}% confidence)`;
            }
            if (poc.repo_score) {
                return `Quality Score: ${poc.repo_score}`;
            }
            return '';
        },
        
        getTotalPoCs() {
            return this.pocResults.reduce((total, result) => total + result.available_pocs.length, 0);
        },
        
        getGitHubRepos() {
            return this.pocResults.reduce((total, result) => 
                total + result.available_pocs.filter(poc => poc.source.includes('GitHub')).length, 0);
        },
        
        getAIRecommended() {
            return this.pocResults.reduce((total, result) => 
                total + result.available_pocs.filter(poc => poc.ai_recommended).length, 0);
        },
        
        toggleCode(cveId, pocIndex) {
            const key = `${cveId}_${pocIndex}`;
            this.expandedCode[key] = !this.expandedCode[key];
        },
        
        toggleExploitOutput(cveId, pocIndex) {
            const key = `${cveId}_${pocIndex}`;
            this.expandedOutputs[key] = !this.expandedOutputs[key];
        },
        
        toggleCveDetails(cveId) {
            this.expandedCves[cveId] = !this.expandedCves[cveId];
        },
        
        formatTimestamp(timestamp) {
            return new Date(timestamp).toLocaleString();
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
        
        async loadResults() {
            try {
                const res = await axios.get(`${API_URL}/api/scan/${this.sessionId}/results`);
                const r = res.data;
                
                if (this.debugMode) {
                    console.log('📡 Loading results:', r);
                }
                
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
                    const currentPocData = JSON.stringify(this.pocResults);
                    const newPocData = JSON.stringify(r.poc_results);
                    
                    if (currentPocData !== newPocData) {
                        if (this.debugMode) {
                            console.log('🔄 PoC results updated:', r.poc_results);
                        }
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
        
        async cleanupFiles() {
            try {
                await axios.delete(`${API_URL}/api/scan/${this.sessionId}/exploit_files?keep_successful=true`);
                this.showNotification('✅ Temporary files cleaned up successfully', 'success');
            } catch (error) {
                console.error('File cleanup failed:', error);
                this.showNotification('❌ File cleanup failed', 'error');
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
        
        // Debug method
        inspectPocData() {
            console.log('🐛 Debug - Current PoC Results:');
            console.log('pocResults length:', this.pocResults.length);
            console.log('pocSearchStarted:', this.pocSearchStarted);
            console.log('AI Agent Status:', this.aiAgentStatus);
            console.log('Search Progress:', this.pocSearchProgress);
            console.log('pocResults data:', this.pocResults);
            
            this.pocResults.forEach((result, index) => {
                console.log(`CVE ${index + 1}:`, result.cve_id);
                console.log(`  PoCs available:`, result.available_pocs.length);
                console.log(`  Status:`, result.status);
                result.available_pocs.forEach((poc, pocIndex) => {
                    console.log(`    PoC ${pocIndex + 1}: ${poc.source} - ${poc.url}`);
                    if (poc.ai_recommended) {
                        console.log(`      🤖 AI Recommended (${poc.ai_confidence})`);
                    }
                });
            });
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
            console.log('🐛 Debug mode enabled');
        }
        
        const sessionFromUrl = urlParams.get('session');
        if (sessionFromUrl) {
            this.sessionId = sessionFromUrl;
            this.startPolling();
            this.loadResults();
        }
        
        // Add debug functions
        if (this.debugMode) {
            window.inspectPocData = this.inspectPocData;
            console.log('🐛 Debug commands: inspectPocData()');
        }
    }
}).mount('#app');
