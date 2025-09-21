const { createApp } = Vue;

const API_URL = window.location.origin;

createApp({
    data() {
        return {
            targetIp: '',
            sessionId: null,
            currentStep: '',
            loading: false,
            
            // Results from JSON files
            osintResult: null,
            nmapResult: null,
            analystResult: null,
            pocResults: [],
            exploitResults: [],
            
            // Status flags
            osintComplete: false,
            nmapComplete: false,
            analysisComplete: false,
            pocsFound: 0,
            exploitsRun: 0,
            reportReady: false,
            
            // UI state
            approvedCves: [],
            exploitsApproved: false,
            ws: null,
            resultsInterval: null,
            
            // Display tabs
            activeTab: 'progress',
            
            // Progress tracking
            scanStartTime: null,
            lastUpdate: null
        }
    },
    methods: {
        async startScan() {
            if (!this.targetIp) {
                alert('Please enter a target IP address');
                return;
            }
            
            this.loading = true;
            this.scanStartTime = Date.now();
            
            try {
                const response = await axios.post(`${API_URL}/api/scan/start`, {
                    target_ip: this.targetIp
                });
                
                this.sessionId = response.data.session_id;
                this.currentStep = 'osint';
                this.connectWebSocket();
                this.startResultsPolling();
                
                console.log('Scan started:', response.data);
                
                // Auto-run OSINT
                setTimeout(() => this.runStep('osint'), 500);
            } catch (error) {
                console.error('Failed to start scan:', error);
                alert('Failed to start scan: ' + (error.response?.data?.detail || error.message));
            } finally {
                this.loading = false;
            }
        },
        
        async runStep(step) {
            this.loading = true;
            const startTime = Date.now();
            
            try {
                let response;
                
                switch(step) {
                    case 'osint':
                        this.currentStep = 'osint';
                        console.log('[OSINT] Starting...');
                        response = await axios.post(`${API_URL}/api/scan/${this.sessionId}/osint`);
                        this.osintResult = response.data;
                        this.osintComplete = true;
                        console.log('[OSINT] Completed in', (Date.now() - startTime) / 1000, 'seconds');
                        break;
                        
                    case 'nmap':
                        this.currentStep = 'nmap';
                        console.log('[NMAP] Starting fast scan...');
                        response = await axios.post(`${API_URL}/api/scan/${this.sessionId}/nmap`);
                        this.nmapResult = response.data;
                        this.nmapComplete = true;
                        console.log('[NMAP] Completed in', (Date.now() - startTime) / 1000, 'seconds');
                        console.log('[NMAP] Found', response.data.open_ports?.length || 0, 'open ports');
                        break;
                        
                    case 'analyze':
                        this.currentStep = 'analysis';
                        console.log('[ANALYSIS] Starting CVE analysis...');
                        response = await axios.post(`${API_URL}/api/scan/${this.sessionId}/analyze`);
                        this.analystResult = response.data;
                        this.analysisComplete = true;
                        console.log('[ANALYSIS] Completed in', (Date.now() - startTime) / 1000, 'seconds');
                        break;
                        
                    case 'poc':
                        this.currentStep = 'poc_search';
                        console.log('[POC] Searching for exploits...');
                        response = await axios.post(`${API_URL}/api/scan/${this.sessionId}/poc`);
                        this.pocResults = response.data;
                        this.pocsFound = response.data.length;
                        console.log('[POC] Found', response.data.length, 'PoCs in', (Date.now() - startTime) / 1000, 'seconds');
                        break;
                }
                
                // Switch to results tab and load latest results
                this.activeTab = 'results';
                await this.loadResults();
            } catch (error) {
                console.error(`[${step.toUpperCase()}] Failed:`, error);
                alert(`Failed to run ${step}: ` + (error.response?.data?.detail || error.message));
            } finally {
                this.loading = false;
            }
        },
        
        async approveExploits() {
            if (this.approvedCves.length === 0) {
                alert('Please select at least one CVE to exploit');
                return;
            }
            
            this.loading = true;
            const startTime = Date.now();
            
            try {
                console.log('[EXPLOIT] Approving CVEs:', this.approvedCves);
                
                await axios.post(
                    `${API_URL}/api/scan/${this.sessionId}/approve`,
                    this.approvedCves,
                    { headers: { 'Content-Type': 'application/json' } }
                );
                this.exploitsApproved = true;
                
                console.log('[EXPLOIT] Executing exploits...');
                const response = await axios.post(`${API_URL}/api/scan/${this.sessionId}/exploit`);
                this.exploitResults = response.data;
                this.exploitsRun = response.data.length;
                console.log('[EXPLOIT] Completed in', (Date.now() - startTime) / 1000, 'seconds');
                
                this.activeTab = 'results';
                await this.loadResults();
            } catch (error) {
                console.error('[EXPLOIT] Failed:', error);
                alert('Failed to execute exploits: ' + (error.response?.data?.detail || error.message));
            } finally {
                this.loading = false;
            }
        },
        
        async generateReport() {
            this.loading = true;
            try {
                console.log('[REPORT] Generating...');
                await axios.post(`${API_URL}/api/scan/${this.sessionId}/report`);
                this.reportReady = true;
                console.log('[REPORT] Generated successfully');
            } catch (error) {
                console.error('[REPORT] Failed:', error);
                alert('Failed to generate report: ' + (error.response?.data?.detail || error.message));
            } finally {
                this.loading = false;
            }
        },
        
        async loadResults() {
            try {
                const response = await axios.get(`${API_URL}/api/scan/${this.sessionId}/results`);
                const results = response.data;
                
                // Update all results
                if (results.osint_result) {
                    this.osintResult = results.osint_result;
                    this.osintComplete = true;
                }
                if (results.nmap_result) {
                    this.nmapResult = results.nmap_result;
                    this.nmapComplete = true;
                }
                if (results.analyst_result) {
                    this.analystResult = results.analyst_result;
                    this.analysisComplete = true;
                }
                if (results.poc_results?.length > 0) {
                    this.pocResults = results.poc_results;
                    this.pocsFound = results.poc_results.length;
                }
                if (results.exploit_results?.length > 0) {
                    this.exploitResults = results.exploit_results;
                    this.exploitsRun = results.exploit_results.length;
                }
                
                this.lastUpdate = new Date().toLocaleTimeString();
                console.log('[RESULTS] Updated at', this.lastUpdate);
            } catch (error) {
                console.error('[RESULTS] Failed to load:', error);
            }
        },
        
        startResultsPolling() {
            // Poll every 2 seconds for fast updates
            this.resultsInterval = setInterval(() => {
                if (this.sessionId && !this.loading) {
                    this.loadResults();
                }
            }, 2000);
        },
        
        stopResultsPolling() {
            if (this.resultsInterval) {
                clearInterval(this.resultsInterval);
                this.resultsInterval = null;
            }
        },
        
        connectWebSocket() {
            const wsUrl = `${API_URL.replace('http', 'ws')}/ws/${this.sessionId}`;
            console.log('[WS] Connecting to', wsUrl);
            
            this.ws = new WebSocket(wsUrl);
            
            this.ws.onmessage = (event) => {
                const status = JSON.parse(event.data);
                this.currentStep = status.current_step;
                this.osintComplete = status.osint_complete;
                this.nmapComplete = status.nmap_complete;
                this.analysisComplete = status.analysis_complete;
                this.pocsFound = status.pocs_found;
                this.exploitsRun = status.exploits_run;
                this.reportReady = status.report_ready;
            };
            
            this.ws.onerror = (error) => {
                console.error('[WS] Error:', error);
            };
            
            this.ws.onclose = () => {
                console.log('[WS] Connection closed');
            };
        },
        
        getStepClass(step) {
            const stepMap = {
                'osint': this.osintComplete,
                'nmap': this.nmapComplete,
                'analysis': this.analysisComplete,
                'poc': this.pocsFound > 0,
                'exploitation': this.exploitsRun > 0,
                'reporting': this.reportReady
            };
            
            if (stepMap[step]) {
                return 'bg-green-500 text-white';
            } else if (this.currentStep === step && this.loading) {
                return 'bg-yellow-500 text-white animate-pulse';
            } else {
                return 'bg-gray-300 text-gray-700';
            }
        },
        
        isStepComplete(step) {
            const stepMap = {
                'osint': this.osintComplete,
                'nmap': this.nmapComplete,
                'analysis': this.analysisComplete
            };
            return stepMap[step] || false;
        },
        
        formatJson(obj) {
            if (!obj) return 'No data';
            return JSON.stringify(obj, null, 2);
        },
        
        getElapsedTime() {
            if (!this.scanStartTime) return '0s';
            const elapsed = Math.floor((Date.now() - this.scanStartTime) / 1000);
            return `${elapsed}s`;
        },
        
        reset() {
            this.stopResultsPolling();
            
            if (this.ws) {
                this.ws.close();
                this.ws = null;
            }
            
            // Reset all state
            Object.assign(this.$data, {
                targetIp: '',
                sessionId: null,
                currentStep: '',
                loading: false,
                osintResult: null,
                nmapResult: null,
                analystResult: null,
                pocResults: [],
                exploitResults: [],
                osintComplete: false,
                nmapComplete: false,
                analysisComplete: false,
                pocsFound: 0,
                exploitsRun: 0,
                reportReady: false,
                approvedCves: [],
                exploitsApproved: false,
                activeTab: 'progress',
                scanStartTime: null,
                lastUpdate: null
            });
            
            console.log('[APP] Reset completed');
        }
    },
    
    beforeUnmount() {
        this.stopResultsPolling();
        if (this.ws) {
            this.ws.close();
        }
    }
}).mount('#app');
