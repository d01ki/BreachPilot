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
            activeTab: 'progress'
        }
    },
    methods: {
        async startScan() {
            if (!this.targetIp) {
                alert('Please enter a target IP address');
                return;
            }
            
            this.loading = true;
            try {
                const response = await axios.post(`${API_URL}/api/scan/start`, {
                    target_ip: this.targetIp
                });
                
                this.sessionId = response.data.session_id;
                this.currentStep = 'osint';
                this.connectWebSocket();
                this.startResultsPolling();
                
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
            
            try {
                let response;
                
                switch(step) {
                    case 'osint':
                        this.currentStep = 'osint';
                        console.log('Starting OSINT scan...');
                        response = await axios.post(`${API_URL}/api/scan/${this.sessionId}/osint`);
                        this.osintResult = response.data;
                        this.osintComplete = true;
                        console.log('OSINT completed:', response.data);
                        break;
                        
                    case 'nmap':
                        this.currentStep = 'nmap';
                        console.log('Starting Nmap scan...');
                        response = await axios.post(`${API_URL}/api/scan/${this.sessionId}/nmap`);
                        this.nmapResult = response.data;
                        this.nmapComplete = true;
                        console.log('Nmap completed:', response.data);
                        break;
                        
                    case 'analyze':
                        this.currentStep = 'analysis';
                        console.log('Starting CVE analysis...');
                        response = await axios.post(`${API_URL}/api/scan/${this.sessionId}/analyze`);
                        this.analystResult = response.data;
                        this.analysisComplete = true;
                        console.log('Analysis completed:', response.data);
                        break;
                        
                    case 'poc':
                        this.currentStep = 'poc_search';
                        console.log('Searching for PoCs...');
                        response = await axios.post(`${API_URL}/api/scan/${this.sessionId}/poc`);
                        this.pocResults = response.data;
                        this.pocsFound = response.data.length;
                        console.log('PoC search completed:', response.data);
                        break;
                }
                
                // Switch to results tab after completion
                this.activeTab = 'results';
                await this.loadResults();
            } catch (error) {
                console.error(`Failed to run ${step}:`, error);
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
            try {
                console.log('Approving CVEs:', this.approvedCves);
                
                // Approve
                await axios.post(
                    `${API_URL}/api/scan/${this.sessionId}/approve`,
                    this.approvedCves,
                    { headers: { 'Content-Type': 'application/json' } }
                );
                this.exploitsApproved = true;
                
                // Execute exploits
                console.log('Executing exploits...');
                const response = await axios.post(`${API_URL}/api/scan/${this.sessionId}/exploit`);
                this.exploitResults = response.data;
                this.exploitsRun = response.data.length;
                console.log('Exploits completed:', response.data);
                
                this.activeTab = 'results';
                await this.loadResults();
            } catch (error) {
                console.error('Failed to execute exploits:', error);
                alert('Failed to execute exploits: ' + (error.response?.data?.detail || error.message));
            } finally {
                this.loading = false;
            }
        },
        
        async generateReport() {
            this.loading = true;
            try {
                console.log('Generating report...');
                await axios.post(`${API_URL}/api/scan/${this.sessionId}/report`);
                this.reportReady = true;
                console.log('Report generated');
            } catch (error) {
                console.error('Failed to generate report:', error);
                alert('Failed to generate report: ' + (error.response?.data?.detail || error.message));
            } finally {
                this.loading = false;
            }
        },
        
        async loadResults() {
            try {
                const response = await axios.get(`${API_URL}/api/scan/${this.sessionId}/results`);
                const results = response.data;
                
                // Update all results from JSON files
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
                if (results.poc_results && results.poc_results.length > 0) {
                    this.pocResults = results.poc_results;
                    this.pocsFound = results.poc_results.length;
                }
                if (results.exploit_results && results.exploit_results.length > 0) {
                    this.exploitResults = results.exploit_results;
                    this.exploitsRun = results.exploit_results.length;
                }
                
                console.log('Results loaded:', results);
            } catch (error) {
                console.error('Failed to load results:', error);
            }
        },
        
        startResultsPolling() {
            // Poll for results every 3 seconds
            this.resultsInterval = setInterval(() => {
                if (this.sessionId) {
                    this.loadResults();
                }
            }, 3000);
        },
        
        stopResultsPolling() {
            if (this.resultsInterval) {
                clearInterval(this.resultsInterval);
                this.resultsInterval = null;
            }
        },
        
        connectWebSocket() {
            const wsUrl = `${API_URL.replace('http', 'ws')}/ws/${this.sessionId}`;
            console.log('Connecting to WebSocket:', wsUrl);
            
            this.ws = new WebSocket(wsUrl);
            
            this.ws.onmessage = (event) => {
                const status = JSON.parse(event.data);
                console.log('WebSocket status update:', status);
                
                this.currentStep = status.current_step;
                this.osintComplete = status.osint_complete;
                this.nmapComplete = status.nmap_complete;
                this.analysisComplete = status.analysis_complete;
                this.pocsFound = status.pocs_found;
                this.exploitsRun = status.exploits_run;
                this.reportReady = status.report_ready;
            };
            
            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
            
            this.ws.onclose = () => {
                console.log('WebSocket connection closed');
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
        
        reset() {
            this.stopResultsPolling();
            
            this.targetIp = '';
            this.sessionId = null;
            this.currentStep = '';
            this.loading = false;
            this.osintResult = null;
            this.nmapResult = null;
            this.analystResult = null;
            this.pocResults = [];
            this.exploitResults = [];
            this.osintComplete = false;
            this.nmapComplete = false;
            this.analysisComplete = false;
            this.pocsFound = 0;
            this.exploitsRun = 0;
            this.reportReady = false;
            this.approvedCves = [];
            this.exploitsApproved = false;
            this.activeTab = 'progress';
            
            if (this.ws) {
                this.ws.close();
                this.ws = null;
            }
        }
    },
    
    beforeUnmount() {
        this.stopResultsPolling();
        if (this.ws) {
            this.ws.close();
        }
    }
}).mount('#app');
