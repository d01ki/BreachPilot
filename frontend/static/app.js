const { createApp } = Vue;

const API_URL = window.location.origin;

createApp({
    data() {
        return {
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
            ws: null,
            resultsInterval: null,
            activeTab: 'progress',
            scanStartTime: null,
            lastUpdate: null,
            selectedCves: [],
            pocSearchStarted: false
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
                        console.log('[OSINT] Completed in', (Date.now() - startTime) / 1000, 's');
                        break;
                    case 'nmap':
                        this.currentStep = 'nmap';
                        console.log('[NMAP] Starting...');
                        response = await axios.post(`${API_URL}/api/scan/${this.sessionId}/nmap`);
                        this.nmapResult = response.data;
                        this.nmapComplete = true;
                        console.log('[NMAP] Completed in', (Date.now() - startTime) / 1000, 's');
                        break;
                    case 'analyze':
                        this.currentStep = 'analysis';
                        console.log('[ANALYSIS] Starting...');
                        response = await axios.post(`${API_URL}/api/scan/${this.sessionId}/analyze`);
                        this.analystResult = response.data;
                        this.analysisComplete = true;
                        console.log('[ANALYSIS] Completed in', (Date.now() - startTime) / 1000, 's');
                        break;
                    case 'poc':
                        this.currentStep = 'poc_search';
                        console.log('[POC] Searching...');
                        response = await axios.post(`${API_URL}/api/scan/${this.sessionId}/poc`);
                        this.pocResults = response.data;
                        this.pocsFound = response.data.length;
                        console.log('[POC] Found', response.data.length, 'PoCs');
                        break;
                }
                this.activeTab = 'results';
                await this.loadResults();
            } catch (error) {
                console.error(`[${step.toUpperCase()}] Failed:`, error);
                alert(`Failed to run ${step}: ` + (error.response?.data?.detail || error.message));
            } finally {
                this.loading = false;
            }
        },
        async searchSelectedPocs() {
            if (this.selectedCves.length === 0) return;
            this.loading = true;
            this.pocSearchStarted = true;
            try {
                console.log('[POC] Searching for selected CVEs:', this.selectedCves);
                const response = await axios.post(
                    `${API_URL}/api/scan/${this.sessionId}/poc`,
                    { cve_list: this.selectedCves },
                    { headers: { 'Content-Type': 'application/json' } }
                );
                this.pocResults = response.data;
                this.pocsFound = response.data.length;
                console.log('[POC] Found', response.data.length, 'PoCs');
                await this.loadResults();
            } catch (error) {
                console.error('[POC] Failed:', error);
                alert('Failed to search PoCs');
            } finally {
                this.loading = false;
            }
        },
        getCvssClass(score) {
            if (!score) return 'bg-gray-500';
            if (score >= 9.0) return 'bg-red-600';
            if (score >= 7.0) return 'bg-orange-500';
            if (score >= 4.0) return 'bg-yellow-500';
            return 'bg-green-500';
        },
        async loadResults() {
            try {
                const response = await axios.get(`${API_URL}/api/scan/${this.sessionId}/results`);
                const results = response.data;
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
            } catch (error) {
                console.error('[RESULTS] Failed:', error);
            }
        },
        startResultsPolling() {
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
        },
        getStepClass(step) {
            const stepMap = {
                'osint': this.osintComplete,
                'nmap': this.nmapComplete,
                'analysis': this.analysisComplete,
                'poc': this.pocsFound > 0
            };
            if (stepMap[step]) return 'bg-green-500 text-white';
            if (this.currentStep === step && this.loading) return 'bg-yellow-500 text-white animate-pulse';
            return 'bg-gray-300 text-gray-700';
        },
        formatJson(obj) {
            if (!obj) return 'No data';
            return JSON.stringify(obj, null, 2);
        },
        reset() {
            this.stopResultsPolling();
            if (this.ws) this.ws.close();
            Object.assign(this.$data, this.$options.data());
        }
    },
    beforeUnmount() {
        this.stopResultsPolling();
        if (this.ws) this.ws.close();
    }
}).mount('#app');
