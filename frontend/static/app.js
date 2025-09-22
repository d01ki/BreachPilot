const { createApp } = Vue;
const API_URL = window.location.origin;

createApp({
    data() {
        return {
            targetIp: '', sessionId: null, currentStep: '', loading: false,
            osintResult: null, nmapResult: null, analystResult: null,
            pocResults: [], exploitResults: [],
            osintComplete: false, nmapComplete: false, analysisComplete: false,
            selectedCves: [], pocSearchStarted: false,
            expandedCves: {},
            debugMode: false,
            showRawOutput: false
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
                    console.log('OSINT completed:', this.osintResult);
                }
                if (step === 'nmap') { 
                    this.nmapResult = res.data; 
                    this.nmapComplete = true;
                    console.log('Nmap completed:', this.nmapResult);
                    console.log('Open ports:', this.nmapResult.open_ports);
                    console.log('Status:', this.nmapResult.status);
                }
                if (step === 'analyze') { 
                    this.analystResult = res.data; 
                    this.analysisComplete = true;
                    console.log('Analysis completed:', this.analystResult);
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
                const res = await axios.post(`${API_URL}/api/scan/${this.sessionId}/poc`, 
                    { selected_cves: this.selectedCves });
                this.pocResults = res.data;
                this.currentStep = '';
            } catch (error) {
                console.error('PoC search failed:', error);
                this.currentStep = '';
                alert('PoC search failed: ' + (error.response?.data?.detail || error.message));
            }
        },
        async executePoc(cveId, poc, pocIndex) {
            try {
                const res = await axios.post(`${API_URL}/api/scan/${this.sessionId}/exploit/single`, {
                    cve_id: cveId,
                    poc: poc,
                    target_ip: this.targetIp
                });
                this.exploitResults.push({ ...res.data, poc_index: pocIndex });
            } catch (error) {
                console.error('Exploit failed:', error);
                alert('Exploit failed: ' + (error.response?.data?.detail || error.message));
            }
        },
        getCvssClass(score) {
            if (!score) return 'bg-gray-500';
            if (score >= 9) return 'bg-red-600';
            if (score >= 7) return 'bg-orange-500';
            if (score >= 4) return 'bg-yellow-500';
            return 'bg-green-500';
        },
        async loadResults() {
            try {
                const res = await axios.get(`${API_URL}/api/scan/${this.sessionId}/results`);
                const r = res.data;
                
                // Update results with better state management
                if (r.osint_result && !this.osintComplete) {
                    this.osintResult = r.osint_result;
                    this.osintComplete = true;
                }
                if (r.nmap_result && !this.nmapComplete) {
                    this.nmapResult = r.nmap_result;
                    this.nmapComplete = true;
                    console.log('Nmap result loaded from polling:', this.nmapResult);
                }
                if (r.analyst_result && !this.analysisComplete) {
                    this.analystResult = r.analyst_result;
                    this.analysisComplete = true;
                }
                if (r.poc_results) {
                    this.pocResults = r.poc_results;
                }
                if (r.exploit_results) {
                    this.exploitResults = r.exploit_results;
                }
            } catch (error) {
                console.error('Failed to load results:', error);
                // Don't show alert for polling errors to avoid spam
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
            
            // Convert markdown-like formatting to HTML
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
    mounted() {
        // Enable debug mode if URL contains debug parameter
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('debug') === 'true') {
            this.debugMode = true;
        }
    }
}).mount('#app');
