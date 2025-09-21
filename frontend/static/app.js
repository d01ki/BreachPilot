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
            expandedCves: {}
        }
    },
    methods: {
        async startScan() {
            if (!this.targetIp) return;
            const res = await axios.post(`${API_URL}/api/scan/start`, { target_ip: this.targetIp });
            this.sessionId = res.data.session_id;
            this.startPolling();
            setTimeout(() => this.runStep('osint'), 500);
        },
        async runStep(step) {
            this.currentStep = step;
            const url = `${API_URL}/api/scan/${this.sessionId}/${step === 'analyze' ? 'analyze' : step}`;
            const res = await axios.post(url);
            if (step === 'osint') { this.osintResult = res.data; this.osintComplete = true; }
            if (step === 'nmap') { this.nmapResult = res.data; this.nmapComplete = true; }
            if (step === 'analyze') { this.analystResult = res.data; this.analysisComplete = true; }
            this.currentStep = '';
        },
        async searchPocs() {
            this.pocSearchStarted = true;
            this.currentStep = 'poc_search';
            const res = await axios.post(`${API_URL}/api/scan/${this.sessionId}/poc`, 
                { selected_cves: this.selectedCves });
            this.pocResults = res.data;
            this.currentStep = '';
        },
        async executePoc(cveId, poc, pocIndex) {
            try {
                const res = await axios.post(`${API_URL}/api/scan/${this.sessionId}/exploit/single`, {
                    cve_id: cveId,
                    poc: poc,
                    target_ip: this.targetIp
                });
                this.exploitResults.push({ ...res.data, poc_index: pocIndex });
            } catch (e) {
                alert('Exploit failed: ' + e.message);
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
            const res = await axios.get(`${API_URL}/api/scan/${this.sessionId}/results`);
            const r = res.data;
            if (r.osint_result) this.osintResult = r.osint_result;
            if (r.nmap_result) this.nmapResult = r.nmap_result;
            if (r.analyst_result) this.analystResult = r.analyst_result;
            if (r.poc_results) this.pocResults = r.poc_results;
        },
        startPolling() {
            setInterval(() => this.loadResults(), 3000);
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
            const highRiskPorts = [445, 3389, 135, 139, 88, 389, 636];
            const mediumRiskPorts = [80, 443, 21, 22, 23, 25, 53, 110, 143, 993, 995];
            
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
    }
}).mount('#app');
