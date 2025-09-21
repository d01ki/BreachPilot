const { createApp } = Vue;
const API_URL = window.location.origin;

createApp({
    data() {
        return {
            targetIp: '', sessionId: null, currentStep: '', loading: false,
            osintResult: null, nmapResult: null, analystResult: null,
            pocResults: [], exploitResults: [],
            osintComplete: false, nmapComplete: false, analysisComplete: false,
            pocsFound: 0, exploitsRun: 0, reportReady: false,
            ws: null, resultsInterval: null, activeTab: 'progress',
            selectedCves: [], pocSearchStarted: false
        }
    },
    methods: {
        async startScan() {
            if (!this.targetIp) return;
            this.loading = true;
            try {
                const res = await axios.post(`${API_URL}/api/scan/start`, { target_ip: this.targetIp });
                this.sessionId = res.data.session_id;
                this.connectWebSocket();
                this.startResultsPolling();
                setTimeout(() => this.runStep('osint'), 500);
            } catch (error) {
                alert('Failed: ' + error.message);
            } finally {
                this.loading = false;
            }
        },
        async runStep(step) {
            this.loading = true;
            this.currentStep = step;
            try {
                let res;
                if (step === 'osint') {
                    res = await axios.post(`${API_URL}/api/scan/${this.sessionId}/osint`);
                    this.osintResult = res.data;
                    this.osintComplete = true;
                } else if (step === 'nmap') {
                    res = await axios.post(`${API_URL}/api/scan/${this.sessionId}/nmap`);
                    this.nmapResult = res.data;
                    this.nmapComplete = true;
                } else if (step === 'analyze') {
                    res = await axios.post(`${API_URL}/api/scan/${this.sessionId}/analyze`);
                    this.analystResult = res.data;
                    this.analysisComplete = true;
                }
                this.activeTab = 'results';
                await this.loadResults();
            } catch (error) {
                alert(`${step} failed`);
            } finally {
                this.loading = false;
                this.currentStep = '';
            }
        },
        async searchSelectedPocs() {
            if (!this.selectedCves.length) return;
            this.loading = true;
            this.currentStep = 'poc_search';
            this.pocSearchStarted = true;
            try {
                const pocPromises = this.selectedCves.map(async (cve) => {
                    const res = await axios.post(`${API_URL}/api/scan/${this.sessionId}/poc`, 
                        { cve_list: [cve], limit: 3 });
                    return res.data[0];
                });
                this.pocResults = await Promise.all(pocPromises);
                this.pocsFound = this.pocResults.length;
                await this.loadResults();
            } catch (error) {
                alert('PoC search failed');
            } finally {
                this.loading = false;
                this.currentStep = '';
            }
        },
        async runExploits() {
            this.loading = true;
            this.currentStep = 'exploit';
            try {
                const res = await axios.post(`${API_URL}/api/scan/${this.sessionId}/exploit`);
                this.exploitResults = res.data;
                this.exploitsRun = res.data.length;
                await this.loadResults();
            } catch (error) {
                alert('Exploitation failed');
            } finally {
                this.loading = false;
                this.currentStep = '';
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
                const res = await axios.get(`${API_URL}/api/scan/${this.sessionId}/results`);
                const r = res.data;
                if (r.osint_result) { this.osintResult = r.osint_result; this.osintComplete = true; }
                if (r.nmap_result) { this.nmapResult = r.nmap_result; this.nmapComplete = true; }
                if (r.analyst_result) { this.analystResult = r.analyst_result; this.analysisComplete = true; }
                if (r.poc_results?.length) { this.pocResults = r.poc_results; this.pocsFound = r.poc_results.length; }
                if (r.exploit_results?.length) { this.exploitResults = r.exploit_results; this.exploitsRun = r.exploit_results.length; }
            } catch (e) {}
        },
        startResultsPolling() {
            this.resultsInterval = setInterval(() => {
                if (this.sessionId && !this.loading) this.loadResults();
            }, 2000);
        },
        stopResultsPolling() {
            if (this.resultsInterval) { clearInterval(this.resultsInterval); this.resultsInterval = null; }
        },
        connectWebSocket() {
            const wsUrl = `${API_URL.replace('http', 'ws')}/ws/${this.sessionId}`;
            this.ws = new WebSocket(wsUrl);
            this.ws.onmessage = (e) => {
                const s = JSON.parse(e.data);
                this.osintComplete = s.osint_complete;
                this.nmapComplete = s.nmap_complete;
                this.analysisComplete = s.analysis_complete;
                this.pocsFound = s.pocs_found;
                this.exploitsRun = s.exploits_run;
            };
        },
        getStepClass(step) {
            const map = {
                'osint': this.osintComplete, 'nmap': this.nmapComplete,
                'analysis': this.analysisComplete, 'poc': this.pocsFound > 0,
                'exploit': this.exploitsRun > 0
            };
            if (map[step]) return 'bg-green-500 text-white';
            if (this.currentStep === step && this.loading) return 'bg-yellow-500 text-white';
            return 'bg-gray-300 text-gray-700';
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
