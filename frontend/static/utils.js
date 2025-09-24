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
                        timestamp: new Date().toISOString(),
                        assessment_type: 'Professional Security Assessment'
                    },
                    network_scan: this.nmapResult,
                    vulnerability_analysis: this.analystResult,
                    exploit_analysis: this.pocResults,
                    exploit_results: this.exploitResults
                };
                
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `security_assessment_raw_${this.targetIp}_${new Date().toISOString().split('T')[0]}.json`;
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
            this.targetIp = '';
            this.sessionId = null;
            this.currentStep = null;
            this.nmapResult = null;
            this.analystResult = null;
            this.debugMode = false;
            this.showRawOutput = false;
            this.expandedCves = {};
            this.selectedCves = [];
            this.pocResults = [];
            this.pocSearching = false;
            this.exploitResults = [];
            this.executingPocs = {};
            this.visiblePocCode = {};
            this.visibleExploitOutput = {};
            this.reportGenerating = false;
            this.reportResult = null;
        }
    },
    
    mounted() {
        console.log('BreachPilot Professional Security Assessment Framework loaded');
    }
}).mount('#app');