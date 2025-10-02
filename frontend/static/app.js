const { createApp } = Vue;

createApp({
    data() {
        return {
            // Basic state
            targetIp: '',
            sessionId: null,
            isLoading: false,
            error: null,
            
            // Scan results
            nmapResult: null,
            analystResult: null,
            executionTime: 0,
            
            // Scan status
            isScanning: {
                nmap: false,
                analysis: false
            },
            
            scanStatus: {
                network_scan: null,
                analysis: null
            },
            
            // Timer
            statusCheckInterval: null
        }
    },
    
    methods: {
        async startScan() {
            if (!this.targetIp) {
                this.error = 'IPアドレスを入力してください';
                return;
            }
            
            // Validate IP format
            const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
            if (!ipRegex.test(this.targetIp)) {
                this.error = '正しいIPアドレス形式で入力してください (例: 192.168.1.100)';
                return;
            }
            
            this.isLoading = true;
            this.error = null;
            
            try {
                const response = await axios.post('/api/scan/start', {
                    target_ip: this.targetIp,
                    scan_type: 'comprehensive',
                    enable_exploitation: false
                });
                
                this.sessionId = response.data.session_id;
                this.scanStatus.network_scan = 'pending';
                this.scanStatus.analysis = 'pending';
                
                // Start checking status
                this.startStatusCheck();
                
            } catch (error) {
                console.error('Failed to start scan:', error);
                this.error = 'スキャンの開始に失敗しました: ' + (error.response?.data?.detail || error.message);
            } finally {
                this.isLoading = false;
            }
        },
        
        async runNmap() {
            if (!this.sessionId) return;
            
            this.isScanning.nmap = true;
            this.scanStatus.network_scan = 'running';
            this.error = null;
            
            try {
                const response = await axios.post(`/api/scan/${this.sessionId}/nmap`);
                this.nmapResult = response.data;
                this.scanStatus.network_scan = 'completed';
            } catch (error) {
                console.error('Nmap scan failed:', error);
                this.error = 'ネットワークスキャンに失敗しました: ' + (error.response?.data?.detail || error.message);
                this.scanStatus.network_scan = 'error';
            } finally {
                this.isScanning.nmap = false;
            }
        },
        
        async runAnalysis() {
            if (!this.sessionId || !this.nmapResult) return;
            
            this.isScanning.analysis = true;
            this.scanStatus.analysis = 'running';
            this.error = null;
            
            try {
                const response = await axios.post(`/api/scan/${this.sessionId}/analyze`);
                this.analystResult = response.data;
                this.scanStatus.analysis = 'completed';
            } catch (error) {
                console.error('Analysis failed:', error);
                this.error = '脆弱性分析に失敗しました: ' + (error.response?.data?.detail || error.message);
                this.scanStatus.analysis = 'error';
            } finally {
                this.isScanning.analysis = false;
            }
        },
        
        startStatusCheck() {
            if (this.statusCheckInterval) {
                clearInterval(this.statusCheckInterval);
            }
            
            this.statusCheckInterval = setInterval(async () => {
                if (!this.sessionId) return;
                
                try {
                    const response = await axios.get(`/api/scan/${this.sessionId}/status`);
                    const data = response.data;
                    
                    // Update execution time
                    if (data.execution_time) {
                        this.executionTime = data.execution_time;
                    }
                    
                    // Check if scan is complete
                    if (data.status === 'completed' || data.status === 'failed') {
                        clearInterval(this.statusCheckInterval);
                        this.statusCheckInterval = null;
                    }
                } catch (error) {
                    console.error('Status check failed:', error);
                }
            }, 2000);
        },
        
        resetScan() {
            if (this.statusCheckInterval) {
                clearInterval(this.statusCheckInterval);
                this.statusCheckInterval = null;
            }
            
            this.targetIp = '';
            this.sessionId = null;
            this.nmapResult = null;
            this.analystResult = null;
            this.executionTime = 0;
            this.error = null;
            
            this.isScanning = {
                nmap: false,
                analysis: false
            };
            
            this.scanStatus = {
                network_scan: null,
                analysis: null
            };
        },
        
        async downloadResults() {
            if (!this.sessionId) return;
            
            try {
                const response = await axios.get(`/api/scan/${this.sessionId}/results`);
                
                const data = {
                    session_id: this.sessionId,
                    target_ip: this.targetIp,
                    timestamp: new Date().toISOString(),
                    network_scan: this.nmapResult,
                    vulnerability_analysis: this.analystResult,
                    execution_time: this.executionTime
                };
                
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `breachpilot_${this.targetIp}_${new Date().toISOString().split('T')[0]}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
            } catch (error) {
                console.error('Failed to download results:', error);
                this.error = '結果のダウンロードに失敗しました';
            }
        },
        
        getOverallStatusClass() {
            if (this.scanStatus.analysis === 'completed') return 'status-completed';
            if (this.scanStatus.analysis === 'running' || this.scanStatus.network_scan === 'running') return 'status-running';
            if (this.scanStatus.network_scan === 'error' || this.scanStatus.analysis === 'error') return 'status-error';
            return 'status-pending';
        },
        
        getOverallStatusText() {
            if (this.scanStatus.analysis === 'completed') return '完了';
            if (this.scanStatus.analysis === 'running') return '分析中';
            if (this.scanStatus.network_scan === 'running') return 'スキャン中';
            if (this.scanStatus.network_scan === 'error' || this.scanStatus.analysis === 'error') return 'エラー';
            return '待機中';
        },
        
        getStatusText(status) {
            const statusMap = {
                'pending': '待機中',
                'running': '実行中',
                'completed': '完了',
                'error': 'エラー'
            };
            return statusMap[status] || status;
        },
        
        formatTime(seconds) {
            if (!seconds) return '0秒';
            if (seconds < 60) return `${Math.round(seconds)}秒`;
            const minutes = Math.floor(seconds / 60);
            const secs = Math.round(seconds % 60);
            return `${minutes}分${secs}秒`;
        }
    },
    
    beforeUnmount() {
        if (this.statusCheckInterval) {
            clearInterval(this.statusCheckInterval);
        }
    },
    
    mounted() {
        console.log('BreachPilot Professional Security Assessment Framework');
        console.log('Version: 2.0.0');
        console.log('Architecture: CrewAI Multi-Agent System');
    }
}).mount('#app');