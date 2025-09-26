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
            Object.assign(this, {
                targetIp: '', sessionId: null, currentStep: null, nmapResult: null, 
                analystResult: null, debugMode: false, showRawOutput: false,
                expandedCves: {}, selectedCves: [], pocResults: [], pocSearching: false,
                exploitResults: [], executingPocs: {}, visiblePocCode: {},
                visibleExploitOutput: {}, reportGenerating: false, reportResult: null
            });
        }
    },
    
    mounted() {
        console.log('BreachPilot Professional Security Assessment Framework loaded');
    }
}).mount('#app');