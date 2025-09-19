        async function checkJobStatus() {
            try {
                const response = await fetch(`/api/job/${jobId}`);
                const data = await response.json();
                
                const progress = data.progress || 0;
                const phase = data.phase || 'unknown';
                
                updateProgress(progress, phase, data);
                
                // Update real-time scan output if available
                if (data.scan_output) {
                    updateScanOutput(data.scan_output);
                }
                
                // Show scenario information
                if (data.scenario) {
                    updateScenarioInfo(data.scenario);
                }
                
                if (data.status === 'completed') {
                    clearInterval(updateInterval);
                } else if (data.status === 'failed') {
                    clearInterval(updateInterval);
                    document.getElementById('current-phase-name').textContent = 'Failed';
                    document.getElementById('phase-content').innerHTML = `
                        <div class="text-red-400">
                            <div class="text-lg">❌ Test Failed</div>
                            <div class="text-sm mt-2">${data.error || 'Unknown error occurred'}</div>
                        </div>
                    `;
                }
                
                lastProgress = progress;
            } catch (error) {
                console.error('Error checking job status:', error);
            }
        }

        function updateScanOutput(output) {
            const outputContainer = document.getElementById('scan-output');
            if (outputContainer && output) {
                outputContainer.textContent = output;
                outputContainer.scrollTop = outputContainer.scrollHeight;
                showOutput();
            }
        }

        function updateScenarioInfo(scenario) {
            if (!scenario) return;
            
            const scenarioInfo = document.createElement('div');
            scenarioInfo.className = 'slide-in mt-4 p-4 bg-gradient-to-r from-purple-900/30 to-blue-900/30 rounded-lg border border-purple-500/30';
            scenarioInfo.innerHTML = `
                <div class="text-sm">
                    <div class="font-semibold text-purple-300 mb-2">🎯 Demo Scenario: ${scenario.name}</div>
                    <div class="text-gray-300 text-xs space-y-1">
                        <div>Target OS: ${scenario.os}</div>
                        <div>Focus: ${scenario.exploit_focus}</div>
                        <div>Vulnerabilities: ${scenario.vulnerabilities ? scenario.vulnerabilities.join(', ') : 'Analyzing...'}</div>
                    </div>
                </div>
            `;
            
            // Add scenario info to phase content if not already added
            const phaseContent = document.getElementById('phase-content');
            if (phaseContent && !phaseContent.querySelector('.scenario-info')) {
                scenarioInfo.classList.add('scenario-info');
                phaseContent.appendChild(scenarioInfo);
            }
        }

        function updatePhaseDetails(phase, jobData) {
            const phaseName = document.getElementById('current-phase-name');
            const phaseContent = document.getElementById('phase-content');
            
            if (phaseMapping[phase]) {
                phaseName.textContent = phaseMapping[phase].name;
            }

            let content = '';
            
            if (phase === 'scan') {
                content = `
                    <div class="space-y-3">
                        <div class="flex items-center">
                            <div class="pulse-dot w-3 h-3 bg-blue-500 rounded-full mr-3"></div>
                            <span>Running comprehensive Nmap scan...</span>
                        </div>
                        ${jobData.scan_output ? `
                            <div class="bg-gray-800 rounded p-3 text-sm text-green-400">
                                📡 ${jobData.scan_output}
                            </div>
                        ` : ''}
                        ${jobData.scan && jobData.scan.open_ports ? `
                            <div class="slide-in">
                                <div class="bg-gray-800 rounded p-3 mt-3">
                                    <div class="text-sm text-green-400 mb-2">✅ Scan Results:</div>
                                    <div class="text-xs text-gray-300 space-y-1">
                                        <div>Target: ${jobData.scan.host_info?.hostname || jobData.scan.scan_info?.target}</div>
                                        <div>OS: ${jobData.scan.host_info?.os_detection || 'Detecting...'}</div>
                                        <div>Open Ports: ${jobData.scan.open_ports.length}</div>
                                        <div class="mt-2">
                                            ${jobData.scan.open_ports.slice(0, 3).map(port => 
                                                `<span class="inline-block bg-blue-900/30 text-blue-300 px-2 py-1 rounded text-xs mr-1 mb-1">
                                                    ${port.port}/${port.service}
                                                </span>`
                                            ).join('')}
                                            ${jobData.scan.open_ports.length > 3 ? `<span class="text-gray-400 text-xs">+${jobData.scan.open_ports.length - 3} more</span>` : ''}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ` : ''}
                    </div>
                `;
                showOutput();
            } else if (phase === 'poc') {
                content = `
                    <div class="space-y-3">
                        <div class="flex items-center">
                            <div class="pulse-dot w-3 h-3 bg-orange-500 rounded-full mr-3"></div>
                            <span>Researching CVE exploits and PoC code...</span>
                        </div>
                        ${jobData.poc ? `
                            <div class="slide-in">
                                <div class="bg-gray-800 rounded p-3 mt-3">
                                    <div class="text-sm text-orange-400 mb-2">🔍 PoC Research:</div>
                                    <div class="text-xs text-gray-300">
                                        Fetching real exploit code from GitHub...<br>
                                        Analyzing CVE databases...<br>
                                        Validating proof-of-concept availability...
                                    </div>
                                </div>
                            </div>
                        ` : ''}
                    </div>
                `;
            } else if (phase === 'exploit') {
                content = `
                    <div class="space-y-3">
                        <div class="flex items-center">
                            <div class="pulse-dot w-3 h-3 bg-red-500 rounded-full mr-3"></div>
                            <span>Executing demo exploits (safe environment)...</span>
                        </div>
                        ${jobData.exploit ? `
                            <div class="slide-in">
                                <div class="bg-gray-800 rounded p-3 mt-3">
                                    <div class="text-sm text-red-400 mb-2">💥 Exploit Demo:</div>
                                    <div class="text-xs text-gray-300">
                                        ${jobData.scenario ? `Scenario: ${jobData.scenario.name}<br>` : ''}
                                        Running exploit simulations...<br>
                                        Validating vulnerability presence...
                                    </div>
                                </div>
                            </div>
                        ` : ''}
                    </div>
                `;
            } else if (phase === 'completed') {
                content = `
                    <div class="text-center">
                        <div class="text-green-400 text-2xl mb-2">🎉</div>
                        <div class="text-lg font-semibold text-green-400">Penetration Test Completed!</div>
                        <div class="text-sm text-gray-400 mt-2">All phases completed successfully</div>
                        ${jobData.scenario ? `
                            <div class="mt-4 p-3 bg-green-900/20 rounded border border-green-500/30">
                                <div class="text-sm text-green-300">
                                    Scenario: ${jobData.scenario.name}<br>
                                    CVEs Analyzed: ${jobData.scenario.vulnerabilities ? jobData.scenario.vulnerabilities.length : 'N/A'}<br>
                                    Real PoC Code Retrieved: ✅
                                </div>
                            </div>
                        ` : ''}
                    </div>
                `;
                showResults(jobData);
            } else {
                content = `
                    <div class="flex items-center">
                        <div class="pulse-dot w-3 h-3 bg-blue-500 rounded-full mr-3"></div>
                        <span>Processing ${phaseMapping[phase]?.name || phase}...</span>
                    </div>
                `;
            }
            
            phaseContent.innerHTML = content;
        }