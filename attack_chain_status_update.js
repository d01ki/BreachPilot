        async function updateChainStatus() {
            try {
                const response = await fetch(`/api/attack-chain/${currentChainId}/status`);
                const status = await response.json();
                
                if (status.error) {
                    addLog('error', `Status check failed: ${status.error}`);
                    return;
                }

                // Update progress
                updateProgress(status.progress || 0);
                
                // Update visualization
                updateVisualization(status);
                
                // Update agent status
                updateAgentStatus(status.agent_states);
                
                // Update timeline
                updateTimeline(status.recent_timeline);
                
                // Update current task
                updateCurrentTaskDisplay(status);

                // Process server logs if available
                if (status.logs && status.logs.length > 0) {
                    status.logs.forEach(logEntry => {
                        // Only add logs we haven't seen before
                        if (!processedLogs.has(logEntry.timestamp + logEntry.message)) {
                            addLog(logEntry.level, logEntry.message, new Date(logEntry.timestamp).toLocaleTimeString());
                            processedLogs.add(logEntry.timestamp + logEntry.message);
                        }
                    });
                }

                // Add status logs
                if (status.status === 'running') {
                    const runningTasks = status.agent_states?.filter(agent => agent.status === 'busy').length || 0;
                    if (runningTasks > 0 && Math.random() < 0.3) { // Occasionally show this info
                        addLog('info', `${runningTasks} agent(s) actively executing tasks`);
                    }
                }

                // Stop monitoring if chain is completed or failed
                if (status.status === 'completed') {
                    addLog('success', 'Attack chain completed successfully!');
                    updateProgress(100);
                    clearInterval(updateInterval);
                } else if (status.status === 'failed') {
                    addLog('error', 'Attack chain execution failed');
                    clearInterval(updateInterval);
                } else if (status.status === 'stopped') {
                    addLog('warning', 'Attack chain was stopped');
                    clearInterval(updateInterval);
                }
            } catch (error) {
                addLog('error', `Error updating chain status: ${error.message}`);
            }
        }