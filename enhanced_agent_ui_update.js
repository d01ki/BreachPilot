        function updateAgentStatus(agents) {
            const container = document.getElementById('agent-status');
            
            if (!agents || agents.length === 0) {
                container.innerHTML = '<div class="text-gray-400 text-center py-8">No agents active</div>';
                return;
            }

            container.innerHTML = agents.map(agent => `
                <div class="agent-card bg-gray-800 rounded-lg p-3 status-${agent.status} border-l-4">
                    <div class="flex justify-between items-center mb-2">
                        <div class="flex-1">
                            <div class="font-medium text-sm text-white">${agent.role.replace('_', ' ').toUpperCase()}</div>
                            <div class="text-xs text-gray-400">
                                Completed: ${agent.completed_tasks_count} | 
                                Tools: ${agent.tools_available || 0} | 
                                Capabilities: ${agent.capabilities ? agent.capabilities.length : 0}
                            </div>
                        </div>
                        <div class="text-right">
                            <div class="text-xs font-medium ${agent.status === 'busy' ? 'text-yellow-400' : agent.status === 'idle' ? 'text-green-400' : 'text-red-400'}">
                                ${agent.status === 'busy' ? '🔄' : agent.status === 'idle' ? '✅' : '❌'} ${agent.status.toUpperCase()}
                            </div>
                            ${agent.current_task ? `<div class="text-xs text-blue-300">Working on task</div>` : ''}
                        </div>
                    </div>
                    ${agent.capabilities && agent.capabilities.length > 0 ? `
                        <div class="mt-2">
                            <div class="text-xs text-gray-500 mb-1">Key Capabilities:</div>
                            <div class="flex flex-wrap gap-1">
                                ${agent.capabilities.slice(0, 3).map(cap => 
                                    `<span class="text-xs bg-blue-900/30 text-blue-300 px-2 py-1 rounded">${cap.replace('_', ' ')}</span>`
                                ).join('')}
                                ${agent.capabilities.length > 3 ? 
                                    `<span class="text-xs text-gray-400">+${agent.capabilities.length - 3} more</span>` : 
                                    ''
                                }
                            </div>
                        </div>
                    ` : ''}
                </div>
            `).join('');
        }