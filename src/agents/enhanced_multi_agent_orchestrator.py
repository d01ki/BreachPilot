    
    def _find_task_by_id(self, chain: AttackChain, task_id: str) -> Optional[AttackTask]:
        """IDでタスクを検索"""
        for task in chain.tasks:
            if task.id == task_id:
                return task
        return None
    
    def _add_timeline_event(self, chain: AttackChain, message: str, task_id: Optional[str] = None):
        """タイムラインイベントを追加"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "message": message,
            "task_id": task_id
        }
        chain.timeline.append(event)
    
    def _generate_execution_summary(self, chain: AttackChain) -> Dict[str, Any]:
        """実行サマリーを生成"""
        total_tasks = len(chain.tasks)
        completed_tasks = len([t for t in chain.tasks if t.status == TaskStatus.COMPLETED])
        failed_tasks = len([t for t in chain.tasks if t.status == TaskStatus.FAILED])
        
        total_duration = 0
        if chain.started_at and chain.completed_at:
            total_duration = int((chain.completed_at - chain.started_at).total_seconds())
        
        # 強化された結果サマリー
        enhanced_results = {}
        for task in chain.tasks:
            if task.status == TaskStatus.COMPLETED and task.result:
                enhanced_results[task.stage.value] = {
                    "task_name": task.name,
                    "duration": task.actual_duration,
                    "tools_used": list(task.result.keys()) if isinstance(task.result, dict) else [],
                    "ai_analysis": task.result.get("ai_analysis", "No analysis") if isinstance(task.result, dict) else "No analysis",
                    "status": "completed"
                }
        
        return {
            "chain_id": chain.id,
            "status": chain.status,
            "target": chain.target,
            "enhanced": True,
            "summary": {
                "total_tasks": total_tasks,
                "completed_tasks": completed_tasks,
                "failed_tasks": failed_tasks,
                "success_rate": (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0,
                "total_duration": total_duration,
                "agents_used": len(self.agents),
                "tools_executed": sum(len(task.result.keys()) if task.result and isinstance(task.result, dict) else 0 for task in chain.tasks)
            },
            "timeline": chain.timeline,
            "enhanced_results": enhanced_results
        }
    
    def get_chain_status(self, chain_id: str) -> Dict[str, Any]:
        """強化された攻撃チェーンの現在のステータスを取得"""
        if chain_id not in self.active_chains:
            return {"error": "Chain not found"}
        
        chain = self.active_chains[chain_id]
        
        # 可視化データを生成
        try:
            visualization_data = AttackChainVisualizer.generate_chain_graph(chain)
        except:
            # フォールバック用の簡単な可視化データ
            visualization_data = {
                "nodes": [
                    {
                        "id": task.id,
                        "name": task.name,
                        "stage": task.stage.value,
                        "agent": task.agent_role.value,
                        "status": task.status.value,
                        "position": {"x": i * 100, "y": 0}
                    }
                    for i, task in enumerate(chain.tasks)
                ],
                "edges": [
                    {"from": dep_id, "to": task.id}
                    for task in chain.tasks
                    for dep_id in task.dependencies
                ]
            }
        
        # 進捗計算
        total_tasks = len(chain.tasks)
        completed_tasks = len([t for t in chain.tasks if t.status == TaskStatus.COMPLETED])
        progress = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
        
        # エージェント状態の詳細
        agent_states = []
        for agent_state in chain.agent_states.values():
            enhanced_agent = self.agents.get(agent_state.id)
            agent_info = {
                "id": agent_state.id,
                "role": agent_state.role.value,
                "status": agent_state.status,
                "current_task": agent_state.current_task,
                "completed_tasks_count": len(agent_state.completed_tasks),
                "capabilities": enhanced_agent.capabilities if enhanced_agent else [],
                "tools_available": len(enhanced_agent.tools) if enhanced_agent else 0
            }
            agent_states.append(agent_info)
        
        return {
            "chain_id": chain.id,
            "name": chain.name,
            "target": chain.target,
            "status": chain.status,
            "progress": progress,
            "enhanced": True,
            "agent_states": agent_states,
            "visualization": visualization_data,
            "recent_timeline": chain.timeline[-20:] if chain.timeline else [],
            "logs": self.execution_logs.get(chain_id, [])[-50:],  # Return last 50 logs
            "performance_metrics": {
                "total_agents": len(self.agents),
                "active_agents": len([a for a in chain.agent_states.values() if a.status == "busy"]),
                "total_tools": sum(len(agent.tools) for agent in self.agents.values()),
                "execution_start": chain.started_at.isoformat() if chain.started_at else None
            }
        }
    
    def stop_attack_chain(self, chain_id: str) -> Dict[str, Any]:
        """強化された攻撃チェーンを停止"""
        if chain_id not in self.active_chains:
            return {"error": "Chain not found"}
        
        self.running = False
        chain = self.active_chains[chain_id]
        chain.status = "stopped"
        
        # 実行中のタスクを停止
        for task in chain.tasks:
            if task.status == TaskStatus.RUNNING:
                task.status = TaskStatus.FAILED
                task.error = "Manually stopped"
                task.end_time = datetime.now()
        
        # エージェントの状態をリセット
        for agent_state in chain.agent_states.values():
            if agent_state.status == "busy":
                agent_state.status = "idle"
                agent_state.current_task = None
        
        self._add_timeline_event(chain, "Enhanced attack chain manually stopped")
        self._log_to_chain(chain_id, "warning", "Enhanced attack chain stopped by user")
        
        return {
            "status": "stopped", 
            "chain_id": chain_id,
            "enhanced": True,
            "message": "Enhanced attack chain stopped successfully"
        }


# グローバルインスタンス
_enhanced_orchestrator = None

def get_enhanced_multi_agent_orchestrator() -> EnhancedMultiAgentOrchestrator:
    """強化されたマルチエージェントオーケストレーターインスタンスを取得"""
    global _enhanced_orchestrator
    if _enhanced_orchestrator is None:
        _enhanced_orchestrator = EnhancedMultiAgentOrchestrator()
    return _enhanced_orchestrator
