"""
BreachPilot Attack Chain Visualizer
攻撃チェーン可視化機能
"""
from typing import Dict, List, Any
from .attack_chain_models import AttackChain, AttackTask, TaskStatus, AttackStage


class AttackChainVisualizer:
    """攻撃チェーン可視化"""
    
    @staticmethod
    def generate_chain_graph(attack_chain: AttackChain) -> Dict[str, Any]:
        """攻撃チェーンのグラフ表現を生成"""
        nodes = []
        edges = []
        
        # タスクノードを作成
        for task in attack_chain.tasks:
            node = {
                "id": task.id,
                "name": task.name,
                "stage": task.stage.value,
                "agent": task.agent_role.value,
                "status": task.status.value,
                "priority": task.priority,
                "duration": task.actual_duration or task.estimated_duration,
                "position": AttackChainVisualizer._calculate_position(task, attack_chain)
            }
            nodes.append(node)
            
            # 依存関係エッジを作成
            for dep_id in task.dependencies:
                edges.append({
                    "from": dep_id,
                    "to": task.id,
                    "type": "dependency"
                })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "total_tasks": len(attack_chain.tasks),
                "completed_tasks": len([t for t in attack_chain.tasks if t.status == TaskStatus.COMPLETED]),
                "failed_tasks": len([t for t in attack_chain.tasks if t.status == TaskStatus.FAILED]),
                "progress": AttackChainVisualizer._calculate_progress(attack_chain)
            }
        }
    
    @staticmethod
    def _calculate_position(task: AttackTask, chain: AttackChain) -> Dict[str, int]:
        """タスクの可視化位置を計算"""
        stage_order = list(AttackStage)
        stage_index = stage_order.index(task.stage)
        
        # 同じステージのタスク数を計算
        same_stage_tasks = [t for t in chain.tasks if t.stage == task.stage]
        task_index = same_stage_tasks.index(task) if task in same_stage_tasks else 0
        
        return {
            "x": stage_index * 150 + 100,
            "y": task_index * 100 + 100
        }
    
    @staticmethod
    def _calculate_progress(chain: AttackChain) -> float:
        """攻撃チェーンの進捗を計算"""
        if not chain.tasks:
            return 0.0
        
        completed = len([t for t in chain.tasks if t.status == TaskStatus.COMPLETED])
        return (completed / len(chain.tasks)) * 100
    
    @staticmethod
    def generate_timeline_data(attack_chain: AttackChain) -> List[Dict[str, Any]]:
        """タイムライン可視化データを生成"""
        timeline_data = []
        
        for event in attack_chain.timeline:
            timeline_data.append({
                "timestamp": event["timestamp"],
                "message": event["message"],
                "task_id": event.get("task_id"),
                "type": "info"
            })
        
        return sorted(timeline_data, key=lambda x: x["timestamp"])
    
    @staticmethod
    def generate_agent_status_data(attack_chain: AttackChain) -> List[Dict[str, Any]]:
        """エージェント状態可視化データを生成"""
        agent_data = []
        
        for agent in attack_chain.agent_states.values():
            agent_data.append({
                "id": agent.id,
                "role": agent.role.value,
                "status": agent.status,
                "current_task": agent.current_task,
                "completed_count": len(agent.completed_tasks),
                "capabilities": agent.capabilities,
                "last_activity": agent.last_activity.isoformat()
            })
        
        return agent_data
