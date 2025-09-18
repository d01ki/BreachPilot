"""
BreachPilot Shared Knowledge Base
エージェント間共有ナレッジベース
"""
import threading
import uuid
from datetime import datetime
from typing import Dict, List, Any, Callable


class SharedKnowledgeBase:
    """エージェント間共有ナレッジベース"""
    
    def __init__(self):
        self._knowledge = {}
        self._lock = threading.Lock()
        self._subscribers = {}
    
    def store(self, key: str, value: Any, agent_id: str):
        """情報を保存"""
        with self._lock:
            if key not in self._knowledge:
                self._knowledge[key] = []
            
            entry = {
                "value": value,
                "agent_id": agent_id,
                "timestamp": datetime.now(),
                "id": str(uuid.uuid4())
            }
            self._knowledge[key].append(entry)
            
            # 購読者に通知
            self._notify_subscribers(key, entry)
    
    def retrieve(self, key: str) -> List[Dict[str, Any]]:
        """情報を取得"""
        with self._lock:
            return self._knowledge.get(key, [])
    
    def query(self, pattern: str) -> Dict[str, List[Dict[str, Any]]]:
        """パターンマッチングで情報を検索"""
        with self._lock:
            results = {}
            for key, entries in self._knowledge.items():
                if pattern.lower() in key.lower():
                    results[key] = entries
            return results
    
    def subscribe(self, key: str, callback: Callable, agent_id: str):
        """情報更新の購読"""
        if key not in self._subscribers:
            self._subscribers[key] = []
        self._subscribers[key].append((callback, agent_id))
    
    def _notify_subscribers(self, key: str, entry: Dict[str, Any]):
        """購読者に通知"""
        if key in self._subscribers:
            for callback, agent_id in self._subscribers[key]:
                if agent_id != entry["agent_id"]:  # 自分以外に通知
                    try:
                        callback(key, entry)
                    except Exception as e:
                        print(f"Subscription notification error: {e}")
    
    def get_latest(self, key: str) -> Dict[str, Any]:
        """最新の情報を取得"""
        entries = self.retrieve(key)
        if entries:
            return max(entries, key=lambda x: x["timestamp"])
        return {}
    
    def clear(self, key: str = None):
        """情報をクリア"""
        with self._lock:
            if key:
                self._knowledge.pop(key, None)
            else:
                self._knowledge.clear()
    
    def get_all_keys(self) -> List[str]:
        """全てのキーを取得"""
        with self._lock:
            return list(self._knowledge.keys())
