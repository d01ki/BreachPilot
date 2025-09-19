"""
Mock imports for missing dependencies during development/testing
"""
import uuid


class MockModule:
    def __init__(self, name):
        self.name = name
    
    def __getattr__(self, item):
        def mock_func(*args, **kwargs):
            print(f"Mock {self.name}.{item} called with args={args}, kwargs={kwargs}")
            if item == "load_config":
                return {}
            elif item == "save_config":
                return True
            elif item == "get_orchestrator":
                class MockOrchestrator:
                    def analyze_scan_results(self, *args):
                        return {"status": "success", "result": "Mock AI analysis", "path": "/mock/path"}
                    def research_poc(self, *args):
                        return {"status": "success", "result": "Mock PoC research", "path": "/mock/path"}
                    def analyze_exploit_results(self, *args):
                        return {"status": "success", "result": "Mock exploit analysis", "path": "/mock/path"}
                return MockOrchestrator()
            elif item == "run_scan":
                return "/mock/scan.json"
            elif item == "fetch_poc":
                return "/mock/poc.json"
            elif item == "run_exploit":
                return "/mock/exploit.json"
            elif item == "generate_report":
                return "/mock/report.md", "/mock/report.pdf"
            elif item == "get_multi_agent_orchestrator":
                class MockMultiAgentOrchestrator:
                    def create_attack_chain(self, target, objective):
                        class MockChain:
                            def __init__(self):
                                self.id = str(uuid.uuid4())
                        return MockChain()
                    def get_chain_status(self, chain_id):
                        return {"status": "running", "logs": []}
                    def stop_attack_chain(self, chain_id):
                        return {"status": "stopped"}
                return MockMultiAgentOrchestrator()
            return None
        return mock_func


# Try to import real modules, fall back to mocks
try:
    from src.agents.scan_agent import run_scan
    from src.agents.poc_agent import fetch_poc
    from src.agents.exploit_agent import run_exploit
    from src.agents.report_agent import generate_report
    from src.agents.ai_orchestrator import get_orchestrator
    from src.agents.multi_agent_orchestrator import get_multi_agent_orchestrator
    from src.utils.config import load_config, save_config
except ImportError:
    print("Warning: Using mock modules for missing dependencies")
    run_scan = MockModule("scan_agent").run_scan
    fetch_poc = MockModule("poc_agent").fetch_poc
    run_exploit = MockModule("exploit_agent").run_exploit
    generate_report = MockModule("report_agent").generate_report
    get_orchestrator = MockModule("ai_orchestrator").get_orchestrator
    get_multi_agent_orchestrator = MockModule("multi_agent_orchestrator").get_multi_agent_orchestrator
    load_config = MockModule("config").load_config
    save_config = MockModule("config").save_config