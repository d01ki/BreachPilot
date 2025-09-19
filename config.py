"""
BreachPilot Production Configuration and Deployment Guide
実運用での再現性を意識した設定管理
"""
import os
import json
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Optional
import logging

@dataclass
class BreachPilotConfig:
    """BreachPilot configuration management"""
    
    # Environment settings
    environment: str = "development"  # development, staging, production
    debug: bool = True
    
    # API Keys (from environment variables)
    anthropic_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    
    # Demo/Production mode
    demo_mode: bool = True
    safe_targets_only: bool = True
    
    # Demo targets configuration
    demo_targets: List[str] = None
    
    # Tool execution settings
    tool_execution_timeout: int = 300
    max_concurrent_agents: int = 6
    enable_real_tools: bool = False
    
    # Storage and reporting
    reports_directory: str = "reports"
    max_report_retention_days: int = 30
    max_stored_jobs: int = 50
    
    # Network and security
    allowed_networks: List[str] = None
    rate_limit_per_hour: int = 100
    
    # Logging
    log_level: str = "INFO"
    log_file: str = "breachpilot.log"
    
    def __post_init__(self):
        if self.demo_targets is None:
            self.demo_targets = [
                "10.10.10.40",  # Blue (EternalBlue scenario)
                "10.10.10.75",  # Shocker (Struts scenario)
                "10.10.10.14",  # Forest (Zerologon scenario)
                "127.0.0.1",    # Localhost testing
                "scanme.nmap.org"  # Public test target
            ]
        
        if self.allowed_networks is None:
            self.allowed_networks = [
                "10.10.10.0/24",    # HTB-style lab network
                "192.168.1.0/24",   # Local lab network
                "172.16.0.0/16",    # Private lab network
                "127.0.0.1/32"      # Localhost
            ]
        
        # Load from environment variables
        self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.environment = os.getenv("BREACHPILOT_ENV", "development")
        self.demo_mode = os.getenv("BREACHPILOT_DEMO_MODE", "true").lower() == "true"
        self.enable_real_tools = os.getenv("BREACHPILOT_REAL_TOOLS", "false").lower() == "true"


class ConfigManager:
    """Configuration management for different environments"""
    
    def __init__(self, config_file: str = "config.json"):
        self.config_file = Path(config_file)
        self.config = self._load_config()
        self._setup_logging()
    
    def _load_config(self) -> BreachPilotConfig:
        """Load configuration from file and environment"""
        
        # Default configuration
        config_data = {}
        
        # Load from file if exists
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                logging.info(f"Loaded configuration from {self.config_file}")
            except Exception as e:
                logging.warning(f"Failed to load config file: {e}")
        
        # Create config object
        config = BreachPilotConfig(**config_data)
        
        # Environment-specific overrides
        if config.environment == "production":
            config.debug = False
            config.demo_mode = False
            config.safe_targets_only = True
            config.enable_real_tools = True
            config.log_level = "WARNING"
        elif config.environment == "staging":
            config.debug = True
            config.demo_mode = True
            config.enable_real_tools = False
            config.log_level = "INFO"
        
        return config
    
    def _setup_logging(self):
        """Setup logging based on configuration"""
        logging.basicConfig(
            level=getattr(logging, self.config.log_level),
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            handlers=[
                logging.FileHandler(self.config.log_file),
                logging.StreamHandler()
            ]
        )
    
    def save_config(self):
        """Save current configuration to file"""
        config_dict = {
            "environment": self.config.environment,
            "debug": self.config.debug,
            "demo_mode": self.config.demo_mode,
            "safe_targets_only": self.config.safe_targets_only,
            "demo_targets": self.config.demo_targets,
            "tool_execution_timeout": self.config.tool_execution_timeout,
            "max_concurrent_agents": self.config.max_concurrent_agents,
            "enable_real_tools": self.config.enable_real_tools,
            "reports_directory": self.config.reports_directory,
            "max_report_retention_days": self.config.max_report_retention_days,
            "max_stored_jobs": self.config.max_stored_jobs,
            "allowed_networks": self.config.allowed_networks,
            "rate_limit_per_hour": self.config.rate_limit_per_hour,
            "log_level": self.config.log_level,
            "log_file": self.config.log_file
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(config_dict, f, indent=2)
        
        logging.info(f"Configuration saved to {self.config_file}")
    
    def is_target_allowed(self, target: str) -> bool:
        """Check if target is allowed for testing"""
        import ipaddress
        
        if self.config.safe_targets_only:
            # Only allow demo targets
            return target in self.config.demo_targets
        
        try:
            target_ip = ipaddress.ip_address(target)
            
            # Check against allowed networks
            for network in self.config.allowed_networks:
                if target_ip in ipaddress.ip_network(network, strict=False):
                    return True
            
            return False
        except ValueError:
            # Handle hostnames
            if self.config.demo_mode:
                return target in self.config.demo_targets
            return True  # Allow hostnames in production
    
    def get_scenario_for_target(self, target: str) -> Dict:
        """Get appropriate scenario for target"""
        scenarios = {
            "10.10.10.40": {
                "name": "Legacy Windows Server (Blue)",
                "description": "Windows Server 2008 R2 vulnerable to EternalBlue",
                "primary_cve": "CVE-2017-0144",
                "difficulty": "Medium",
                "focus": "SMB exploitation and lateral movement"
            },
            "10.10.10.75": {
                "name": "Apache Struts Web Server (Shocker)",
                "description": "Ubuntu server with vulnerable Apache Struts2",
                "primary_cve": "CVE-2017-5638",
                "difficulty": "Easy",
                "focus": "Web application exploitation"
            },
            "10.10.10.14": {
                "name": "Domain Controller (Forest)",
                "description": "Windows Server 2016 Domain Controller",
                "primary_cve": "CVE-2020-1472",
                "difficulty": "Hard",
                "focus": "Active Directory compromise via Zerologon"
            },
            "127.0.0.1": {
                "name": "Localhost Testing",
                "description": "Local system for safe testing",
                "primary_cve": "CVE-2021-44228",
                "difficulty": "Easy",
                "focus": "Tool validation and demonstration"
            },
            "scanme.nmap.org": {
                "name": "Nmap Test Server",
                "description": "Official Nmap test target",
                "primary_cve": None,
                "difficulty": "Easy",
                "focus": "Network discovery and service enumeration"
            }
        }
        
        return scenarios.get(target, {
            "name": "Generic Target",
            "description": "Standard penetration test target",
            "primary_cve": None,
            "difficulty": "Unknown",
            "focus": "Comprehensive security assessment"
        })


# Global configuration instance
_config_manager = None

def get_config() -> BreachPilotConfig:
    """Get global configuration instance"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager.config

def get_config_manager() -> ConfigManager:
    """Get global configuration manager instance"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


# Production deployment helpers
class DeploymentValidator:
    """Validate deployment readiness"""
    
    @staticmethod
    def validate_production_readiness() -> Dict[str, bool]:
        """Check if system is ready for production deployment"""
        config = get_config()
        checks = {}
        
        # API keys check
        checks["anthropic_api_key"] = bool(config.anthropic_api_key)
        checks["openai_api_key"] = bool(config.openai_api_key)
        
        # Security settings
        checks["safe_targets_only"] = config.safe_targets_only
        checks["demo_mode_disabled"] = not config.demo_mode
        checks["debug_disabled"] = not config.debug
        
        # Tool availability
        checks["nmap_available"] = DeploymentValidator._check_tool("nmap")
        checks["nikto_available"] = DeploymentValidator._check_tool("nikto")
        
        # Directory permissions
        reports_dir = Path(config.reports_directory)
        checks["reports_directory_writable"] = DeploymentValidator._check_directory_writable(reports_dir)
        
        # Log file writable
        log_file = Path(config.log_file)
        checks["log_file_writable"] = DeploymentValidator._check_file_writable(log_file)
        
        return checks
    
    @staticmethod
    def _check_tool(tool_name: str) -> bool:
        """Check if a tool is available in PATH"""
        import shutil
        return shutil.which(tool_name) is not None
    
    @staticmethod
    def _check_directory_writable(directory: Path) -> bool:
        """Check if directory is writable"""
        try:
            directory.mkdir(parents=True, exist_ok=True)
            test_file = directory / ".write_test"
            test_file.touch()
            test_file.unlink()
            return True
        except:
            return False
    
    @staticmethod
    def _check_file_writable(file_path: Path) -> bool:
        """Check if file is writable"""
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, 'a'):
                pass
            return True
        except:
            return False
    
    @staticmethod
    def generate_deployment_report() -> str:
        """Generate deployment readiness report"""
        checks = DeploymentValidator.validate_production_readiness()
        
        report = ["BreachPilot Deployment Readiness Report", "=" * 45, ""]
        
        passed = sum(1 for check in checks.values() if check)
        total = len(checks)
        
        report.append(f"Overall: {passed}/{total} checks passed")
        report.append("")
        
        for check_name, result in checks.items():
            status = "✅ PASS" if result else "❌ FAIL"
            report.append(f"{status} {check_name.replace('_', ' ').title()}")
        
        report.append("")
        
        if passed == total:
            report.append("🎉 System is ready for production deployment!")
        else:
            report.append("⚠️  Please address failed checks before production deployment")
            report.append("")
            report.append("Common fixes:")
            if not checks.get("anthropic_api_key"):
                report.append("- Set ANTHROPIC_API_KEY environment variable")
            if not checks.get("openai_api_key"):
                report.append("- Set OPENAI_API_KEY environment variable")
            if not checks.get("nmap_available"):
                report.append("- Install nmap: sudo apt-get install nmap")
            if not checks.get("nikto_available"):
                report.append("- Install nikto: sudo apt-get install nikto")
        
        return "\n".join(report)


# Environment configuration templates
ENVIRONMENT_CONFIGS = {
    "development": {
        "debug": True,
        "demo_mode": True,
        "safe_targets_only": True,
        "enable_real_tools": False,
        "log_level": "DEBUG"
    },
    "staging": {
        "debug": True,
        "demo_mode": True,
        "safe_targets_only": True,
        "enable_real_tools": False,
        "log_level": "INFO"
    },
    "production": {
        "debug": False,
        "demo_mode": False,
        "safe_targets_only": True,
        "enable_real_tools": True,
        "log_level": "WARNING"
    }
}


def setup_environment(env_name: str):
    """Setup environment-specific configuration"""
    if env_name not in ENVIRONMENT_CONFIGS:
        raise ValueError(f"Unknown environment: {env_name}")
    
    config_manager = get_config_manager()
    env_config = ENVIRONMENT_CONFIGS[env_name]
    
    # Update configuration
    for key, value in env_config.items():
        setattr(config_manager.config, key, value)
    
    # Save configuration
    config_manager.save_config()
    
    logging.info(f"Environment configured for: {env_name}")
    
    return config_manager.config


if __name__ == "__main__":
    # CLI for deployment validation
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "validate":
            print(DeploymentValidator.generate_deployment_report())
        elif command == "setup" and len(sys.argv) > 2:
            env_name = sys.argv[2]
            try:
                setup_environment(env_name)
                print(f"✅ Environment configured for: {env_name}")
            except ValueError as e:
                print(f"❌ Error: {e}")
        else:
            print("Usage:")
            print("  python config.py validate              - Check deployment readiness")
            print("  python config.py setup <environment>   - Setup environment (development/staging/production)")
    else:
        # Show current configuration
        config = get_config()
        print("Current BreachPilot Configuration:")
        print(f"Environment: {config.environment}")
        print(f"Demo Mode: {config.demo_mode}")
        print(f"Safe Targets Only: {config.safe_targets_only}")
        print(f"Real Tools Enabled: {config.enable_real_tools}")
        print(f"Max Concurrent Agents: {config.max_concurrent_agents}")
        print(f"Demo Targets: {len(config.demo_targets)} configured")
