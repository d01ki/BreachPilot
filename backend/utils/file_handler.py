import os
import re
from pathlib import Path
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class FileHandler:
    """Handle file operations for exploit execution"""
    
    @staticmethod
    def clean_content(content: str) -> str:
        """Clean file content from BOM and encoding issues"""
        try:
            # Remove UTF-8 BOM if present
            if content.startswith('\ufeff'):
                content = content[1:]
            
            # Handle various line ending formats
            content = content.replace('\r\n', '\n').replace('\r', '\n')
            
            # Remove null bytes and problematic characters
            content = content.replace('\x00', '').replace('\x0c', '')
            
            return content.strip()
        except Exception as e:
            logger.warning(f"Error cleaning content: {e}")
            return content
    
    @staticmethod
    def clean_file_encoding(filepath: Path) -> bool:
        """Clean file encoding issues like BOM"""
        try:
            with open(filepath, 'rb') as f:
                raw_content = f.read()
            
            # Detect and handle BOM
            if raw_content.startswith(b'\xef\xbb\xbf'):
                raw_content = raw_content[3:]
                logger.debug(f"Removed UTF-8 BOM from {filepath.name}")
            
            # Decode content
            try:
                content = raw_content.decode('utf-8')
            except UnicodeDecodeError:
                content = raw_content.decode('latin-1', errors='ignore')
            
            # Clean and rewrite
            cleaned_content = FileHandler.clean_content(content)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(cleaned_content)
            
            return True
        except Exception as e:
            logger.error(f"Error cleaning file {filepath}: {e}")
            return False
    
    @staticmethod
    def detect_file_extension(code: str) -> str:
        """Detect appropriate file extension based on code content"""
        code_lower = code.lower()
        
        if any(kw in code_lower for kw in ['import ', 'def ', 'class ', 'from ', 'print(']):
            return 'py'
        elif any(kw in code_lower for kw in ['#!/bin/bash', '#!/bin/sh', 'curl ', 'wget ', 'echo ']):
            return 'sh'
        elif any(kw in code_lower for kw in ['require ', 'puts ', 'ruby']):
            return 'rb'
        elif any(kw in code_lower for kw in ['use ', 'sub ', 'my ', 'perl']):
            return 'pl'
        else:
            return 'py'  # Default to Python
    
    @staticmethod
    def is_executable_code(code: str) -> bool:
        """Check if content appears to be executable code"""
        if not code or len(code.strip()) < 20:
            return False
        
        code_lower = code.lower()
        
        code_indicators = [
            'import ', 'def ', 'class ', 'from ', 'if ', 'for ', 'while ',
            '#!/bin/bash', '#!/bin/sh', '#!/usr/bin/python',
            'curl ', 'wget ', 'nc ', 'nmap ', 'ssh ',
            'require ', 'puts ', '$', 'use ', 'sub ', 'my '
        ]
        
        non_code_indicators = ['<html', '<div', '<script', 'http://']
        
        indicator_count = sum(1 for indicator in code_indicators if indicator in code_lower)
        non_code_count = sum(1 for indicator in non_code_indicators if indicator in code_lower)
        
        return indicator_count >= 2 and non_code_count == 0
    
    @staticmethod
    def inject_target_ip(code: str, target_ip: str) -> str:
        """Intelligently inject target IP into code"""
        try:
            patterns = [
                (r'target\s*=\s*["\']([^"\']+)["\']', f'target = "{target_ip}"'),
                (r'host\s*=\s*["\']([^"\']+)["\']', f'host = "{target_ip}"'),
                (r'TARGET_IP\s*=\s*["\']([^"\']+)["\']', f'TARGET_IP = "{target_ip}"'),
                (r'rhost\s*=\s*["\']([^"\']+)["\']', f'rhost = "{target_ip}"'),
                (r'RHOST\s*=\s*["\']([^"\']+)["\']', f'RHOST = "{target_ip}"'),
                (r'192\.168\.1\.1\d+', target_ip),
                (r'10\.0\.0\.\d+', target_ip),
                (r'127\.0\.0\.1', target_ip),
                (r'localhost', target_ip),
            ]
            
            modified_code = code
            for pattern, replacement in patterns:
                if re.search(pattern, modified_code):
                    modified_code = re.sub(pattern, replacement, modified_code)
            
            # Add target IP as argument for Python code
            if 'sys.argv' not in modified_code and 'ARGV' not in modified_code:
                if 'import' in modified_code or modified_code.strip().startswith('#!/usr/bin/env python'):
                    modified_code = f"""import sys\ntarget_ip = "{target_ip}" if len(sys.argv) <= 1 else sys.argv[1]\n\n{modified_code}"""
            
            return modified_code
        except Exception as e:
            logger.warning(f"Error injecting target IP: {e}")
            return code
    
    @staticmethod
    def wrap_code_safely(code: str, cve_id: str, target_ip: str, extension: str) -> str:
        """Wrap code with safety measures and metadata"""
        try:
            if extension == 'py':
                return f"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# CVE: {cve_id}, Target: {target_ip}, Generated by BreachPilot

import sys, signal, traceback
from datetime import datetime

def timeout_handler(signum, frame):
    print("[TIMEOUT] Exploit timed out after 120 seconds")
    sys.exit(1)

def main():
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(120)
    try:
        print(f"[START] Exploit execution at {{datetime.now()}}")
        print(f"[TARGET] IP: {target_ip}, [CVE] {cve_id}")
        print("-" * 50)
{FileHandler._indent_code(code, 8)}
        print("-" * 50)
        print("[SUCCESS] Exploit completed")
    except KeyboardInterrupt:
        print("[INTERRUPTED] User interrupt")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] {{str(e)}}")
        traceback.print_exc()
        sys.exit(1)
    finally:
        signal.alarm(0)

if __name__ == "__main__":
    main()
"""
            elif extension == 'pl':
                return f"""#!/usr/bin/perl
# CVE: {cve_id}, Target: {target_ip}, Generated by BreachPilot
use strict; use warnings; use utf8;
binmode(STDOUT, ':utf8'); binmode(STDERR, ':utf8');

my $target_ip = "{target_ip}";
print "[START] Exploit execution at " . localtime() . "\\n";
print "[TARGET] IP: $target_ip, [CVE] {cve_id}\\n";
print "-" x 50 . "\\n";

{code}

print "-" x 50 . "\\n";
print "[SUCCESS] Exploit completed\\n";
"""
            elif extension == 'sh':
                return f"""#!/bin/bash
# CVE: {cve_id}, Target: {target_ip}, Generated by BreachPilot
set -e; set -o pipefail
TARGET_IP="{target_ip}"
echo "[START] Exploit execution at $(date)"
echo "[TARGET] IP: $TARGET_IP, [CVE] {cve_id}"
echo "$(printf '%.0s-' {{1..50}})"
timeout 120 bash -c '{code.replace("'", "'\\''")}' || {{ echo "[ERROR] Failed/timed out"; exit 1; }}
echo "$(printf '%.0s-' {{1..50}})"
echo "[SUCCESS] Exploit completed"
"""
            else:
                return f"# CVE: {cve_id}, Target: {target_ip}, Generated by BreachPilot\n\n{code}"
        except Exception as e:
            logger.warning(f"Error wrapping code: {e}")
            return code
    
    @staticmethod
    def _indent_code(code: str, spaces: int) -> str:
        """Indent code for proper structure"""
        try:
            return '\n'.join(' ' * spaces + line if line.strip() else '' for line in code.split('\n'))
        except:
            return code
