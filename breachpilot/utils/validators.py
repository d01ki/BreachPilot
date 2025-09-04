"""Input validation utilities for BreachPilot."""

import re
import socket
from ipaddress import ip_address, AddressValueError
from typing import Union

from .logger import get_logger

logger = get_logger(__name__)


def is_valid_ip(ip_str: str) -> bool:
    """Validate if string is a valid IP address.
    
    Args:
        ip_str: String to validate as IP address
        
    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ip_address(ip_str)
        return True
    except AddressValueError:
        return False


def is_valid_hostname(hostname: str) -> bool:
    """Validate if string is a valid hostname.
    
    Args:
        hostname: String to validate as hostname
        
    Returns:
        True if valid hostname, False otherwise
    """
    if len(hostname) > 255:
        return False
    
    # Remove trailing dot if present
    if hostname.endswith("."):
        hostname = hostname[:-1]
    
    # Check each label
    allowed = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
    return all(allowed.match(label) for label in hostname.split("."))


def is_valid_target(target: str) -> bool:
    """Validate if string is a valid scan target (IP or hostname).
    
    Args:
        target: String to validate as scan target
        
    Returns:
        True if valid target, False otherwise
    """
    if not target or not isinstance(target, str):
        return False
    
    target = target.strip()
    
    # Check for malicious patterns
    malicious_patterns = [
        r"[;&|`$(){}\[\]<>]",  # Shell metacharacters
        r"\.\.+",              # Path traversal
        r"[\x00-\x1f\x7f-\x9f]", # Control characters
    ]
    
    for pattern in malicious_patterns:
        if re.search(pattern, target):
            logger.warning(f"Potentially malicious target rejected: {target}")
            return False
    
    return is_valid_ip(target) or is_valid_hostname(target)


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal and other issues.
    
    Args:
        filename: Filename to sanitize
        
    Returns:
        Sanitized filename
        
    Raises:
        ValueError: If filename is invalid or dangerous
    """
    if not filename or not isinstance(filename, str):
        raise ValueError("Filename must be a non-empty string")
    
    # Remove path separators and dangerous characters
    filename = filename.strip()
    dangerous_chars = r'[<>:"/\\|?*\x00-\x1f]'
    filename = re.sub(dangerous_chars, '_', filename)
    
    # Remove leading/trailing dots and spaces
    filename = filename.strip('. ')
    
    # Prevent reserved names on Windows
    reserved_names = {
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    }
    
    name_without_ext = filename.split('.')[0].upper()
    if name_without_ext in reserved_names:
        filename = f"safe_{filename}"
    
    # Ensure reasonable length
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        max_name_len = 255 - len(ext) - 1 if ext else 255
        filename = f"{name[:max_name_len]}.{ext}" if ext else name[:255]
    
    if not filename:
        raise ValueError("Filename became empty after sanitization")
    
    return filename


def validate_port(port: Union[int, str]) -> bool:
    """Validate if value is a valid port number.
    
    Args:
        port: Port number to validate
        
    Returns:
        True if valid port number, False otherwise
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def validate_timeout(timeout: Union[int, str]) -> bool:
    """Validate if value is a valid timeout.
    
    Args:
        timeout: Timeout value to validate
        
    Returns:
        True if valid timeout, False otherwise
    """
    try:
        timeout_val = int(timeout)
        return 1 <= timeout_val <= 3600  # 1 second to 1 hour
    except (ValueError, TypeError):
        return False