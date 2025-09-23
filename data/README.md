# Data Directory

This directory contains JSON files generated during scans:

- `session_<session_id>.json` - Complete session data including all scan results
- `<target_ip>_osint.json` - OSINT scan results
- `<target_ip>_nmap.json` - Nmap scan results  
- `<target_ip>_nmap.xml` - Raw nmap XML output for debugging

## Example Structure

```
data/
├── session_12345678-1234-1234-1234-123456789abc.json
├── 192.168.1.100_osint.json
├── 192.168.1.100_nmap.json
└── 192.168.1.100_nmap.xml
```

## Sample Session Data

Each session file contains the complete scan workflow data that can be loaded and resumed by the backend.
