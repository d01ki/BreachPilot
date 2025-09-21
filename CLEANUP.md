# Files to Delete

The following files/directories are from the old implementation and should be deleted:

## Root Level
- `app.py` - Old Flask app
- `api_realtime_endpoints.py` - Old API endpoints  
- `requirements_realtime.txt` - Redundant requirements

## Directories
- `breachpilot/` - Old implementation
- `core/` - Old core module
- `src/` - Old source directory
- `templates/` - Old templates (not used in new implementation)

## Instructions
Run the following commands to clean up:

```bash
rm app.py api_realtime_endpoints.py requirements_realtime.txt
rm -rf breachpilot/ core/ src/ templates/
```
