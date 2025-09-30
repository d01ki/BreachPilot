# BreachPilot API Reference

## Base URL
```
http://localhost:8000
```

## Attack Scenario Generation API

### Generate Attack Graph
```http
POST /api/scenario/{session_id}/generate-graph
```

Generates attack graph from completed Nmap and CVE analysis.

**Response:**
```json
{
  "success": true,
  "attack_graph": {
    "total_nodes": 15,
    "total_vulnerabilities": 3,
    "entry_points": 2
  },
  "visualization": { ... }
}
```

### Generate Attack Scenarios
```http
POST /api/scenario/{session_id}/generate-scenarios?max_scenarios=5
```

**Response:**
```json
{
  "success": true,
  "total_scenarios": 5,
  "scenarios": [{ ... }]
}
```

### Approve Scenario (HITL)
```http
POST /api/scenario/{session_id}/scenarios/{scenario_id}/approve
```

**Request Body:**
```json
{
  "approved_by": "user@example.com"
}
```

### Synthesize PoCs
```http
POST /api/scenario/{session_id}/scenarios/{scenario_id}/synthesize-pocs
```

### Execute Scenario
```http
POST /api/scenario/{session_id}/scenarios/{scenario_id}/execute
```

**Request Body:**
```json
{
  "timeout": 3600
}
```

See full documentation for complete API details.