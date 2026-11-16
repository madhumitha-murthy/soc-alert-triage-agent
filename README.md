# SOC Alert Triage Agent

An AI-powered Security Operations Center (SOC) alert triage agent built with **LangGraph** and **Gemini**. It classifies security alerts as malicious or benign, assigns severity, maps MITRE ATT&CK techniques, and recommends analyst actions.

## Architecture

```
┌─────────────┐     ┌───────────────┐     ┌──────────┐     ┌───────────┐
│  FastAPI     │────>│  LangGraph    │────>│  Gemini   │────>│  Tools    │
│  /triage     │     │  ReAct Agent  │     │  2.0 Flash│     │  (2 LCT)  │
└─────────────┘     └───────────────┘     └──────────┘     └───────────┘
                           │                                      │
                           ▼                                      ▼
                    ┌──────────────┐                   ┌──────────────────┐
                    │ Parse JSON   │                   │ analyse_event    │
                    │ TriageDecision│                   │ lookup_technique │
                    └──────────────┘                   └──────────────────┘
```

**Agent flow:** Entry → LLM calls tools → tools return analysis → LLM produces JSON decision → parse into `TriageDecision`.

### Tools

| Tool | Purpose |
|------|---------|
| `analyse_event_fields` | Inspects raw Windows event fields (process, command line, user, EventID) for suspicious indicators |
| `lookup_technique` | Looks up MITRE ATT&CK technique details from a local database (28 techniques) |

## Project Structure

```
├── src/
│   ├── agents/
│   │   ├── schemas.py          # Pydantic models (AlertInput, TriageDecision)
│   │   ├── tools.py            # LangChain tools for event analysis
│   │   └── triage_agent.py     # LangGraph ReAct agent
│   ├── api/
│   │   └── app.py              # FastAPI endpoints (/triage, /triage/batch, /health)
│   ├── data/
│   │   ├── build_golden_set.py # Builds labeled dataset from OTRF logs + Sigma rules
│   │   ├── sigma_matcher.py    # Lightweight Sigma rule parser
│   │   └── ...                 # Data pipeline utilities
│   └── eval/
│       ├── evaluator.py        # Evaluation harness (accuracy, precision, recall, F1)
│       └── run_eval.py         # CLI entry point for evaluation
├── data/
│   ├── attack_techniques.json  # MITRE ATT&CK technique database
│   └── golden_set/             # Labeled alerts (160: 32 malicious, 128 benign)
├── tests/                      # 63 tests (schemas, tools, agent, eval, API)
├── Dockerfile                  # Multi-stage (production + test targets)
├── docker-compose.yml          # Agent service + test profile
└── .github/workflows/ci.yml    # GitHub Actions (lint + test)
```

## Quick Start

### Prerequisites

- Python 3.11+
- A Gemini API key (for live inference)

### Install

```bash
pip install -e ".[dev]"
```

### Run Tests (no API key needed)

```bash
pytest tests/ -q
```

Tests use a deterministic `FakeLLM` that classifies alerts via heuristics, so no API calls are made.

### Start the API

```bash
export GEMINI_API_KEY=your-key-here
uvicorn src.api.app:app --host 0.0.0.0 --port 8000
```

### Triage an Alert

```bash
curl -X POST http://localhost:8000/triage \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "ALERT-001",
    "rule_name": "Mimikatz Credential Dumping",
    "sigma_level": "critical",
    "description": "Detects mimikatz credential access",
    "matched_event": {
      "Image": "C:\\tools\\mimikatz.exe",
      "CommandLine": "mimikatz.exe sekurlsa::logonpasswords",
      "User": "SYSTEM",
      "EventID": 1
    },
    "techniques": ["T1003.001"]
  }'
```

**Response:**

```json
{
  "alert_id": "ALERT-001",
  "label": "malicious",
  "confidence": 0.95,
  "severity": "critical",
  "techniques": ["T1003.001"],
  "reasoning": "Mimikatz credential dumping detected with SYSTEM privileges.",
  "recommended_action": "Isolate host immediately. Check for lateral movement."
}
```

### Run Evaluation

```bash
make eval          # dev set (10 alerts)
make eval-full     # full golden set (160 alerts)
```

Produces precision, recall, F1, false-alarm rate, severity accuracy, and per-alert latency.

## Docker

```bash
# Run the API
docker compose up agent

# Run tests
docker compose run test
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/triage` | Triage a single alert |
| `POST` | `/triage/batch` | Triage up to 50 alerts |

## Severity Mapping (MITRE ATT&CK Tactics)

| Severity | Tactics |
|----------|---------|
| Critical | Credential Access, Impact, Exploitation |
| High | Persistence, Privilege Escalation, Lateral Movement, Exfiltration |
| Medium | Execution, Defense Evasion, Collection, C2, Initial Access |
| Low | Discovery, Reconnaissance |

## Tech Stack

- **LangGraph** — ReAct agent orchestration with tool calling
- **Gemini 2.0 Flash** — LLM for alert analysis (via langchain-google-genai)
- **FastAPI** — REST API with Pydantic validation
- **Sigma Rules** — Detection rule matching for golden set construction
- **OTRF Attack Logs** — Real Windows attack telemetry for evaluation

## License

MIT
# soc-alert-traige-agent
