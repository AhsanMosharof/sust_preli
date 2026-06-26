# QueueStorm Investigator — Runbook / Judging Guide

This runbook guides judges and developers through the steps of deploying, running, and validating QueueStorm Investigator.

---

## 1. Quick Verification & Execution Checklist

Before submitting or reviewing, ensure the following checklist is verified:

| Step | Action | Command / Check | Status |
| --- | --- | --- | --- |
| 1 | **Prerequisites Check** | Python 3.11+ is installed. | Completed |
| 2 | **Install Dependencies** | Run `pip install -r requirements.txt` | Completed |
| 3 | **Execute Test Suite** | Run `python -m pytest tests/` | Passed (57/57) |
| 4 | **Docker Build** | Run `docker build -t queuestorm-team .` | Ready |
| 5 | **Docker Size Validation** | Check that the final image is `< 500MB` | Ready |
| 6 | **Generate Sample Output** | Run API and fetch response to confirm schema | Generated |

---

## 2. Setting Up the Environment

### Local Configuration
Create a `.env` file from `.env.example` in the project root:
```bash
copy .env.example .env
```
Fill in the API key (leave empty if you want to verify the local rule-based fallback engine):
```env
GEMINI_API_KEY=AIzaSy...
MODEL_NAME=gemini-2.5-flash
PORT=8000
LLM_TIMEOUT_SECONDS=20
```

---

## 3. Running Automated Tests

Run the full pytest suite to verify safety, schema compliance, health endpoints, and sample cases:

```bash
# Run all tests
python -m pytest tests/ -v

# Run safety adversarial tests specifically
python -m pytest tests/test_safety.py -v

# Run schema validation tests specifically
python -m pytest tests/test_schema.py -v

# Run public sample case validation specifically
python -m pytest tests/test_sample_cases.py -v
```

---

## 4. Docker Deployment Instructions

### Build the Image
To build the optimized Docker container:
```bash
docker build -t queuestorm-team .
```

### Validate Image Size
Verify that the image complies with size constraints (must be `< 500MB`):
```bash
docker images queuestorm-team
```
*(Our base image `python:3.11-slim` ensures the final image footprint remains ~200MB–300MB).*

### Run the Docker Container
Launch the container by passing environment variables:
```bash
# Using a local env file
docker run -d -p 8000:8000 --env-file .env queuestorm-team
```

---

## 5. Manual Endpoint Testing & UI Dashboard

### Access the Interactive UI Dashboard
To test and visualize your tickets interactively:
1. Open your browser and navigate to `http://localhost:8000/`
2. Click any of the 10 loaded sample cases to automatically populate the forms and history.
3. Click **Run Investigation Pipeline** to trigger real-time classification, routing, and guardrail validation.

### Verify Health Check
Ensure the service responds under 1 second:
```bash
curl http://localhost:8000/health
```
**Expected Output:**
```json
{"status": "ok"}
```

### Verify Ticket Analysis Pipeline
Send a ticket payload to ensure the analyzer handles it:
```bash
curl -X POST http://localhost:8000/analyze-ticket \
     -H "Content-Type: application/json" \
     -d @SUST_Preli_Sample_Cases.json
```
*(Alternatively, copy any input payload from `SUST_Preli_Sample_Cases.json` and send it as the JSON body).*

---

## 6. Fallback and Safety Guardrails Behavior

* **LLM Offline / Rate-Limited**: The system is designed to gracefully degrade. If the Gemini API is blocked or offline, our deterministic rule engine parses matching details (case type, severity, routing, transaction verification) and routes the issue correctly.
* **Safety Double-Lock**: The safety guardrail applies *after* LLM output and *before* final serialization. If any unsafe text leaks from the LLM, the regex scrubbers dynamically sanitize or replace it (e.g. converting a refund promise to safe text).
