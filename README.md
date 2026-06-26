# QueueStorm Investigator

QueueStorm Investigator is a production-grade, highly resilient backend analysis pipeline designed to process, classify, and route customer support tickets for digital financial services. It implements a hybrid Rule Engine + LLM model that enforces strict schema compliance and multi-layer deterministic safety guardrails.

---

## Technical Architecture

QueueStorm Investigator employs an 8-layer architecture to process inputs:
1. **Sanitization / Truncation**: Inputs are truncated if they exceed limits, and transaction history is restricted to the top 8 entries to maintain token economy and avoid LLM confusion.
2. **Deterministic Rule Engine**: Matches transaction amounts, phone numbers, duplicates, and checks for phishing signals prior to LLM execution.
3. **Structured Context Injection**: Injecting rules as trusted metadata hints directly into the system prompt.
4. **Resilient LLM Execution**: Invoking Gemini 2.5 Flash with strict JSON schema configurations and a hard 20-second timeout.
5. **Rule-Enhanced Fallback**: Instantly recovers if the LLM times out or rate-limits, utilizing deterministic rules to correctly resolve the issue type, transaction matching, and routing.
6. **Post-Validation Parser**: Enforces strict Pydantic enums, aligns hallucinated transaction IDs to match user history, and determines human review flags.
7. **Double-Lock Safety Guardrails**: Deterministically sanitizes responses for forbidden content (credentials, unauthorized commitments, third-party redirects) and appends safety instructions.
8. **FastAPI Web Server**: Serves responses with sub-second health checks and handles standard FastAPI validation errors gracefully without returning HTTP 500.

---

## Tech Stack
* **FastAPI** + **Uvicorn** (Asynchronous High-Performance API)
* **Pydantic v2** (Strict Schema Modeling & Enums)
* **Google Generative AI** (Gemini 2.5 Flash API Client)
* **Pytest** (Automated Test Suite)

---

## Setup & Local Installation

### Prerequisites
* Python 3.11+
* Pip (Python package manager)

### Installation Steps
1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd sust_preli
   ```

2. **Configure Environment Variables**:
   Copy `.env.example` to `.env` and fill in your Gemini API key:
   ```bash
   copy .env.example .env
   ```
   Edit `.env` to set your `GEMINI_API_KEY`:
   ```env
   GEMINI_API_KEY=your_gemini_api_key_here
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Server**:
   ```bash
   python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```
   The API will be available at `http://localhost:8000`.

---

## Running with Docker

1. **Build the Docker Image**:
   ```bash
   docker build -t queuestorm-team .
   ```

2. **Run the Container**:
   Create a file `judging.env` containing your environment variables, then run:
   ```bash
   docker run -p 8000:8000 --env-file judging.env queuestorm-team
   ```

---

## API Endpoints

### 1. Interactive Playground Dashboard
* **Endpoint**: `GET /`
* **Description**: Serves a premium, highly interactive single-page dashboard that visualizes ticket investigations, allows live edits, loads the 10 SUST preliminary evaluation cases with one click, and diagrams the processing logs.

### 2. Health Check
* **Endpoint**: `GET /health`
* **Response**:
  ```json
  {
    "status": "ok"
  }
  ```

### 2. Ticket Investigation & Classification
* **Endpoint**: `POST /analyze-ticket`
* **Request Body**:
  ```json
  {
    "ticket_id": "TKT-001",
    "complaint": "I sent 5000 BDT to the wrong number. Please help me get it back.",
    "transaction_history": [
      {
        "transaction_id": "TXN-9101",
        "timestamp": "2026-04-14T14:08:22Z",
        "type": "transfer",
        "amount": 5000.0,
        "counterparty": "+8801719876543",
        "status": "completed"
      }
    ]
  }
  ```
* **Response Body**:
  ```json
  {
    "ticket_id": "TKT-001",
    "relevant_transaction_id": "TXN-9101",
    "evidence_verdict": "consistent",
    "case_type": "wrong_transfer",
    "severity": "high",
    "department": "dispute_resolution",
    "agent_summary": "Customer reports sending 5000 BDT via TXN-9101 to +8801719876543...",
    "recommended_next_action": "Verify TXN-9101 details and initiate wrong-transfer dispute workflow...",
    "customer_reply": "We have noted your concern about transaction TXN-9101. Please do not share your PIN...",
    "human_review_required": true,
    "confidence": 0.85,
    "reason_codes": ["wrong_transfer", "rule_fallback"]
  }
  ```

---

## Safety Logic & Guardrails

The application executes a **deterministic post-processing safety guardrail** (Double-Lock System) on `customer_reply` and `recommended_next_action` variables:
* **Credential Protection**: Identifies and blocks any attempts to request PINs, OTPs, or passwords (fails or sanitizes the response).
* **Financial Commitments**: Replaces unauthorized refund commitments (e.g. "We will refund you") with safe canonical text ("any eligible amount will be returned through official channels").
* **Third-Party Escapes**: Scrubs external phone numbers, suspicious domains, and URLs that could facilitate phishing redirection.
* **Mandatory Safety Disclaimers**: Injects security reminders dynamically in the appropriate language (Bangla or English) to empower the customer.

---

## Model Selection Reasoning

We chose **Gemini 2.5 Flash** for the following reasons:
1. **Language Capability**: Superior out-of-the-box support for complex Bangla code-switching, Bangla script, and Banglish (Bengali written in English letters).
2. **Speed & Efficiency**: Ultra-low latency suited for real-time customer support routing under strict time SLAs.
3. **Structured Output Enforcer**: Native support for strict JSON response MIME types.

---

## Known Limitations & Edge Cases

* **Rate Limits**: Free tier Gemini API keys are subject to standard rate-limiting. The system handles HTTP 429 exceptions gracefully by activating the local rule-based fallback model.
* **Latency Variance**: Complex LLM analysis can occasionally experience network spikes. A hard 20-second timeout ensures the API responds within the competition's 30-second budget.
