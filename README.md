# SolrCloud Observability & RCA — V4 (two-stage LangGraph)

**Core idea:** Python does evidence-based log analysis. LangGraph optionally
runs two LLM stages with ONE safe read-only diagnostic between them.
The browser UI offers hosted providers, per-call model parameters, bounded
diagnostic settings, evidence preview and a fake-model practice workflow.

## Start here (Windows PowerShell)

Extract the ZIP. Open PowerShell inside the extracted project folder.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open **http://localhost:8501**. Use the virtual environment's interpreter
for every command, not bare `py -m streamlit`. Python 3.11–3.13 can be used;
see `py -0p` if 3.12 is unavailable. The `.venv` is created locally and is
NOT bundled into the ZIP.

### Step 1: without any LLM

Choose `Bundled demo`. You should see **21,609 parsed events and two
incidents**. Visit Overview, Incidents & evidence, Adaptive detection.

### Step 2: practice the real LangGraph workflow with a fake model

Open `LangGraph AI investigation`, select the Node A incident and click
`Practice LangGraph (fake model, no API)`. The graph calls a deterministic fake
model for both stages and runs a REAL read-only diagnostic. This is NOT AI.

### Step 3: connect a hosted model (recommended; no GPU needed)

1. Sign up at https://console.groq.com/ and create a Groq API key.
2. In the sidebar select **Groq — recommended**. Endpoint should be
   `https://api.groq.com/openai/v1`, model `openai/gpt-oss-120b`.
3. Paste the key in Streamlit's password field, not the source code.
4. Click `Check model connection` (no logs sent), then select the Node A
   incident and click `Investigate with REAL hosted/local AI`.
5. Look at the steps: initial LLM hypothesis → read-only diagnostic → final
   LLM answer + validation. `AI_PROPOSAL_REQUIRES_HUMAN_REVIEW` indicates a
   model proposal passed formatting and evidence checks; it is NOT proof of RCA.

Alternatives: Google Gemini, Hugging Face Inference Providers, OpenAI, local
Ollama, or any OpenAI-compatible Chat Completions endpoint. The API provider
may impose quotas, billing and parameter constraints.

### What can the model request?

An allowlisted `gc_query_timeline`, `indexing_activity`,
`zookeeper_timeline`, `error_breakdown`, or `none`.
All diagnostics only read already-loaded parsed events within the adjustable
incident time window; they do not access servers or execute commands.

### Model parameters configurable in UI

Provider, base URL, model, API key, context capacity (planning bound), input
budget (estimated tokens), initial evidence count, max output tokens per call,
temperature, optional top_p, timeout, reasoning effort, JSON-object mode,
allowed diagnostics, maximum tool rounds, time window, extra log excerpts, and
retries per LLM stage. Core anomaly thresholds remain deterministic and are
not overridden by model settings.

## Files you need to understand

| File | Role |
|---|---|
| `generate_logs.py` | Generates simulated Solr + JVM GC logs; labels separate |
| `parser.py` | Reads normal INFO, WARN and ERROR log entries |
| `analyzer.py` | Fixed rules + MAD/CUSUM + incident correlation |
| `agent.py` | TWO LangGraph stages, four read-only tool choices, validation |
| `app.py` | Single Streamlit UI; no LLM invoked without clicking button |
| `cli.py` | Headless batch analysis/export |
| `evaluate.py` | Synthetic fault evaluation (not production benchmark) |
| `watch.py`, `storage.py` | Periodic polling / optional SQLite persistence |

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe evaluate.py --output evaluation.json
```

See `docs/TWO_STAGE_EXPLAINED.md` for the full plain-language diagram, model
tradeoffs, prompts, and the exact division of responsibility.

**Disclosure:** The bundled log files are synthetic; no live SolrCloud health
is checked. The model may send selected logs to a third-party API; only share
information you are authorized to disclose. There is no automatic remediation.
