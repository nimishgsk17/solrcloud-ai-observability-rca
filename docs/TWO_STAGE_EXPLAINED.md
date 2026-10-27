# V4: two-stage evidence-first LangGraph investigation

## 1. Architecture (read top to bottom)

```text
SIMULATED Solr logs + JVM GC logs (3 nodes, 6 text files)
    |
    v
parser.py : normalize every supported INFO/WARN/ERROR line; retain evidence IDs
    |
    v
analyzer.py : hard-failure rules + adaptive rolling MAD/CUSUM
    |
    v
analyzer.py : relate findings by node, time, family, shared ZK topology
    |
    v
INCIDENT + deterministic rule-based RCA (works without any model)
    |
    v
SELECT ONE INCIDENT in Streamlit
    |
    v
agent.py : INITIAL DOSSIER (e.g. 12 representative cited excerpts)
    |
    v
LLM #1 : preliminary hypothesis + choose ONE named read-only check
    |                  (or none)
    v
Python tool (allowlisted) : summarize existing in-memory logs only
    |
    v
agent.py : FINAL DOSSIER = original + preliminary hypothesis + tool summary
    |
    v
LLM #2 : 1-3 possible RCA hypotheses, evidence IDs, impact, checks, uncertainty
    |
    v
Python validator: JSON fields + real citations + confidence bounds
    |---- PASS : publish AI proposal requiring human review
    +---- FAIL : retry as configured, then deterministic fallback
```

**Important:** Both LLM stages are model calls. The *read-only check is a Python
function*, not a new LLM and not a network call to Solr. No external commands,
no automatic remediation, and no open-ended agent loops. Two stages generally
mean at least two API calls per selected incident, which may incur provider cost.

## 2. What can the LLM request?

Stage 1 returns exactly one code:

- `gc_query_timeline`: minute-by-minute GC pause counts/maximum and logged query p95/errors.
- `indexing_activity`: indexing-related messages and counts of observed event types.
- `zookeeper_timeline`: session loss, reconnection and leader-election messages.
- `error_breakdown`: observed HTTP/error types and logged query p95.
- `none`: skip further data collection, still make stage-2 LLM assessment.

The tool **only examines already parsed events** on the incident's nodes within
an adjustable time window. The UI lets the operator enable or disable tools.
The tool adds its own original evidence IDs, not imagined references.

### Example from the bundled Node A incident

1. Detector has already found GC pauses, heap pressure, slow queries and errors.
2. Stage-1 model may hypothesize GC-related search degradation and request
   `gc_query_timeline`.
3. Python scans about 500 nearby parsed events (default +/- 6 minutes) and
   summarizes them into UTC-minute buckets and a few original log excerpts.
4. Stage-2 model receives those summaries and proposes explanations and checks.
5. Validator verifies the cited evidence IDs. **This still does not prove
   GC caused the failed requests.**

The exact tool selection and model text will vary with provider/model/settings.

## 3. Parameters exposed in the Streamlit sidebar

| Control | Effect |
|---|---|
| Provider, base URL, model ID, API key | Select remote/local OpenAI-compatible Chat Completions API |
| Model context capacity | Planning bound only. Cannot expand server capacity |
| Approximate input budget | Prunes observation excerpts to fit model budget |
| Maximum initial log excerpts | Limits original lines initially selected |
| Maximum output tokens | Generation limit PER LLM call; reasoning counts on some models |
| Temperature | Sampling randomness (ignored for some reasoning models) |
| Top-p | Optional nucleus sampling override; provider/model dependent |
| Timeout | Limit per API request |
| Reasoning effort | Default/none/low/medium/high; choose supported value |
| JSON object mode | Requests JSON; not all providers support it |
| Permitted diagnostics | Whitelist of read-only Python tools model may select |
| Diagnostic rounds (0/1) | Caps tool execution at ONE round |
| Diagnostic time window | Minutes +/- incident anchor examined by tool |
| Extra diagnostic excerpts | Maximum original log excerpts added by tool |
| Retries per stage (0-2) | Bound total API requests and fallback behavior |

**Limits:** Request token counts are estimates. Providers tokenize differently.
Your actual provider may reject certain parameters with HTTP 400. Model changes
in the UI do not download or run the model on your CPU when using hosted APIs.

## 4. Hosted model choices (verify models/pricing in provider console)

### Recommended to start: Groq + GPT-OSS 120B

- Base URL: `https://api.groq.com/openai/v1`
- Model: `openai/gpt-oss-120b`
- Groq currently lists a 131,072-token context, JSON mode and `low/medium/high`
  reasoning effort. Published base token rates: $0.15 input and $0.60 output
  per million tokens. Model quotas and access vary by account.
- Why: efficient remote inference, no GPU required, strong fit for two short
  structured SRE investigations.
- Suggested initial settings: context 131072, input budget 6144, 12 excerpts,
  max output 2048 per model call, temp 0, reasoning low, JSON mode ON,
  timeout 90 sec, diagnostic window +/-6 min, extra excerpts 8,
  one retry per stage. Increase output budget if the model spends it on reasoning.

Create an API key at: https://console.groq.com/

### Alternative: Google Gemini

- Base URL: `https://generativelanguage.googleapis.com/v1beta/openai`
- Example model: `gemini-3.8-flash` (availability depends on account).
- Very large context and structured outputs. Provider-specific behavior
  and tier limits may affect JSON/reasoning settings.
- Some models have an accessible free tier; check current eligibility and
  data usage terms before submitting confidential logs.

Google AI Studio: https://aistudio.google.com/apikey

### Alternative: Hugging Face Inference Providers

- Base URL: `https://router.huggingface.co/v1`
- Model: provider-routed choice enabled in your HF account.
- Helpful if experimenting with several backends, but HF currently states
  monthly free-user credits of $0.10, subject to change; tokens may be billed
  against your account beyond credits.

Token settings and model availability are account/provider dependent.

### Local Ollama

- Base URL: `http://localhost:11434/v1`, model `llama3.2:3b`
- No remote model fees, keeps logs local, but slow on a CPU-only laptop and
  weaker at following strict two-step JSON contracts. Not recommended for the
  interview demonstration unless offline-only is required.

## 5. Evaluation and honesty

- Parser, hard rules, MAD/CUSUM, correlated incidents, and rule-based RCA work
  with **no model**.
- Stage 1 and 2 can fail because of connectivity, quotas, schema mistakes,
  invented citations, or unsupported provider parameters.
- If either stage cannot be validated within retries, the project returns
  `RULE_BASED_FALLBACK`. An accepted model response is only a **human-review
  proposal**—its causal interpretation is not scientifically certified.
- The ground truth in generated logs is held apart from the detector.
- No real SolrCloud service or genuine production labels were tested here.

## 6. Interview-ready explanation

> I deliberately separate detection from reasoning. Python first measures and
> correlates the Solr and GC symptoms. LangGraph makes a preliminary hypothesis,
> chooses one pre-approved read-only diagnostic that can distinguish explanations,
> and asks the model to reassess using those additional measurements. The final
> output must cite actual log evidence, passes bounded validation, and cannot
> change infrastructure. Both the number of model calls and diagnostic scope are
> capped, and a deterministic RCA is always available as fallback.
