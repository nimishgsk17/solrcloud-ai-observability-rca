"""Start here: python -m streamlit run app.py

Single dashboard for the complete UseReady case study.
The AI tab runs agent.py ONLY after the user clicks Investigate.
"""
from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

from analyzer import analyze
from agent import (RUNBOOKS, ANOMALY_GROUPS, ask_model, fallback, investigate,
                   test_connection, practice_model, budgeted_evidence, estimate_input_tokens,
                   DIAGNOSTIC_LABELS, estimate_stage_tokens)

ROOT = Path(__file__).resolve().parent


def read_logs(folder: Path) -> list[dict]:
    sources = []
    for file in sorted(folder.glob("*.log")):
        name, sep, kind = file.stem.rpartition("_")
        if not sep or kind not in ("solr", "gc"):
            continue
        sources.append({"node": name, "source": kind, "filename": file.name,
                        "text": file.read_text(encoding="utf-8", errors="replace")})
    return sources


def table(rows: list[dict]) -> None:
    if rows:
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info("No records for this view.")


st.set_page_config(page_title="SolrCloud RCA | UseReady", page_icon="🔎", layout="wide")
st.title("SolrCloud Observability & RCA")
st.caption("Parse logs → Detect anomalies → Correlate → LLM triage → targeted read-only check → final LLM RCA")
st.info("This demo uses simulated logs. Health is inferred from logs, NOT confirmed live SolrCloud state.", icon="ℹ️")

with st.sidebar:
    st.header("1. Choose your logs")
    source = st.radio("Source", ["Bundled demo", "Local folder", "Upload files"], index=0)
    directory = st.text_input("Folder of *.log files", value=str(ROOT / "demo_logs")) if source == "Local folder" else None
    uploads = st.file_uploader("Select *.log files", type=["log", "txt"], accept_multiple_files=True) if source == "Upload files" else None
    topology_text = st.text_area("Topology JSON (optional)", value="", height=105,
                                 help="Use known node_to_shards and zookeeper_dependency only.")
    st.divider()
    st.header("2. AI provider (optional)")
    st.caption("Hosted providers use THEIR computers, not your laptop. Never paste a key into source code.")
    providers = {
        "Groq — recommended (fast hosted GPT-OSS 120B)": (
            "https://api.groq.com/openai/v1", "openai/gpt-oss-120b", 131072),
        "Google Gemini — hosted / possible free tier": (
            "https://generativelanguage.googleapis.com/v1beta/openai", "gemini-3.8-flash", 1048576),
        "Hugging Face Router — hosted providers": (
            "https://router.huggingface.co/v1", "openai/gpt-oss-120b:fastest", 131072),
        "OpenAI — hosted API": (
            "https://api.openai.com/v1", "gpt-6-luna", 1048576),
        "Local Ollama — CPU / private": (
            "http://localhost:11434/v1", "llama3.2:3b", 4096),
        "Custom OpenAI-compatible provider": ("https://example.com/v1", "your-model-id", 131072),
    }
    provider = st.selectbox("Provider", list(providers), index=0)
    default_url, default_model, default_context = providers[provider]
    endpoint = st.text_input("OpenAI-compatible base URL", value=default_url,
        help="Switch providers above; change this if your account has a different endpoint.")
    model = st.text_input("Model ID", value=default_model,
        help="Use a model enabled in your provider account; IDs can change.")
    key = st.text_input("API key (not saved to files)", type="password", value="",
        help="Create the key in the chosen provider's official developer console.")
    if st.button("Check model connection (no logs sent)", use_container_width=True):
        try:
            if provider != "Local Ollama — CPU / private" and not key:
                st.error("Enter an API key for this hosted provider first.")
            else:
                models = test_connection(endpoint, key)
                st.success("API reachable; this does not test RCA JSON quality.")
                st.write("Available models (first 12):", models[:12] if models else "None returned")
        except Exception as exc:
            st.error(f"Connection check failed: {exc}")

    st.header("3. Model / evidence settings")
    st.caption("Defaults target short evidence-grounded RCA, not a full-log prompt.")
    with st.expander("Advanced parameters", expanded=True):
        context_tokens = st.number_input("Model context capacity (tokens)",
            min_value=2048, max_value=2097152, value=default_context, step=1024,
            help="Advertised model capacity / planning bound. This DOES NOT expand the server's context window.")
        input_budget = st.slider("Our approximate input budget (tokens)",
            min_value=1024, max_value=16384, value=6144, step=256,
            help="Prunes selected log observations to stay under this estimated prompt budget. Counts are approximate.")
        evidence_limit = st.slider("Maximum original log observations", 2, 30, 12,
            help="Important finding types selected first, then additional supporting events.")
        max_output = st.slider("Maximum output tokens PER model call", 256, 8192, 2048, step=128,
            help="Maximum generation budget; some reasoning models also consume hidden reasoning tokens.")
        temperature = st.slider("Temperature", 0.0, 1.0, 0.0, step=0.1,
            help="0 is most predictable. Some reasoning models ignore/reject explicit temperature.")
        timeout_seconds = st.slider("Request timeout (seconds, per attempt)", 15, 300, 90, step=15)
        set_top_p = st.checkbox("Override top_p (advanced; model-dependent)", value=False)
        top_p = st.slider("Top-p sampling", 0.1, 1.0, 1.0, step=0.05,
            help="Nucleus sampling; only passed if override is enabled.") if set_top_p else None
        effort_choices = ["Provider default", "none", "low", "medium", "high"]
        default_effort = "low" if provider.startswith("Groq") else (
            "none" if provider.startswith("OpenAI") or provider.startswith("Google") else "Provider default"
        )
        effort_choice = st.selectbox("Reasoning effort (model-dependent)", effort_choices,
            index=effort_choices.index(default_effort),
            help="Groq GPT-OSS accepts low/medium/high. OpenAI GPT-6 Luna accepts none/low/etc. Other models may reject this parameter; choose Provider default in that case.")
        reasoning_effort = "default" if effort_choice == "Provider default" else effort_choice
        json_mode = st.checkbox("Request JSON-object mode", value=provider.startswith("Groq"),
            help="Helps obtain valid JSON where supported. Turn off if the provider returns HTTP 400.")
        st.caption("Model context capacity is a planning limit, not a setting that expands the provider's model.")
    st.header("4. Two-stage investigation controls")
    st.caption("Stage 1: hypothesis and select one tool. Stage 2: Python executes the tool, then model reassesses.")
    available_checks = st.multiselect("Permitted read-only diagnostics",
        options=list(DIAGNOSTIC_LABELS), default=list(DIAGNOSTIC_LABELS),
        format_func=lambda code: DIAGNOSTIC_LABELS[code],
        help="Model can choose only one of these; no shell commands or external queries are allowed.")
    max_rounds = st.slider("Maximum targeted diagnostic rounds", 0, 1, 1,
        help="0 skips extra diagnostics; 1 permits one read-only tool call. Both stages still run.")
    diagnostic_minutes = st.slider("Diagnostic time window on each side (minutes)", 1, 30, 6)
    diagnostic_examples = st.slider("Maximum extra diagnostic log excerpts", 0, 20, 8)
    retries_per_stage = st.slider("Validation retries per LLM stage", 0, 2, 1,
        help="Each stage makes one initial call plus up to this many retries. Two stages cost at least two calls.")
    st.caption("These affect only optional AI investigation—not anomaly detector thresholds or incident correlation.")

if source == "Bundled demo":
    sources = read_logs(ROOT / "demo_logs")
    manifest = ROOT / "demo_logs" / "TOPOLOGY.json"
    default_topology = json.loads(manifest.read_text()) if manifest.exists() else {}
elif source == "Local folder":
    sources = read_logs(Path(directory))
    default_topology = {}
else:
    sources = []
    for uploaded in uploads or []:
        prefix, sep, kind = uploaded.name.rpartition("_")
        kind = kind.rsplit(".", 1)[0]
        if sep and kind in ("gc", "solr"):
            sources.append({"node": prefix, "source": kind, "filename": uploaded.name,
                            "text": uploaded.getvalue().decode("utf-8", errors="replace")})
        else:
            st.warning(f"Skipping {uploaded.name}. Expected filename: node-a_gc.log or node-a_solr.log")
    default_topology = {}

try:
    topology = json.loads(topology_text) if topology_text.strip() else default_topology
    if not isinstance(topology, dict):
        raise ValueError("Topology must be a JSON object")
except ValueError as exc:
    st.error(f"Invalid topology JSON: {exc}")
    st.stop()

if not sources:
    st.warning("No logs selected. Choose Bundled demo or upload files with names like node-a_solr.log.")
    st.stop()

expected = sorted({s["node"] for s in sources} | set(topology.get("node_to_shards", {})))
with st.spinner("Reading and analyzing log events..."):
    report = analyze(sources, expected_nodes=expected, topology=topology)

st.caption("Analyzed: " + ", ".join(s["filename"] for s in sources))
a, b, c, d = st.columns(4)
a.metric("Cluster (log-derived)", report["cluster_health"])
b.metric("Incidents", len(report["incidents"]))
c.metric("Parsed events", f"{len(report['events']):,}")
d.metric("Unparsed lines", report["data_quality"]["unparsed_lines"])

summary_tab, incident_tab, stat_tab, ai_tab = st.tabs(
    ["Overview", "Incidents & evidence", "Adaptive detection", "LangGraph AI investigation"])

with summary_tab:
    st.subheader("Node health")
    table([{"Node": node, "Log-derived condition": condition} for node, condition in report["node_health"].items()])
    st.subheader("Incident summary")
    table([{"Incident": inc["id"], "Nodes": ", ".join(inc["nodes"]),
            "Severity": inc["severity"], "Symptoms": ", ".join(inc["anomalies"])}
           for inc in report["incidents"]])
    st.caption("No anomaly observed ≠ proof that the live server is healthy.")

with incident_tab:
    if not report["incidents"]:
        st.success("No incidents found by configured detectors in these log files.")
    for incident in report["incidents"]:
        with st.container(border=True):
            st.markdown(f"**{incident['severity'].upper()} · {', '.join(incident['nodes'])} · {incident['window_start']}**")
            st.write("**Observed anomalies:**", ", ".join(incident["anomalies"]))
            st.write("**Rule-based RCA hypothesis:**", incident["root_cause_hypothesis"])
            st.write("**Possible operational impact:**", incident["operational_impact"])
            st.write("**Read-only next checks:**", incident["recommended_remediation"])
            st.write("**Alternative hypotheses:**", "; ".join(incident.get("alternatives", [])))
            st.caption("Log proximity can support a hypothesis, not prove a root cause.")
            linked = set(incident["evidence_ids"])
            evidence = [event for event in report["events"] if event["id"] in linked]
            with st.expander(f"Original supporting logs ({len(evidence)} lines)"):
                for e in evidence[:70]:
                    st.code(f"{e['id']}  {e['node']}  {e['filename']}:{e['line']}\n{e['message']}", language="text")

with stat_tab:
    st.subheader("Adaptive latency findings")
    st.caption("Rolling median / MAD identifies large deviations; CUSUM requires a sustained shift.")
    table(report.get("adaptive_diagnostics", []))
    st.subheader("All detection findings")
    table([{"Node": f["node"], "Type": f["type"], "Severity": f["severity"],
            "Detector": f.get("detector", "rule"), "Summary": f["summary"]}
           for f in report["findings"]])
    with st.expander("Thresholds and known limitations"):
        st.json(report["thresholds"])
        st.write("The detector is calibrated on synthetic examples, not production workloads.")

with ai_tab:
    st.subheader("AI-assisted root cause analysis")
    st.markdown("**Two model stages with one bounded read-only Python diagnostic.**")
    st.code("START → evidence → LLM triage / tool choice → Python read-only check\n"
            "      → LLM final RCA + evidence validation → publish / retry / fallback",
            language="text")
    if not report["incidents"]:
        st.info("No incident to investigate. Choose the bundled mixed-failure demo.")
    else:
        chosen = st.selectbox("Choose an incident", range(len(report["incidents"])),
            format_func=lambda ix: f"{report['incidents'][ix]['id']} — {', '.join(report['incidents'][ix]['nodes'])} — {', '.join(report['incidents'][ix]['anomalies'])}")
        incident = report["incidents"][chosen]
        anomaly_groups = {ANOMALY_GROUPS.get(t, "general") for t in incident["anomalies"]}
        with st.expander("Curated troubleshooting knowledge (no vector database required)"):
            for group in sorted(anomaly_groups):
                st.write(f"**{group.capitalize()}**")
                for advice in RUNBOOKS[group]:
                    st.write("• " + advice)
        st.warning("If you choose a hosted provider, selected incident excerpts and metadata are sent to that provider. Use only simulated/public logs or logs you are authorized to share.")
        with st.expander("Preview EXACT evidence dossier before sharing", expanded=True):
            try:
                preview = budgeted_evidence(
                    incident, report["events"], topology,
                    evidence_limit=evidence_limit, input_budget_tokens=input_budget,
                    context_window_tokens=context_tokens, max_output_tokens=max_output,
                )
                preview["stage"] = "triage"
                preview["allowed_checks"] = list(available_checks) if max_rounds else []
                st.write(f"**{len(preview['observations'])} initial log excerpts** selected; "
                         f"~**{estimate_stage_tokens(preview, 'triage'):,}** estimated input tokens "
                         f"(limit {min(input_budget, context_tokens - max_output - 256):,}).")
                st.caption("This is the actual planned Stage 1 dossier. Stage 2 depends on the model's selected check; both use the input budget. Token estimates are approximate.")
                st.json(preview)
                usable = min(input_budget, context_tokens - max_output - 256)
                if estimate_stage_tokens(preview, 'triage') > usable:
                    raise ValueError("Stage 1 prompt exceeds the chosen input budget, even after selecting original evidence. Increase the budget.")
                budget_ok = True
            except ValueError as exc:
                st.error(str(exc))
                budget_ok = False
        if provider != "Local Ollama — CPU / private" and not endpoint.startswith("https://"):
            st.error("Hosted endpoints should use HTTPS to protect the API key and log excerpts.")
            budget_ok = False
        left, right = st.columns(2)
        if left.button("Practice LangGraph (fake model, no API)"):
            try:
                out = investigate(
                    incident, report["events"], model_callable=practice_model,
                    topology=topology, evidence_limit=evidence_limit,
                    input_budget_tokens=input_budget, context_window_tokens=context_tokens,
                    max_output_tokens=max_output, allowed_checks=available_checks,
                    diagnostic_window_minutes=diagnostic_minutes,
                    diagnostic_examples=diagnostic_examples, max_diagnostic_rounds=max_rounds,
                    retries_per_stage=retries_per_stage,
                )
                out["report"]["status"] = "MOCK_DEMO_NOT_A_REAL_AI_INVESTIGATION"
                st.session_state["last_ai"] = (incident["id"], out)
            except ModuleNotFoundError:
                st.error("LangGraph missing. Use .\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt")
            except Exception as exc:
                st.error(f"Practice workflow failed: {exc}")
        if right.button("Investigate with REAL hosted/local AI", type="primary", disabled=not budget_ok):
            if provider != "Local Ollama — CPU / private" and not key:
                st.error("Enter an API key from your provider before sending any evidence.")
            else:
                try:
                    with st.spinner("Two-stage AI investigation: initial hypothesis, diagnostic, final RCA (with bounded retries)..."):
                        out = investigate(
                            incident, report["events"],
                            model_callable=lambda dossier, correction: ask_model(
                                dossier, correction, base_url=endpoint, model=model,
                                api_key=key, timeout=timeout_seconds,
                                max_output_tokens=max_output, temperature=temperature,
                                json_mode=json_mode, reasoning_effort=reasoning_effort,
                                top_p=top_p, stage=dossier.get("stage", "final"),
                            ),
                            topology=topology, evidence_limit=evidence_limit,
                            input_budget_tokens=input_budget,
                            context_window_tokens=context_tokens, max_output_tokens=max_output,
                            allowed_checks=available_checks,
                            diagnostic_window_minutes=diagnostic_minutes,
                            diagnostic_examples=diagnostic_examples, max_diagnostic_rounds=max_rounds,
                            retries_per_stage=retries_per_stage,
                        )
                    st.session_state["last_ai"] = (incident["id"], out)
                except ModuleNotFoundError:
                    st.error("LangGraph not installed. Re-run the project venv installation steps.")
                except Exception as exc:
                    st.error(f"AI investigation failed: {exc}")
        saved = st.session_state.get("last_ai")
        if saved and saved[0] == incident["id"]:
            st.write("**LangGraph steps actually executed**")
            for step in saved[1]["graph_steps"]:
                st.write("• " + step)
            result_status = saved[1]["report"].get("status", "")
            if result_status == "AI_PROPOSAL_REQUIRES_HUMAN_REVIEW":
                st.success("Real model response accepted after evidence and format checks. This is still a hypothesis, not a proven root cause.")
            elif result_status == "RULE_BASED_FALLBACK":
                st.warning("The AI investigation did not pass validation or the API failed. Showing the deterministic rule-based RCA instead.")
            else:
                st.info("Practice mode: no real model inference was used.")
            stage_one = saved[1]["report"].get("stage_one", {})
            if stage_one and isinstance(stage_one, dict) and stage_one.get("requested_check"):
                st.markdown("**Stage 1: what the LLM asked to investigate**")
                st.write("**Preliminary hypothesis:**", stage_one.get("preliminary_hypothesis", ""))
                st.write("**Selected diagnostic:**", DIAGNOSTIC_LABELS.get(stage_one["requested_check"], "No extra check"))
                st.caption(stage_one.get("why_this_check", ""))
            if saved[1].get("diagnostic"):
                with st.expander("Stage 2: read-only Python diagnostic actually executed", expanded=True):
                    st.json(saved[1]["diagnostic"])
            st.write("**Investigation result (mock or AI; labeled in status)**")
            st.json(saved[1]["report"])
        if saved and saved[0] == incident["id"]:
            st.caption("If returned by the provider, API usage counters are included in the result. Real costs and model limits depend on your provider/account.")
        st.markdown("**Rule-based explanation (works without a model)**")
        st.json(fallback(incident, "No live model required for this diagnostic summary."))

st.divider()
st.download_button("Download full JSON report", json.dumps(report, indent=2),
                   file_name="solr_rca_report.json", mime="application/json")
st.caption("All data is simulated unless authentic logs are separately supplied. No automatic remediation.")
