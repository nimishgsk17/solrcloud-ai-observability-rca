# Solr RCA — V4 architecture

```text
Bundled synthetic / uploaded Solr + GC logs
  -> parser.py: supported INFO/WARN/ERROR patterns -> normalized events + IDs
  -> analyzer.py: hard rules + rolling MAD/CUSUM -> findings
  -> analyzer.py: time/node/family/ZooKeeper DSU correlation -> incidents
  -> initial deterministic RCA (always available)
  -> (optional user click) agent.py + LangGraph:
        prepare incident dossier
        -> LLM triage / select one allowlisted check
        -> Python read-only tool examines already parsed events
        -> LLM final RCA with added diagnostics
        -> Python evidence validation
        -> publish human-review proposal or deterministic fallback
  -> app.py: Streamlit investigation tabs and export
```

Read `TWO_STAGE_EXPLAINED.md` for examples, model choices and each UI control.
