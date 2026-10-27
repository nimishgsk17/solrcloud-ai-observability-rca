"""Deterministic Solr/GC log parsing, detection and evidence-backed incident analysis.

No network or third-party dependency is needed for this module.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

TIME = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?")
QTIME = re.compile(r"\b(?:QTime|qtime|elapsed(?:Time)?)\s*[=:]\s*(\d+(?:\.\d+)?)\s*(?:ms)?\b", re.I)
MEM = re.compile(r"(\d+(?:\.\d+)?)([KMG])->(\d+(?:\.\d+)?)([KMG])\((\d+(?:\.\d+)?)([KMG])\)", re.I)
GC_MS = re.compile(r"(\d+(?:\.\d+)?)\s*(ms|msec|secs?|seconds?)\b", re.I)
LEVEL = re.compile(r"\b(INFO|WARN|WARNING|ERROR|DEBUG|TRACE|FATAL)\b")
BAD_REQUEST = re.compile(r"(?:\bHTTP(?:/\d(?:\.\d)?)?\s+(?:status\s*[=:]\s*)?5\d\d\b|\b(?:status|http_status|httpStatus|responseCode)\s*[=:]\s*5\d\d\b)", re.I)
ZK = re.compile(r"(?:zookeeper|\bzk\b).{0,130}(?:session expired|connection loss|connection lost|disconnected|connection refused|timed out)|(?:session expired|connectionloss)\b", re.I)
ELECTION = re.compile(r"(?:leader election|electing leader|becoming leader|leader changed|leader lost)", re.I)
ENTITY = re.compile(r"\b(collection|shard|replica|trace_id|core)\s*=\s*([^\s\]&,}]+)", re.I)
OOM = re.compile(r"OutOfMemoryError|Java heap space|GC overhead limit exceeded", re.I)
ERR = re.compile(r"\bERROR\b|\bFATAL\b|\bException\b|\b(?:request|read) timed out\b|\btimeout\b", re.I)


def parse_timestamp(line: str) -> Optional[datetime]:
    m = TIME.search(line)
    if not m:
        return None
    value = m.group(0).replace(",", ".").replace(" ", "T")
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    if re.search(r"[+-]\d{4}$", value):
        value = value[:-5] + value[-5:-2] + ":" + value[-2:]
    # Python accepts fractional seconds up to six digits.
    value = re.sub(r"(\.\d{6})\d+", r"\1", value)
    try:
        result = datetime.fromisoformat(value)
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)
    except ValueError:
        return None


def mb(value: str, unit: str) -> float:
    return round(float(value) * {"K": 1 / 1024, "M": 1, "G": 1024}[unit.upper()], 2)


def parse_line(line: str, source: str, node: str, filename: str, lineno: int) -> Optional[Dict[str, Any]]:
    ts = parse_timestamp(line)
    if ts is None or not line.strip():
        return None
    line = line.rstrip("\r\n")
    kind = "normal"
    measures: Dict[str, float] = {}
    if source == "gc":
        # Covers representative JDK 9+ unified GC records with wall clock decorators.
        if not re.search(r"\b(?:GC\(\d+\)|\[Full GC|\[GC\b|Pause (?:Young|Full))", line, re.I):
            return None
        if re.search(r"(?:Pause Full|Full GC)", line, re.I):
            kind = "full_gc"
        else:
            kind = "gc"
        vals = GC_MS.findall(line)
        if vals:
            val, unit = vals[-1]
            elapsed = round(float(val) * (1000 if unit.lower() in ("s", "sec", "secs", "second", "seconds") else 1), 2)
            # JDK concurrent marking can last seconds without blocking requests;
            # do not classify it as a stop-the-world GC pause.
            low = line.lower()
            if "gc,phases" in low or "gc,heap" in low or "gc,start" in low:
                measures["gc_detail_ms"] = elapsed  # A subphase is NOT a total STW pause.
            elif "concurrent" in low and "pause" not in low:
                measures["concurrent_ms"] = elapsed
            elif "pause" in low or "full gc" in low or "[gc " in low:
                measures["pause_ms"] = elapsed
        mm = MEM.search(line)
        if mm:
            measures["before_mb"] = mb(mm.group(1), mm.group(2))
            measures["after_mb"] = mb(mm.group(3), mm.group(4))
            measures["heap_mb"] = mb(mm.group(5), mm.group(6))
            if measures["heap_mb"]:
                measures["heap_after_pct"] = round(100 * measures["after_mb"] / measures["heap_mb"], 1)
    else:
        if OOM.search(line):
            kind = "oom"
        elif ZK.search(line):
            kind = "zk_disconnect"
        elif ELECTION.search(line):
            kind = "leader_change"
        elif BAD_REQUEST.search(line):
            kind = "http_5xx"
        elif ERR.search(line):
            kind = "error"
        mq = QTIME.search(line)
        if mq:
            measures["qtime_ms"] = float(mq.group(1))
            if kind == "normal":
                kind = "request"
    attrs = {key.lower(): val for key, val in ENTITY.findall(line)} if source != "gc" else {}
    fingerprint = hashlib.sha256(f"{node}|{source}|{ts.isoformat()}|{line}".encode("utf8")).hexdigest()[:14]
    level_m = LEVEL.search(line)
    return {
        "id": fingerprint, "ts": ts.isoformat(), "node": node, "source": source,
        "filename": filename, "line": lineno, "kind": kind,
        "level": level_m.group(1) if level_m else "INFO", "message": line[:1300], "measures": measures,
        "attrs": attrs,
    }


def parse_sources(sources: Iterable[Dict[str, str]]) -> tuple[List[Dict[str, Any]], Dict[str, int]]:
    events, counts, seen = [], {"total_lines": 0, "parsed_lines": 0, "unparsed_lines": 0, "duplicates": 0, "continuation_lines": 0}, set()
    for item in sources:
        source, node, filename = item["source"], item["node"], item.get("filename", "input.log")
        if source not in ("solr", "gc"):
            raise ValueError("source must be 'solr' or 'gc'")
        for lineno, line in enumerate(item["text"].splitlines(), 1):
            if not line.strip():
                continue
            counts["total_lines"] += 1
            event = parse_line(line, source, node, filename, lineno)
            if event is None:
                # JVM/Solr exception stack traces have timestamp-less continuation lines.
                # Preserve them with the immediately preceding log event, rather than
                # pretending they are distinct timestamped incidents.
                if (events and (line.startswith(("\t", "  at ", "    at ", "Caused by:", "\t...")))):
                    events[-1]["message"] = (events[-1]["message"] + "\n" + line)[:1300]
                    events[-1]["continuation_lines"] = events[-1].get("continuation_lines", 0) + 1
                    counts["continuation_lines"] += 1
                else:
                    counts["unparsed_lines"] += 1
            elif event["id"] in seen:
                counts["duplicates"] += 1
            else:
                seen.add(event["id"])
                events.append(event)
                counts["parsed_lines"] += 1
    return sorted(events, key=lambda e: (e["ts"], e["node"])), counts


def bucket(ts: str, seconds: int = 300) -> int:
    return int(datetime.fromisoformat(ts).timestamp()) // seconds


def finding(node: str, b: int, typ: str, severity: str, summary: str,
            events: List[Dict[str, Any]], metric: Optional[str] = None) -> Dict[str, Any]:
    return {"node": node, "window": b, "type": typ, "severity": severity, "summary": summary,
            "metric": metric, "evidence_ids": [e["id"] for e in events[:12]],
            "first_seen": min(e["ts"] for e in events), "last_seen": max(e["ts"] for e in events)}


def detect(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups = defaultdict(list)
    for e in events:
        groups[(e["node"], bucket(e["ts"]))].append(e)
    result = []
    for (node, b), group in sorted(groups.items()):
        gc = [e for e in group if e["source"] == "gc"]
        pauses = [e for e in gc if e["measures"].get("pause_ms", 0) >= 500]
        if pauses:
            top = max(pauses, key=lambda e: e["measures"]["pause_ms"])
            v = top["measures"]["pause_ms"]
            result.append(finding(node, b, "gc_pause", "critical" if v >= 2000 else "warning",
                                  f"Long GC pause observed ({v:,.0f} ms; threshold 500 ms)", pauses,
                                  f"max_pause_ms={v}"))
        full = [e for e in gc if e["kind"] == "full_gc"]
        if len(full) >= 2:
            result.append(finding(node, b, "frequent_full_gc", "warning",
                                  f"{len(full)} full GC events within five minutes", full, f"count={len(full)}"))
        heap = [e for e in gc if e["measures"].get("heap_after_pct", 0) >= 85]
        if heap:
            top = max(heap, key=lambda e: e["measures"]["heap_after_pct"])
            pct = top["measures"]["heap_after_pct"]
            result.append(finding(node, b, "heap_pressure", "warning",
                                  f"Post-GC heap occupancy reached {pct}% (threshold 85%)", heap, f"max_heap_after_pct={pct}"))
        oom = [e for e in group if e["kind"] == "oom"]
        if oom:
            result.append(finding(node, b, "oom", "critical", "JVM out-of-memory indicator found", oom))
        zk = [e for e in group if e["kind"] == "zk_disconnect"]
        if zk:
            result.append(finding(node, b, "zk_disconnect", "critical", "ZooKeeper connection/session disruption", zk))
        leader = [e for e in group if e["kind"] == "leader_change"]
        if len(leader) >= 2:
            result.append(finding(node, b, "leader_churn", "warning",
                                  f"{len(leader)} leader-change messages within five minutes", leader, f"count={len(leader)}"))
        errors = [e for e in group if e["kind"] in ("http_5xx", "error")]
        if len(errors) >= 2:
            result.append(finding(node, b, "error_burst", "critical" if len(errors) >= 4 else "warning",
                                  f"{len(errors)} error/5xx events within five minutes", errors, f"count={len(errors)}"))
        slow = [e for e in group if e["measures"].get("qtime_ms", 0) >= 1000]
        if len(slow) >= 2:
            top = max(e["measures"]["qtime_ms"] for e in slow)
            result.append(finding(node, b, "slow_queries", "warning",
                                  f"{len(slow)} queries took >=1,000 ms; max {top:,.0f} ms", slow,
                                  f"count={len(slow)},max_qtime_ms={top}"))
    return result


SEVERITY = {"warning": 1, "critical": 2}


def _diagnose(group: List[Dict[str, Any]], crossnode: bool = False) -> Dict[str, str]:
    types = {f["type"] for f in group}
    if "oom" in types:
        return {"cause": "JVM memory exhaustion is explicitly indicated in the Solr logs.",
                "confidence": "high", "impact": "Possible query failures, node restarts, and replica unavailability; actual customer impact not measured.",
                "remediation": "Inspect heap dump/JVM memory use; check Solr caches, indexing bursts and heap sizing. Restart only per incident procedure."}
    if "zk_disconnect" in types:
        return {"cause": "ZooKeeper session/connection disruption is observed" + (" on multiple nodes." if crossnode else "; coordination instability is a likely contributor."),
                "confidence": "high" if "leader_churn" in types else "medium",
                "impact": "Possible leader elections, replica unavailability and search/indexing errors; verify with live cluster APIs.",
                "remediation": "Check ZooKeeper quorum, network connectivity, session timeouts and Solr live_nodes/shard leaders before intervening."}
    if "gc_pause" in types and ("slow_queries" in types or "error_burst" in types):
        return {"cause": "Long JVM GC pauses coincide with Solr query latency/errors in the same five-minute window; GC contribution is plausible, not proven.",
                "confidence": "medium", "impact": "Elevated response latency and possible timeouts; request volumes and affected users are unknown.",
                "remediation": "Compare exact request and GC timings; review post-GC heap occupancy, allocation rate, JVM settings and Solr cache pressure."}
    if "heap_pressure" in types or "gc_pause" in types or "frequent_full_gc" in types:
        return {"cause": "GC/heap pressure is observed; its underlying trigger is not established from these logs.",
                "confidence": "medium", "impact": "Potential latency spikes or throughput degradation; validate with service metrics.",
                "remediation": "Inspect GC cadence, allocation rate, heap utilization, cache settings and system memory; compare to healthy baseline."}
    if "slow_queries" in types:
        return {"cause": "Repeated slow Solr queries observed; root cause cannot be determined from latency alone.",
                "confidence": "low", "impact": "Search responses may exceed latency objectives; SLA/SLO data not provided.",
                "remediation": "Inspect slow request parameters, shard/core, filters, warmup, cache hit ratio and query plan."}
    if "leader_churn" in types:
        return {"cause": "Repeated leader changes detected; network, ZooKeeper and replica lifecycle need validation.",
                "confidence": "low", "impact": "Possible periods of reduced indexing/search availability; verify live replica state.",
                "remediation": "Check cluster state, overseer logs, live nodes, ZooKeeper quorum and recent deployments."}
    return {"cause": "Burst of Solr errors observed; exact underlying failure is unknown.",
            "confidence": "low", "impact": "Potential failed requests; impact magnitude is unverified.",
            "remediation": "Inspect exception stack traces, request IDs, relevant core/shard, upstream dependencies and HTTP error distribution."}


def incidents_from(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Group within node/time window; merge cross-node incidents only on corroborated ZooKeeper disruptions.
    windows = defaultdict(list)
    for f in findings:
        windows[f["window"]].append(f)
    incidents = []
    for win, fs in sorted(windows.items()):
        by_node = defaultdict(list)
        for f in fs:
            by_node[f["node"]].append(f)
        zk_nodes = sorted(node for node, ff in by_node.items() if "zk_disconnect" in {f["type"] for f in ff})
        groups = []
        if len(zk_nodes) >= 2:
            groups.append(([f for node in zk_nodes for f in by_node.pop(node)], True))
        groups.extend((ff, False) for ff in by_node.values())
        for group, multi in groups:
            diag = _diagnose(group, crossnode=multi)
            nodes = sorted({f["node"] for f in group})
            evid = sorted(set(i for f in group for i in f["evidence_ids"]))
            types = sorted({f["type"] for f in group})
            incident_id = hashlib.sha256(f"{win}|{','.join(nodes)}|{','.join(types)}".encode()).hexdigest()[:10]
            incident = {"id": incident_id, "nodes": nodes, "scope": "multi-node" if multi else "node",
                        "window_start": datetime.fromtimestamp(win * 300, tz=timezone.utc).isoformat(),
                        "severity": "critical" if any(f["severity"] == "critical" for f in group) else "warning",
                        "anomalies": types, "findings": group, "evidence_ids": evid,
                        "root_cause_hypothesis": diag["cause"], "confidence": diag["confidence"],
                        "operational_impact": diag["impact"], "recommended_remediation": diag["remediation"]}
            incidents.append(incident)
    incidents.sort(key=lambda i: (i["severity"] != "critical", i["window_start"], i["id"]))
    return incidents


def analyze(sources: List[Dict[str, str]], expected_nodes: Optional[List[str]] = None) -> Dict[str, Any]:
    events, quality = parse_sources(sources)
    findings = detect(events)
    incidents = incidents_from(findings)
    known = set(expected_nodes or []) | {s["node"] for s in sources if s.get("node")}
    observed = {e["node"] for e in events}
    health = {}
    for n in sorted(known):
        its = [i for i in incidents if n in i["nodes"]]
        health[n] = "UNKNOWN" if n not in observed else ("CRITICAL" if any(i["severity"] == "critical" for i in its)
                     else "DEGRADED" if its else "NO_ANOMALY_OBSERVED")
    if not observed:
        cluster = "UNKNOWN"
    elif any(i["scope"] == "multi-node" and i["severity"] == "critical" for i in incidents):
        cluster = "CRITICAL"
    elif any(i["severity"] == "critical" for i in incidents):
        cluster = "DEGRADED"
    elif incidents:
        cluster = "DEGRADED"
    elif any(v == "UNKNOWN" for v in health.values()):
        cluster = "UNKNOWN"
    else:
        cluster = "NO_ANOMALY_OBSERVED"
    quality["parsed_events"] = len(events)
    quality["unparsed_ratio"] = round(quality["unparsed_lines"] / quality["total_lines"], 3) if quality["total_lines"] else 0
    return {"cluster_health": cluster, "node_health": health, "data_quality": quality, "events": events,
            "findings": findings, "incidents": incidents,
            "assessment_scope": "Log-derived and time-windowed, not a live SolrCloud health check. UTC assumed for timestamps without offsets.",
            "thresholds": {"window_minutes": 5, "slow_query_ms": 1000, "slow_query_count": 2,
                           "gc_pause_ms": 500, "critical_gc_pause_ms": 2000, "post_gc_heap_pct": 85,
                           "error_count": 2, "leader_change_count": 2}}
