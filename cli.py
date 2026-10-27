"""Dependency-free analysis of logs in a folder into JSON.

Usage: python cli.py --dir sample_logs --output report.json
"""
import argparse
import json
from pathlib import Path
from analyzer import analyze
from storage import persist


def main():
    ap = argparse.ArgumentParser(description="SolrCloud incident analyzer")
    ap.add_argument("--dir", type=Path, required=True, help="Folder containing <node>_solr.log and <node>_gc.log")
    ap.add_argument("--output", type=Path, default=Path("report.json"))
    ap.add_argument("--nodes", default="", help="Comma-separated list of expected nodes; missing logs -> UNKNOWN")
    ap.add_argument("--sqlite",type=Path,default=None,help="Optional SQLite incident database")
    args = ap.parse_args()
    if not args.dir.is_dir():
        ap.error(f"Not a directory: {args.dir}")
    sources = []
    for p in sorted(args.dir.glob("*.log")):
        parts = p.stem.rsplit("_", 1)
        if len(parts) != 2 or parts[1] not in ("solr", "gc"):
            print(f"Skipping {p.name}: filename must be <node>_solr.log or <node>_gc.log")
            continue
        sources.append({"node": parts[0], "source": parts[1], "filename": p.name,
                        "text": p.read_text(encoding="utf8", errors="replace")})
    topo_file = args.dir / "TOPOLOGY.json"
    topology = json.loads(topo_file.read_text()) if topo_file.exists() else {}
    result = analyze(sources, [n.strip() for n in args.nodes.split(",") if n.strip()], topology=topology)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf8")
    if args.sqlite:
        persist(result,args.sqlite)
        print(f"Incident metadata stored in: {args.sqlite}")
    print(f"Cluster: {result['cluster_health']} | Events: {len(result['events'])} | "
          f"Findings: {len(result['findings'])} | Incidents: {len(result['incidents'])}")
    for item in result["incidents"]:
        print(f"  [{item['severity']}] {','.join(item['nodes'])} -> {','.join(item['anomalies'])}: {item['root_cause_hypothesis']}")
    print(f"Full evidence JSON: {args.output}")


if __name__ == "__main__":
    main()
