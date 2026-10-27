"""Poll appended *.log data and export updated RCA JSON (stdlib-only).

Filenames: <node>_solr.log or <node>_gc.log. Example:
    python watch.py --dir sample_logs --interval 10 --output latest_report.json

This is an in-memory tailer for the demo, not a durable production ingestion system.
"""
import argparse
import json
import os
import time
from pathlib import Path

from analyzer import analyze
from storage import persist


def watch(folder: Path, output: Path, interval: float = 10, once: bool = False, sqlite=None):
    offsets, buffers = {}, {}
    try:
        while True:
            # Preserve current file content for a bounded prototype. Rotation is recognized using inode + truncation.
            paths = sorted(folder.glob("*.log"))
            for path in paths:
                st = path.stat()
                key = str(path.resolve())
                offset, old_inode = offsets.get(key, (0, st.st_ino))
                if st.st_ino != old_inode or st.st_size < offset:
                    offset, buffers[key] = 0, ""
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    f.seek(offset)
                    chunk = f.read()
                    offsets[key] = (f.tell(), st.st_ino)
                if chunk:
                    buffers[key] = (buffers.get(key, "") + chunk)[-2_000_000:]
            sources = []
            for name, data in buffers.items():
                path = Path(name)
                source = "gc" if path.stem.lower().endswith("_gc") else "solr"
                node = path.stem.rsplit("_", 1)[0] if "_" in path.stem else "unknown-node"
                sources.append({"filename": path.name, "node": node, "source": source, "text": data})
            topo_file = folder / "TOPOLOGY.json"
            topology = json.loads(topo_file.read_text()) if topo_file.exists() else {}
            report = analyze(sources, topology=topology)
            tmp = output.with_suffix(output.suffix + ".tmp")
            tmp.write_text(json.dumps(report, indent=2), encoding="utf-8")
            os.replace(tmp, output)
            if sqlite: persist(report,sqlite)
            print(f"{time.strftime('%H:%M:%S')} files={len(paths)} events={len(report['events'])} incidents={len(report['incidents'])} cluster={report['cluster_health']}", flush=True)
            if once:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Stopped")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", type=Path, default=Path("sample_logs"))
    ap.add_argument("--output", type=Path, default=Path("latest_report.json"))
    ap.add_argument("--interval", type=float, default=10)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--sqlite",type=Path,default=None)
    args = ap.parse_args()
    if args.interval < 1:
        ap.error("--interval must be >= 1")
    if not args.dir.is_dir():
        ap.error("--dir does not exist")
    watch(args.dir, args.output, args.interval, args.once, args.sqlite)
