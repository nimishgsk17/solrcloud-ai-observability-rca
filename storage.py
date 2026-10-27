"""Durable SQLite store for incident summaries (source logs remain on disk)."""
import json, sqlite3
from pathlib import Path

def persist(report, path):
    conn=sqlite3.connect(str(path))
    try:
        conn.execute('''CREATE TABLE IF NOT EXISTS incidents (
             id TEXT PRIMARY KEY, window_start TEXT, severity TEXT,
             nodes_json TEXT, anomalies_json TEXT, summary TEXT, report_json TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS analyses (
             id INTEGER PRIMARY KEY AUTOINCREMENT, observed_utc TEXT DEFAULT CURRENT_TIMESTAMP,
             cluster_health TEXT, event_count INTEGER, incident_count INTEGER, quality_json TEXT)''')
        for inc in report['incidents']:
            conn.execute('''INSERT INTO incidents(id,window_start,severity,nodes_json,anomalies_json,summary,report_json)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET severity=excluded.severity,
                report_json=excluded.report_json, summary=excluded.summary''',
                (inc['id'],inc['window_start'],inc['severity'],json.dumps(inc['nodes']),json.dumps(inc['anomalies']),
                 inc['root_cause_hypothesis'],json.dumps(inc)))
        conn.execute('INSERT INTO analyses(cluster_health,event_count,incident_count,quality_json) VALUES(?,?,?,?)',
                     (report['cluster_health'],len(report['events']),len(report['incidents']),json.dumps(report['data_quality'])))
        conn.commit()
    finally: conn.close()
