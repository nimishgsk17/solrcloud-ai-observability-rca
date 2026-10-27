"""Upgraded evidence-first detection and topology-aware correlation.

Rules and robust statistics are independent sensors; no unsupervised model is
trained on fabricated anomalies. All scores are heuristics, not probabilities.
"""
from __future__ import annotations
import hashlib, statistics, math
from collections import defaultdict
from datetime import datetime,timezone
from typing import Any
from parser import parse_sources, detect as baseline_detect, finding as old_finding

BAD = {'oom','gc_pause','frequent_full_gc','heap_pressure','zk_disconnect','leader_churn','error_burst','slow_queries'}
FAMILIES={'gc_pause':'memory','frequent_full_gc':'memory','heap_pressure':'memory','oom':'memory',
          'slow_queries':'query','latency_shift':'query','error_burst':'query','error_rate_shift':'query',
          'zk_disconnect':'coordination','leader_churn':'coordination'}
SEVERITY={'warning':1,'critical':2}


def minutes(ts):return int(datetime.fromisoformat(ts).timestamp())//60

def derived_features(events):
    """Node/collection minute aggregates for request latency and error-rate.
    Important: request logging completeness is UNKNOWN; reported rates are of logged requests.
    """
    groups=defaultdict(list)
    for e in events:
        if e['source']=='solr' and 'qtime_ms' in e['measures']:
            groups[(e['node'],e.get('attrs',{}).get('collection','unknown'),minutes(e['ts']))].append(e)
    rows=[]
    for (node,coll,minute),evs in sorted(groups.items()):
        values=sorted(x['measures']['qtime_ms'] for x in evs)
        pos=max(0,math.ceil(.95*len(values))-1)
        errors=sum(x['kind']=='http_5xx' for x in evs)
        rows.append({'node':node,'collection':coll,'minute':minute,'time':datetime.fromtimestamp(minute*60,tz=timezone.utc).isoformat(),
                     'requests':len(evs),'p95_qtime_ms':values[pos],'error_count':errors,
                     'logged_error_rate':round(errors/len(evs),4), 'evidence_ids':[x['id'] for x in sorted(evs,key=lambda x:x['measures']['qtime_ms'],reverse=True)[:4]]})
    return rows


def robust_detect(rows, events, min_baseline=12, min_samples=8):
    """Compare a minute's per-collection p95 to 12+ *previous* healthy-looking minutes.

    Baseline freezes before the first detected shift; 3 persistent abnormal
    minutes trigger one finding. CUSUM is a sustained-shift secondary signal.
    """
    events_by_id={e['id']:e for e in events}
    groups=defaultdict(list)
    for row in rows:groups[(row['node'],row['collection'])].append(row)
    found=[]; feature_diagnostics=[]
    for (node,collection),group in sorted(groups.items()):
        group.sort(key=lambda r:r['minute'])
        baseline=[]; run=[]; cusum=0.0; detected=False
        for r in group:
            x=r['p95_qtime_ms']
            if r['requests']<min_samples:continue
            if len(baseline)<min_baseline:
                baseline.append(x);continue
            med=statistics.median(baseline)
            mad=statistics.median(abs(v-med) for v in baseline)
            scaled=max(10.0,1.4826*mad)
            robust_z=(x-med)/scaled
            # Two criteria: statistically surprising AND meaningful absolute/relative change.
            surprising=robust_z>6 and x>max(med*2.5,med+100)
            cusum=max(0.0,cusum+(x-med-max(20,0.6*med)))
            shifted=cusum>max(350,5*med)
            if surprising and shifted:run.append(r)
            else:
                run=[];cusum=max(0.0,cusum*.25)
                if not detected:
                    baseline.append(x)
                    if len(baseline)>30:baseline.pop(0)
            if len(run)==3 and not detected:
                chosen=[events_by_id[eid] for rr in run for eid in rr['evidence_ids'] if eid in events_by_id]
                if chosen:
                    first=run[0]; last=run[-1]
                    finding={'node':node,'window':first['minute']//5,'type':'latency_shift','severity':'warning',
                             'summary':f'{collection} p95 latency persistently rose from baseline {med:.0f}ms to {x:.0f}ms',
                             'metric':f'baseline_p95_ms={med:.1f},observed_p95_ms={x:.1f},robust_z={robust_z:.1f}',
                             'collection':collection,'evidence_ids':list(dict.fromkeys(e['id'] for e in chosen))[:12],
                             'first_seen':first['time'],'last_seen':last['time'],'detector':'MAD+CUSUM'}
                    found.append(finding);detected=True
                    feature_diagnostics.append({'node':node,'collection':collection,'baseline_p95_ms':round(med,1),
                        'detection_minute_utc':last['time'],'observed_p95_ms':x,'robust_z':round(robust_z,1)})
            if detected and not surprising:
                # mark recovery but don't create duplicates in the same incident episode
                if len(run)==0:detected=False
    return found,feature_diagnostics


def normalize_findings(findings):
    for f in findings:
        f.setdefault('detector','hard_rule')
        f['id']=hashlib.sha1((f['node']+f['type']+str(f['window'])+str(f['first_seen'])).encode()).hexdigest()[:12]
    return findings


def make_incidents(findings,events,topology=None):
    """Conservative union-find: link observations by short temporal proximity and domain.

    - memory and query findings on the same node can be related
    - coordination across nodes can be related only with shared ZooKeeper dependency
    - unrelated coordination and memory must NOT merge on node identity alone
    """
    if not findings:return [],[]
    topo=topology or {}
    zk_nodes=set(topo.get('zookeeper_dependency',[]))
    parent=list(range(len(findings)))
    def root(i):
        while parent[i]!=i:
            parent[i]=parent[parent[i]];i=parent[i]
        return i
    def join(a,b):parent[root(a)]=root(b)
    edges=[]
    for i,a in enumerate(findings):
        at=minutes(a['first_seen'])
        for j in range(i+1,len(findings)):
            b=findings[j]; bt=minutes(b['first_seen'])
            gap=abs(at-bt)
            fa,fb=FAMILIES.get(a['type'],'other'),FAMILIES.get(b['type'],'other')
            if gap>6:continue
            if a['node']==b['node']:
                if fa==fb or {fa,fb}=={'memory','query'}:
                    # A query issue could be related to a memory issue but doesn't prove cause.
                    relation='same_node_temporal' if fa==fb else 'possible_gc_query_relation'
                else: continue
            elif fa==fb=='coordination' and a['node'] in zk_nodes and b['node'] in zk_nodes and gap<=3:
                relation='shared_zookeeper_dependency'
            else:continue
            join(i,j)
            edges.append({'from':a['id'],'to':b['id'],'relationship':relation,'causal':False})
    grouped=defaultdict(list)
    for i,f in enumerate(findings):grouped[root(i)].append(f)
    incidents=[]
    for group in grouped.values():
        types={f['type'] for f in group}; nodes=sorted({f['node'] for f in group})
        ids=list(dict.fromkeys(eid for f in group for eid in f['evidence_ids']))
        win=min(f['first_seen'] for f in group)
        if 'oom' in types:
            diagnosis='JVM OutOfMemoryError is logged; the initiating memory-allocation cause is unknown.'
            checks='Review JVM heap dump, indexing allocations and Solr caches; follow change-controlled recovery procedures.'
            conf='high'
        elif 'zk_disconnect' in types:
            diagnosis=('Multiple Solr nodes reported ZooKeeper session/connection disruption.' if len(nodes)>1 else
                       'This Solr node reported ZooKeeper connection/session trouble; shared cluster impact is unverified.')
            checks='Check ZooKeeper quorum and live nodes; inspect network/session timeline and shard leaders.'
            conf='medium'
        elif ('gc_pause' in types or 'heap_pressure' in types) and ('latency_shift' in types or 'slow_queries' in types or 'error_burst' in types):
            diagnosis='JVM memory/GC pressure and degraded queries overlap; GC contribution is plausible but not established.'
            checks='Align exact GC pause intervals with request start/end and compare load, allocations and heap occupancy.'
            conf='medium'
        elif 'latency_shift' in types or 'slow_queries' in types:
            diagnosis='Search latency degraded relative to the observed baseline; the initiating cause is unverified.'
            checks='Inspect query mix, indexing, cache hit ratio, per-shard latency and request traces.'
            conf='medium' if 'latency_shift' in types else 'low'
        else:
            diagnosis='Operational anomaly detected; no uniquely supported underlying cause.'
            checks='Inspect original event evidence, node metrics and live Solr cluster state.'
            conf='low'
        iid=hashlib.sha256((str(win)+str(nodes)+str(sorted(types))).encode()).hexdigest()[:10]
        multi=len(nodes)>1
        impact=('Logged query degradation/errors may affect searches; customer numbers and financial impact are unknown.'
                if any(t in types for t in ('latency_shift','slow_queries','error_burst')) else
                'Potential operational disruption; actual user impact is unmeasured.')
        incident_edges=[e for e in edges if e['from'] in {f['id'] for f in group} and e['to'] in {f['id'] for f in group}]
        incidents.append({'id':iid,'nodes':nodes,'scope':'multi-node' if multi else 'node','window_start':win,
           'severity':'critical' if any(f['severity']=='critical' for f in group) else 'warning',
           'anomalies':sorted(types),'findings':group,'evidence_ids':ids[:70],
           'root_cause_hypothesis':diagnosis,'confidence':conf,'operational_impact':impact,
           'recommended_remediation':checks,'evidence_relations':incident_edges,
           'alternatives':(['Query/indexing workload change','Independent GC pressure'] if 'latency_shift' in types else
                          ['Independent network issue','JVM stall','Planned replica recovery'] if 'zk_disconnect' in types else
                          ['Insufficient evidence for a unique cause']),
           'unknowns':['No direct business impact data','Log proximity does not prove causation'],
           'assessment_basis':'Logs + operator-supplied topology only'})
    incidents.sort(key=lambda x:x['window_start'])
    return incidents,edges


def analyze(sources,expected_nodes=None,topology=None):
    events,quality=parse_sources(sources)
    raw=baseline_detect(events)
    # A brief disconnect followed by explicit same-node reconnection is not an
    # observed outage. Preserve session-expiry events and sustained failures.
    def transient_reconnect(f):
        if f['type'] != 'zk_disconnect':return False
        linked=[e for e in events if e['id'] in set(f['evidence_ids'])]
        if len(linked)!=1 or 'expired' in linked[0]['message'].lower():return False
        t=minutes(linked[0]['ts'])
        return any(e['node']==f['node'] and e['source']=='solr' and 'zookeeper reconnected' in e['message'].lower()
                  and 0<=(datetime.fromisoformat(e['ts'])-datetime.fromisoformat(linked[0]['ts'])).total_seconds()<=30
                  for e in events if abs(minutes(e['ts'])-t)<=1)
    raw=[f for f in raw if not transient_reconnect(f)]
    rows=derived_features(events)
    learned,stats=robust_detect(rows,events)
    findings=normalize_findings(raw+learned)
    incidents,edges=make_incidents(findings,events,topology)
    expected=set(expected_nodes or [])|{s['node'] for s in sources if s.get('node')}
    observed={e['node'] for e in events}
    node_health={node:('UNKNOWN' if node not in observed else 'CRITICAL' if any(node in i['nodes'] and i['severity']=='critical' for i in incidents)
       else 'DEGRADED' if any(node in i['nodes'] for i in incidents) else 'NO_ANOMALY_OBSERVED') for node in sorted(expected)}
    cluster='UNKNOWN' if not observed else ('CRITICAL' if any(i['scope']=='multi-node' and i['severity']=='critical' for i in incidents)
               else 'DEGRADED' if incidents else 'UNKNOWN' if 'UNKNOWN' in node_health.values() else 'NO_ANOMALY_OBSERVED')
    quality['parsed_events']=len(events)
    quality['unparsed_ratio']=round(quality['unparsed_lines']/max(quality['total_lines'],1),3)
    return {'cluster_health':cluster,'node_health':node_health,'data_quality':quality,'events':events,
        'findings':findings,'incidents':incidents,'feature_windows':rows,'adaptive_diagnostics':stats,
        'evidence_graph_edges':edges,'assessment_scope':'Log-derived, UTC; simulated topology is not a live Solr state check.',
        'thresholds':{'hard_rules':'See rca_engine.py','statistical':'MAD robust-z > 6, baseline x2.5 and +100ms, CUSUM, persistence=3 windows',
                      'correlation':'<=6 minute relation gap, strict evidence-family and topology checks'}}
