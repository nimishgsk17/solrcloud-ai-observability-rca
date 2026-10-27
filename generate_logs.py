"""Reproducible *simulated*, NOT authentic Solr/JVM, workload-based log generator.

The format is inspired by the public Solr documentation (Log4j2 request/slow logs),
JDK unified GC logging and operational ZooKeeper patterns. No external model or
Solr instance is used. Ground truth is stored separately and never analyzed.
"""
from __future__ import annotations
import argparse, json, math, random
from datetime import datetime, timedelta, timezone
from pathlib import Path

COLLECTIONS=('products','inventory','orders')
QUERIES=('q=ssd&rows=10','q=headphones&rows=20','q=laptop&fq=inStock:true&rows=10',
         'q=wireless&facet=true&rows=50','q=charger&rows=20')


def gen(scenario='mixed', seed=23, duration_minutes=105, rate=64, start='2026-10-26T08:00:00+00:00'):
    if scenario not in ('normal','mixed','gc','zk','slow_no_gc','benign_zk','oom','independent'):
        raise ValueError('unknown scenario')
    if duration_minutes<50 or not (5<=rate<=200):
        raise ValueError('duration>=50 minutes; rate=5..200 requests/min/node')
    rnd=random.Random(seed)
    begin=datetime.fromisoformat(start.replace('Z','+00:00')).astimezone(timezone.utc)
    files={f'node-{node}_{src}.log':[] for node in 'abc' for src in ('solr','gc')}
    manifest=[]
    if scenario in ('mixed','gc','independent'):
        manifest.append(dict(type='gc_pressure_search_degradation',start_minute=40,end_minute=47,nodes=['node-a'],known_initiator='simulated_allocation_pressure'))
    if scenario in ('mixed','zk'):
        manifest.append(dict(type='shared_zookeeper_disruption',start_minute=78,end_minute=81,nodes=['node-a','node-b'],known_initiator='simulated_shared_coordination_failure'))
    if scenario=='independent':
        manifest.append(dict(type='independent_zookeeper',start_minute=43,end_minute=45,nodes=['node-b'],known_initiator='simulated_independent_connectivity_issue'))
    if scenario=='slow_no_gc':
        manifest.append(dict(type='slow_queries_without_gc',start_minute=38,end_minute=46,nodes=['node-a'],known_initiator='simulated_expensive_query_mix'))
    if scenario=='oom':
        manifest.append(dict(type='out_of_memory',start_minute=58,end_minute=59,nodes=['node-c'],known_initiator='simulated_heap_exhaustion'))
    # Benign ZooKeeper events are deliberate negative controls, NOT expected incidents.
    if scenario=='benign_zk':
        manifest.append(dict(type='benign_zk_reconnect',start_minute=48,end_minute=49,nodes=['node-b'],expected_incident=False))
    gcid={f'node-{n}':1 for n in 'abc'}
    heap={f'node-{n}':320.0+rnd.random()*60 for n in 'abc'}
    for minute in range(duration_minutes):
        # A smooth daypart wave plus independent bursts and jitter (not constant-rate traffic).
        seasonal=1+.40*math.sin(2*math.pi*minute/54)
        surge=1.65 if 22<=minute<27 else 1.0
        for node in 'abc':
            nod=f'node-{node}'
            n=max(8,round(rate*seasonal*surge*rnd.uniform(.85,1.15)))
            pressure=(node=='a' and scenario in ('gc','mixed','independent') and 40<=minute<47)
            expensive=(node=='a' and scenario=='slow_no_gc' and 38<=minute<46)
            # Low-memory state evolves with allocations and GC reclamation; don't sample after-GC independently.
            for req in range(n):
                at=begin+timedelta(minutes=minute,milliseconds=rnd.randrange(60000))
                coll=rnd.choices(COLLECTIONS,weights=[.68,.20,.12])[0]
                shard=1 if node!='c' else 2
                query=rnd.choice(QUERIES)
                # Lognormal produces a realistic right-skewed shape; complexity/traffic affect latency.
                complexity=1.8 if 'facet=true' in query else 1.0
                base=rnd.lognormvariate(math.log(38),.42)*complexity*(1+max(0,n-rate)/rate*.50)
                if expensive and coll=='products': base+=rnd.uniform(330,530)
                if pressure and coll=='products': base+=rnd.uniform(320,660)
                # Inject rare benign successful outliers in baseline, independent of incident.
                if rnd.random()<0.0004: base+=rnd.randrange(650,950)
                latency=round(base)
                id=f'{node}{minute:03d}{req:04d}{rnd.randrange(9999):04d}'
                code=503 if pressure and coll=='products' and rnd.random()<.16 else 0
                level='ERROR' if code else ('WARN' if latency>=1000 else 'INFO')
                msg=(f'[collection={coll} shard=shard{shard} replica={nod} trace_id={id}] '
                     f'path=/select params={{{query}}} QTime={latency} status={code}')
                if code: msg+=f' http_status={code} request failed'
                files[f'{nod}_solr.log'].append((at,f'{at.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]} {level} org.apache.solr.core.SolrCore.Request {msg}'))
                # Allocation / request is positively related to query complexity and indexing activity.
                heap[nod]+=rnd.uniform(.12,.42)*complexity*(3.0 if pressure else 1.0)
            if minute%3==0:
                at=begin+timedelta(minutes=minute,seconds=52)
                coll=rnd.choice(COLLECTIONS)
                files[f'{nod}_solr.log'].append((at,f'{at.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]} INFO org.apache.solr.update.UpdateHandler update batch completed collection={coll} docs={rnd.randint(20,120)}'))
                heap[nod]+=rnd.uniform(2,7)*(3 if pressure else 1)
            if minute%7==2:
                at=begin+timedelta(minutes=minute,seconds=17)
                files[f'{nod}_solr.log'].append((at,f'{at.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]} WARN org.apache.solr.update.SolrCmdDistributor transient update retry succeeded retryCount=1'))
            # JVM allocation pressure correlates with GC cadence, reclaimed size and pause time.
            collections=2 if pressure else 1
            for j in range(collections):
                at=begin+timedelta(minutes=minute,seconds=(26 if j==0 else 40))
                before=min(1020,int(heap[nod]+rnd.uniform(60,95)))
                if pressure:
                    after=max(880,int(before-rnd.uniform(20,70)))
                    pause=round(rnd.uniform(720,1400) if j==0 else rnd.uniform(2050,3100),1)
                    desc='Pause Full (G1 Compaction Pause)' if j==1 else 'Pause Young (Normal) (G1 Evacuation Pause)'
                else:
                    after=max(220,min(530,int(before-rnd.uniform(130,270))))
                    pause=round(rnd.uniform(14,90),1)
                    desc='Pause Young (Normal) (G1 Evacuation Pause)'
                # Ensure coherent before/after even in high pressure windows.
                after=min(after,before)
                heap[nod]=float(after)
                gcid[nod]+=1
                stamp=at.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'+0000'
                text=f'[{stamp}][info][gc] GC({gcid[nod]}) {desc} {before}M->{after}M(1024M) {pause}ms'
                files[f'{nod}_gc.log'].append((at,text))
            if minute%14==0:
                at=begin+timedelta(minutes=minute,seconds=49)
                stamp=at.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'+0000'
                files[f'{nod}_gc.log'].append((at,f'[{stamp}][info][gc] GC({gcid[nod]}) Concurrent Mark Cycle 780.0ms'))
    # Explicit synthetic fault/recovery events; the timelines remain in a separate manifest.
    def add(node,minute,sec,level,logger,message):
        at=begin+timedelta(minutes=minute,seconds=sec)
        line=f'{at.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]} {level} {logger} {message}'
        files[f'{node}_solr.log'].append((at,line))
    if scenario in ('mixed','zk'):
        for node in ('node-a','node-b'):
            add(node,78,12,'WARN','org.apache.solr.cloud.ZkController','ZooKeeper connection lost (connection loss) collection=products shard=shard1')
            add(node,78,22,'ERROR','org.apache.solr.cloud.ZkController','ZooKeeper session expired; disconnected collection=products shard=shard1')
            add(node,78,36,'WARN','org.apache.solr.cloud.ZkController','leader election started collection=products shard=shard1')
            add(node,78,41,'WARN','org.apache.solr.cloud.ZkController','leader changed collection=products shard=shard1')
            add(node,81,7,'INFO','org.apache.solr.cloud.ZkController','ZooKeeper reconnected; replica ACTIVE collection=products shard=shard1')
    if scenario=='independent':
        add('node-b',43,14,'WARN','org.apache.solr.cloud.ZkController','ZooKeeper connection lost (connection loss) collection=inventory shard=shard1')
        add('node-b',43,22,'ERROR','org.apache.solr.cloud.ZkController','ZooKeeper session expired collection=inventory shard=shard1')
    if scenario=='benign_zk':
        add('node-b',48,4,'WARN','org.apache.solr.cloud.ZkController','ZooKeeper disconnected collection=inventory shard=shard1')
        add('node-b',48,6,'INFO','org.apache.solr.cloud.ZkController','ZooKeeper reconnected session remains active collection=inventory shard=shard1')
    if scenario=='oom':
        add('node-c',58,12,'ERROR','org.apache.solr.core.SolrCore','java.lang.OutOfMemoryError: Java heap space collection=products shard=shard2')
    out={k:'\n'.join(line for _,line in sorted(v,key=lambda p:p[0]))+'\n' for k,v in files.items()}
    truth={'synthetic':True,'generator':'generate_logs_v2.py','seed':seed,'scenario':scenario,'start_utc':begin.isoformat(),
           'duration_minutes':duration_minutes,'total_lines':sum(len(x.splitlines()) for x in out.values()),
           'fault_injections':manifest,'validation':'Not authentic SolrCloud logs; timings are simulated, with explicit limitations.'}
    topology={'source':'SIMULATED_REFERENCE_TOPOLOGY', 'node_to_shards':{'node-a':['products/shard1','inventory/shard1'],
         'node-b':['products/shard1','orders/shard1'], 'node-c':['products/shard2','inventory/shard2']},
         'zookeeper_dependency':['node-a','node-b','node-c']}
    return out,truth,topology


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--scenario',choices=('normal','mixed','gc','zk','slow_no_gc','benign_zk','oom','independent'),default='mixed')
    p.add_argument('--seed',type=int,default=23)
    p.add_argument('--duration-minutes',type=int,default=105)
    p.add_argument('--rate',type=int,default=64)
    p.add_argument('--output-dir',type=Path,default=Path('generated_logs')/'enhanced')
    a=p.parse_args()
    logs,truth,topology=gen(a.scenario,a.seed,a.duration_minutes,a.rate)
    a.output_dir.mkdir(parents=True,exist_ok=True)
    for k,v in logs.items(): (a.output_dir/k).write_text(v,encoding='utf8')
    (a.output_dir/'GROUND_TRUTH.json').write_text(json.dumps(truth,indent=2),encoding='utf8')
    (a.output_dir/'TOPOLOGY.json').write_text(json.dumps(topology,indent=2),encoding='utf8')
    print(f'Generated {truth["total_lines"]:,} synthetic records; faults={len(truth["fault_injections"])}; output={a.output_dir}')

if __name__=='__main__': main()
