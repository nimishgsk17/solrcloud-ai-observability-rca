"""Synthetic *scenario-level* ablation; not production accuracy."""
from __future__ import annotations
import argparse,json,time
from pathlib import Path
from datetime import datetime
from generate_logs import gen
from parser import analyze as baseline
from analyzer import analyze as enhanced

SCENARIOS=('normal','gc','zk','slow_no_gc','benign_zk','oom','independent','mixed')

def inputs(logs):
    return [dict(filename=n,node=n.rsplit('_',1)[0],source=n.rsplit('_',1)[1][:-4],text=txt) for n,txt in logs.items()]

def positive_matches(incident,truth):
    # Match by observed node(s), rough time (within 6min), and incident *family*;
    # no privileged ground-truth variables are passed to analyze().
    typ=truth['type']; want={
       'gc_pressure_search_degradation':{'gc_pause','heap_pressure'},
       'shared_zookeeper_disruption':{'zk_disconnect'},
       'independent_zookeeper':{'zk_disconnect'},
       'slow_queries_without_gc':{'latency_shift','slow_queries'},
       'out_of_memory':{'oom'}}.get(typ,set())
    if not want or not want.intersection(incident['anomalies']):return False
    if not set(truth['nodes']).issubset(incident['nodes']):return False
    t=datetime.fromisoformat(incident['window_start'])
    base=datetime.fromisoformat(truth['_simulation_start'])
    minute=(t-base).total_seconds()/60
    return truth['start_minute']-5<=minute<=truth['end_minute']+5


def evaluate(seeds=(23,),rate=30):
    results=[]; total=dict(tp=0,fp=0,fn=0,scenarios=0,lines=0)
    for seed in seeds:
      for name in SCENARIOS:
        logs,truth,topology=gen(scenario=name,seed=seed,rate=rate)
        sources=inputs(logs)
        st=time.perf_counter()
        b=baseline(sources)
        v=enhanced(sources,topology=topology)
        seconds=round(time.perf_counter()-st,2)
        targets=[dict(x,_simulation_start=truth['start_utc']) for x in truth['fault_injections'] if x.get('expected_incident',True)]
        matched_t=set(); matched_i=set()
        for i,incident in enumerate(v['incidents']):
            for j,t in enumerate(targets):
                if j not in matched_t and positive_matches(incident,t):
                    matched_t.add(j);matched_i.add(i);break
        tp=len(matched_i);fp=len(v['incidents'])-tp;fn=len(targets)-tp
        total['tp']+=tp;total['fp']+=fp;total['fn']+=fn;total['lines']+=truth['total_lines'];total['scenarios']+=1
        results.append({'seed':seed,'scenario':name,'lines':truth['total_lines'],'expected_positive':len(targets),
            'baseline_incidents':len(b['incidents']),'enhanced_incidents':len(v['incidents']),
            'matched':tp,'false_incidents':fp,'missed':fn,'time_seconds':seconds,
            'adaptive_findings':len([f for f in v['findings'] if f['detector']=='MAD+CUSUM'])})
    prec=total['tp']/max(1,total['tp']+total['fp'])
    rec=total['tp']/max(1,total['tp']+total['fn'])
    return {'scope':'Synthetic, generator-defined incident labels only. Scenario matching uses node/family/time tolerance, not true causal correctness.',
      'total':total,'precision_synthetic':round(prec,3),'recall_synthetic':round(rec,3),
      'f1_synthetic':round(2*prec*rec/(prec+rec),3) if prec+rec else 0,'runs':results}

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,default=Path('EVALUATION.json'))
    args=ap.parse_args()
    d=evaluate();args.output.write_text(json.dumps(d,indent=2))
    print('Controlled synthetic evaluation: TP={tp}, FP={fp}, FN={fn}; precision={p:.3f} recall={r:.3f}'.format(**d['total'],p=d['precision_synthetic'],r=d['recall_synthetic']))
    for run in d['runs']:
        print(run['scenario'],run['seed'],'expected',run['expected_positive'],'baseline',run['baseline_incidents'],
          'enhanced',run['enhanced_incidents'],'match',run['matched'],'FP',run['false_incidents'])
