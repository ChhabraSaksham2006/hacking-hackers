"""Resumable baseline + RSSM benchmark for K=1,50,100 and RSSM 10/50/100%."""
from __future__ import annotations
import argparse, json, subprocess, sys, time
from pathlib import Path
import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix
from tqdm import tqdm

ROOT=Path(__file__).resolve().parents[2]
HORIZONS=(1,50,100); SPARSITIES=(.10,.50,1.0)

def write_comparison(out: Path):
    rows=[]
    for f in sorted((out/'sparse_rssm').glob('**/metrics.json')):
        m=json.loads(f.read_text(encoding='utf-8')); rows.append({'Model':f.parent.parent.name,'K':m.get('horizon_k'),'Attack F1':m.get('test_f1'),'Precision':m.get('test_precision'),'Recall':m.get('test_recall'),'FPR':m.get('test_fpr'),'State MSE':m.get('test_state_mse',m.get('val_state_mse')),'Source':str(f)})
    bdir=ROOT/'reports'/'baselines'
    for f in sorted(bdir.glob('06_multihorizon_comparison*.csv')):
        try: d=pd.read_csv(f)
        except Exception: continue
        for _,r in d.iterrows():
            if str(r.get('model_name','')) == 'GRU':
                continue
            if int(r.get('horizon_k',-1)) in HORIZONS:
                rows.append({'Model':f"{r.get('model_name')} — {r.get('variant')}",'K':int(r['horizon_k']),'Attack F1':r.get('test_f1'),'Precision':r.get('test_precision'),'Recall':r.get('test_recall'),'FPR':(float(r['test_fp'])/max(1,float(r['test_fp'])+float(r['test_tn'])) if 'test_fp' in r and pd.notna(r.get('test_fp')) and pd.notna(r.get('test_tn')) else None),'State MSE':(float(r['test_state_rmse'])**2 if pd.notna(r.get('test_state_rmse')) else None),'Source':str(f)})
    archive=out/'baseline_log_metrics.jsonl'
    if archive.exists():
        for line in archive.read_text(encoding='utf-8').splitlines():
            try: rows.append(json.loads(line))
            except json.JSONDecodeError: pass
    if not rows: return
    c=pd.DataFrame(rows).drop_duplicates(['Model','K'], keep='last').sort_values(['K','Model']); comp=out/'comparison'; comp.mkdir(exist_ok=True)
    c.to_csv(comp/'combined_comparison.csv',index=False); (comp/'combined_comparison.json').write_text(json.dumps(c.where(pd.notna(c),None).to_dict('records'),indent=2),encoding='utf-8'); (comp/'combined_comparison.txt').write_text(c.to_string(index=False),encoding='utf-8')
    print(f'Comparison written: {comp}',flush=True)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--results-dir',type=Path,default=ROOT/'results_selected_benchmark')
    p.add_argument('--epochs',type=int,default=5); p.add_argument('--batch-size',type=int,default=1024)
    p.add_argument('--stream',action='store_true'); p.add_argument('--no-resume',action='store_true')
    p.add_argument('--skip-gru',action='store_true'); a=p.parse_args()
    out=a.results_dir if a.results_dir.is_absolute() else ROOT/a.results_dir; out.mkdir(parents=True,exist_ok=True)
    marks=out/'done'; logs=out/'logs'; marks.mkdir(exist_ok=True); logs.mkdir(exist_ok=True)
    baseline_models=['persistence','logistic','random_forest','transformer']
    if not a.skip_gru:
        baseline_models.append('gru')
    tasks=[(f'baseline_{m}_k{k}','baseline',k,m) for m in baseline_models for k in HORIZONS]
    tasks += [(f'rssm_{s:g}_k{k}','rssm',k,s) for s in SPARSITIES for k in HORIZONS]
    for name,kind,k,s in tqdm(tasks,desc='benchmark tasks',unit='task'):
        marker=marks/(name+'.json')
        if marker.exists() and not a.no_resume: continue
        if kind=='baseline':
            cmd=[sys.executable,str(ROOT/'scripts/experiments/run_baseline_suite.py'),'--horizon',str(k),'--epochs',str(a.epochs),'--only-model',str(s)]
        else:
            cmd=[sys.executable,str(ROOT/'scripts/experiments/run_sparse_rssm.py'),'--sparsity',str(s),'--horizon',str(k),'--epochs',str(a.epochs),'--batch-size',str(a.batch_size),'--results-dir',str(out/'sparse_rssm')]
        log=logs/(name+'.log'); print(f'\nSTART {name}',flush=True)
        with log.open('w',encoding='utf-8') as fh:
            if a.stream:
                proc=subprocess.Popen(cmd,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
                for line in proc.stdout: print(f'[{name}] {line.rstrip()}',flush=True); fh.write(line)
                rc=proc.wait()
            else: rc=subprocess.run(cmd,cwd=ROOT,stdout=fh,stderr=subprocess.STDOUT).returncode
        if rc: raise SystemExit(f'{name} failed (exit {rc}); rerun to resume; see {log}')
        marker.write_text(json.dumps({'task':name,'horizon':k,'sparsity':s,'completed':time.time()}),encoding='utf-8'); print(f'END {name}',flush=True)
        # Keep comparison artifacts current so interruption never loses the
        # results of tasks that already completed successfully.
        write_comparison(out)
    write_comparison(out)
    print(f'Completed benchmark. Results: {out}',flush=True)
if __name__=='__main__': main()
