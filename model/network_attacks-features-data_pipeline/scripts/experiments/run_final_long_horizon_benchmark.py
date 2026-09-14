"""Resumable final LR/RF/Sparse-RSSM benchmark for K=1,100,200,400,600."""
import argparse,json,subprocess,sys,time
from pathlib import Path
import pandas as pd
from tqdm import tqdm
ROOT=Path(__file__).resolve().parents[2]; KS=(1,100,200,250,300); SP=(1.0,)
def write_comparison(out):
 rows=[]
 for f in (out/'sparse_rssm').glob('**/metrics.json'):
  m=json.loads(f.read_text()); rows.append({'Model':'Dense RSSM','K':m.get('horizon_k'),'F1':m.get('test_f1'),'Precision':m.get('test_precision'),'Recall':m.get('test_recall'),'FPR':m.get('test_fpr')})
 for f in list((out/'logs').glob('logistic_k*.log')) + list((out/'logs').glob('random_forest_k*.log')):
  for line in f.read_text(errors='ignore').splitlines():
   import re; m=re.search(r'(LR|RF) \[(.*?)\].*?K=(\d+).*?Test F1: ([0-9.]+).*?Rec: ([0-9.]+)',line)
   if m and int(m.group(3)) in KS:
    f1,rec=float(m.group(4)),float(m.group(5)); rows.append({'Model':m.group(1)+' — '+m.group(2).strip(),'K':int(m.group(3)),'F1':f1,'Precision':f1*rec/(2*rec-f1) if 2*rec>f1 else None,'Recall':rec,'FPR':None})
 if rows:
  d=out/'comparison'; d.mkdir(exist_ok=True); df=pd.DataFrame(rows); df.to_csv(d/'comparison.csv',index=False); (d/'comparison.json').write_text(json.dumps(df.where(pd.notna(df),None).to_dict('records'),indent=2)); (d/'comparison.txt').write_text(df.to_string(index=False))
def main():
 p=argparse.ArgumentParser(); p.add_argument('--results-dir',default='results_final_long_horizons'); p.add_argument('--epochs',type=int,default=5); p.add_argument('--batch-size',type=int,default=1024); p.add_argument('--stream',action='store_true'); p.add_argument('--no-resume',action='store_true'); a=p.parse_args(); out=ROOT/a.results_dir; (out/'logs').mkdir(parents=True,exist_ok=True); (out/'done').mkdir(exist_ok=True)
 tasks=[(f'{m}_k{k}','base',m,k,None) for m in ('logistic','random_forest') for k in KS]+[(f'rssm_{s:g}_k{k}','rssm',None,k,s) for s in SP for k in KS]
 for name,kind,m,k,s in tqdm(tasks,desc='final benchmark',unit='task'):
  mark=out/'done'/(name+'.json')
  if mark.exists() and not a.no_resume: continue
  cmd=([sys.executable,str(ROOT/'scripts/experiments/run_baseline_suite.py'),'--only-model',m,'--horizon',str(k),'--epochs',str(a.epochs)] if kind=='base' else [sys.executable,str(ROOT/'scripts/experiments/run_sparse_rssm.py'),'--sparsity',str(s),'--horizon',str(k),'--epochs',str(a.epochs),'--batch-size',str(a.batch_size),'--results-dir',str(out/'sparse_rssm')])
  log=out/'logs'/(name+'.log'); print(f'START {name}',flush=True)
  with log.open('w',encoding='utf-8') as f:
   if a.stream:
    q=subprocess.Popen(cmd,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    for line in q.stdout: print(f'[{name}] {line.rstrip()}',flush=True); f.write(line)
    rc=q.wait()
   else: rc=subprocess.run(cmd,cwd=ROOT,stdout=f,stderr=subprocess.STDOUT).returncode
  if rc: raise SystemExit(f'{name} failed (exit {rc}); rerun to resume; see {log}')
  mark.write_text(json.dumps({'task':name,'completed':time.time()})); print(f'END {name}',flush=True); write_comparison(out)
 write_comparison(out)
 print(f'Completed. Results: {out}',flush=True)
if __name__=='__main__': main()
