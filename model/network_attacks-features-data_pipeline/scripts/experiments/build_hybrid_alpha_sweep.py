"""Build RF/RSSM probability hybrids for alpha=0.1..0.9."""
import argparse,json
from pathlib import Path
import numpy as np,pandas as pd
from sklearn.metrics import f1_score,precision_score,recall_score,confusion_matrix
ROOT=Path(__file__).resolve().parents[2]
def main():
 p=argparse.ArgumentParser(); p.add_argument('--rssm-dir',default='results_selected_benchmark/sparse_rssm'); p.add_argument('--baseline-dir',default='reports/baselines'); p.add_argument('--out-dir',default='results_selected_benchmark/comparison_hybrid'); a=p.parse_args(); bd=ROOT/a.baseline_dir; rf=bd/'rf_test_probabilities.npz'; lab=bd/'rf_test_labels_k1.npy'
 if not rf.exists() or not lab.exists(): raise SystemExit('RF probability artifacts missing; rerun RF with updated script.')
 z=np.load(rf); rows=[]
 for f in (ROOT/a.rssm_dir).glob('**/test_probabilities.npz'):
  k=int(f.parent.name[1:]); key=f'RF_Static_k{k}';
  if key not in z: continue
  r=np.load(f); pr,yr=z[key],r['attack_label']; ps=r['attack_probability']; n=min(len(pr),len(ps),len(yr)); y=yr[:n]; pr=pr[:n]; ps=ps[:n]
  for alpha in np.arange(.1,1.0,.1):
   yp=((alpha*pr+(1-alpha)*ps)>=.5).astype(int); tn,fp,fn,tp=confusion_matrix(y,yp,labels=[0,1]).ravel(); rows.append({'Model':'RF+RSSM hybrid','K':k,'alpha':round(float(alpha),1),'F1':f1_score(y,yp,zero_division=0),'Precision':precision_score(y,yp,zero_division=0),'Recall':recall_score(y,yp,zero_division=0),'FPR':fp/max(1,fp+tn)})
 out=ROOT/a.out_dir; out.mkdir(parents=True,exist_ok=True); d=pd.DataFrame(rows); d.to_csv(out/'hybrid_alpha_comparison.csv',index=False); (out/'hybrid_alpha_comparison.json').write_text(json.dumps(d.to_dict('records'),indent=2)); (out/'hybrid_alpha_comparison.txt').write_text(d.to_string(index=False)); print(f'Wrote {len(d)} hybrid rows to {out}')
if __name__=='__main__': main()
