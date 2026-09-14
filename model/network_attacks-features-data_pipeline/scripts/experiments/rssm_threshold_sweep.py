"""Evaluate saved RSSM test probabilities over thresholds 0.1..0.9."""
import argparse,json
from pathlib import Path
import numpy as np,pandas as pd
import torch
from torch.utils.data import DataLoader
from sklearn.metrics import f1_score,precision_score,recall_score,confusion_matrix
ROOT=Path(__file__).resolve().parents[2]
import sys
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
def main():
 p=argparse.ArgumentParser(); p.add_argument('--rssm-dir',default='results_selected_benchmark/sparse_rssm'); p.add_argument('--out-dir',default='results_selected_benchmark/rssm_thresholds'); p.add_argument('--min-threshold',type=float,default=.1); p.add_argument('--max-threshold',type=float,default=.9); p.add_argument('--step',type=float,default=.1); a=p.parse_args(); rows=[]
 rssm_root=ROOT/a.rssm_dir
 for ckpt in sorted(rssm_root.glob('**/checkpoint.pt')):
  m=ckpt.parent; k=int(m.name[1:]); s=m.parent.name
  zpath=m/'test_probabilities.npz'
  if zpath.exists():
   z=np.load(zpath); prob=z['attack_probability']; y=z['attack_label']
  else:
   # Infer probabilities directly from the trained checkpoint.
   from scripts.experiments.run_sparse_rssm import load_data
   from src.models.sparse_rssm import SparseRSSM
   raw=torch.load(ckpt,map_location='cpu',weights_only=False); cfg=raw.get('config',{})
   model=SparseRSSM(sparsity_ratio=float(cfg.get('sparsity_ratio',1.0))).eval(); model.load_state_dict(raw['model_state_dict'])
   test=load_data(ROOT/'data/processed/temporal_states',k)[2]; prob=[]; ys=[]
   for x,y in DataLoader(torch.utils.data.TensorDataset(test[0],test[2][k]),1024):
    with torch.no_grad(): prob.extend(torch.sigmoid(model(x[:,-1],k)['attack'][-1]).squeeze(-1).numpy())
    ys.extend(y.numpy())
   prob=np.asarray(prob); y=np.asarray(ys)
  for t in np.arange(a.min_threshold, a.max_threshold + a.step/2, a.step):
   pred=(prob>=t).astype(int); tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel(); rows.append({'Model':s,'K':k,'Threshold':round(float(t),1),'F1':f1_score(y,pred,zero_division=0),'Precision':precision_score(y,pred,zero_division=0),'Recall':recall_score(y,pred,zero_division=0),'FPR':fp/max(1,fp+tn)})
 if not rows: raise SystemExit('No RSSM test_probabilities.npz files found.')
 out=ROOT/a.out_dir; out.mkdir(parents=True,exist_ok=True); d=pd.DataFrame(rows); d.to_csv(out/'threshold_sweep.csv',index=False); (out/'threshold_sweep.json').write_text(json.dumps(d.to_dict('records'),indent=2)); (out/'threshold_sweep.txt').write_text(d.to_string(index=False)); print(f'Wrote {len(d)} rows to {out}')
if __name__=='__main__': main()
