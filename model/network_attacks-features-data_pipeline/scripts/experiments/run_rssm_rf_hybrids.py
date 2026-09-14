"""Dense RSSM K=100 feature/hybrid RF experiments.

Uses the trained RSSM checkpoint for latent/state features, then evaluates
RSSM-only, RF-only, RSSM->RF, RF->RSSM proxy, probability fusion, and RF with
RSSM latent features.  Outputs are isolated under ``results_rssm_rf_k100``.
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
import numpy as np, pandas as pd, torch
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix
ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from scripts.experiments.run_sparse_rssm import load_data
from src.models.sparse_rssm import SparseRSSM

def metrics(y,p):
 tn,fp,fn,tp=confusion_matrix(y,p,labels=[0,1]).ravel()
 return {'f1':float(f1_score(y,p,zero_division=0)),'precision':float(precision_score(y,p,zero_division=0)),'recall':float(recall_score(y,p,zero_division=0)),'fpr':float(fp/max(1,fp+tn))}
def best_threshold(y,score):
 best_t,best=.5,-1.0
 for t in np.arange(.01,1.0,.01):
  v=f1_score(y,(score>=t).astype(int),zero_division=0)
  if v>best: best,best_t=float(v),float(t)
 return best_t
def main():
 p=argparse.ArgumentParser(); p.add_argument('--checkpoint',default='results_dense_k100_10ep/dense/k100/checkpoint.pt'); p.add_argument('--out-dir',default='results_rssm_rf_k100'); p.add_argument('--batch-size',type=int,default=1024); a=p.parse_args(); out=ROOT/a.out_dir; out.mkdir(parents=True,exist_ok=True)
 raw=torch.load(ROOT/a.checkpoint,map_location='cpu',weights_only=False); model=SparseRSSM(sparsity_ratio=1.0).eval(); model.load_state_dict(raw['model_state_dict']); tr,va,te=load_data(ROOT/'data/processed/temporal_states',100)
 def features(ds):
  xs=[]; probs=[]; lat=[]; pred=[]; unc=[]; ys=[]
  for x,y in torch.utils.data.DataLoader(torch.utils.data.TensorDataset(ds[0],ds[2][100]),a.batch_size):
   with torch.no_grad(): o=model(x,100); z=o['z']; q=o['states'][-1]; pr=torch.sigmoid(o['attack'][-1]).squeeze(-1)
   xs.append(x[:,-1].numpy()); lat.append(z.numpy()); pred.append(q.numpy()); probs.append(pr.numpy()); unc.append(z.std(1).numpy()); ys.append(y.numpy())
  return np.vstack(xs),np.vstack(lat),np.vstack(pred),np.concatenate(probs).reshape(-1,1),np.concatenate(unc).reshape(-1,1),np.concatenate(ys)
 Xtr,Ztr,Str,Ptr,Utr,Ytr=features(tr); Xva,Zva,Sva,Pva,Uva,Yva=features(va); Xte,Zte,Ste,Pte,Ute,Yte=features(te)
 rf=lambda X,y: RandomForestClassifier(n_estimators=200,max_depth=15,min_samples_split=10,n_jobs=-1,random_state=42).fit(X,y)
 rf_model=rf(Xtr,Ytr); rf_val=rf_model.predict_proba(Xva)[:,1]; rfprob=rf_model.predict_proba(Xte)[:,1]
 rf_aug=rf(np.hstack([Xtr,Ztr,Str,Ptr,Utr]),Ytr); rf_lat=rf(np.hstack([Xtr,Ztr]),Ytr)
 rows=[]; models={
  '1_rssm_alone':(Pte.ravel()>=.5).astype(int),
  '2_rf_alone':rfprob,
  '3_rssm_to_rf':rf_aug.predict_proba(np.hstack([Xte,Zte,Ste,Pte,Ute]))[:,1],
  '6_rf_rssm_latent':rf_lat.predict_proba(np.hstack([Xte,Zte]))[:,1],
 }
 rfprob=models['2_rf_alone']; rssmprob=Pte.ravel()
 models['4_rf_to_rssm_proxy']=.5*rfprob+.5*rssmprob
 models['5_probability_fusion']=.5*rfprob+.5*rssmprob
 val_scores={'1_rssm_alone':Pva.ravel(),'2_rf_alone':rf_val,
             '3_rssm_to_rf':rf_aug.predict_proba(np.hstack([Xva,Zva,Sva,Pva,Uva]))[:,1],
             '6_rf_rssm_latent':rf_lat.predict_proba(np.hstack([Xva,Zva]))[:,1]}
 val_scores['4_rf_to_rssm_proxy']=.5*rf_val+.5*Pva.ravel(); val_scores['5_probability_fusion']=val_scores['4_rf_to_rssm_proxy']
 for name,score in models.items():
  threshold=best_threshold(Yva,val_scores[name]); pred=(score>=threshold).astype(int); row={'Model':name,'K':100,'threshold':threshold,**metrics(Yte,pred)}; rows.append(row); (out/(name)).mkdir(exist_ok=True); np.savez_compressed(out/name/'test_outputs.npz',score=score,label=Yte,prediction=pred,threshold=threshold)
 d=pd.DataFrame(rows); d.to_csv(out/'comparison.csv',index=False); (out/'comparison.json').write_text(json.dumps(rows,indent=2)); (out/'comparison.txt').write_text(d.to_string(index=False)); print(d.to_string(index=False)); print('Results:',out)
if __name__=='__main__': main()
