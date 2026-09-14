"""Train one or all Sparse RSSM configurations on the project's canonical split."""
from __future__ import annotations
import argparse, json, os, random
from pathlib import Path
import numpy as np, pandas as pd, torch
from torch.utils.data import DataLoader
from tqdm import tqdm
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix
# Make direct ``python scripts/experiments/...`` execution import the package.
import sys
ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from src.models.sparse_rssm import SparseRSSM
from src.temporal.dataset_builder import TemporalSequenceBuilder, STATE_FEATURE_NAMES, TRAIN_DAYS, VAL_DAYS, TEST_DAYS

HORIZONS=(1,100,200,250,300); DATA_HORIZONS=tuple(range(1,301)); SPARSITIES=(.05,.10,.25,.50,1.0)
def seed_all(s=42): random.seed(s); np.random.seed(s); torch.manual_seed(s); torch.cuda.manual_seed_all(s)
def load_data(data_dir, max_h):
    read=lambda names:[pd.read_parquet(Path(data_dir)/(n.replace('.parquet','_states.parquet'))) for n in names]
    horizons=tuple(range(1,max_h+1))
    tr,va,te=read(TRAIN_DAYS),read(VAL_DAYS),read(TEST_DAYS); b=TemporalSequenceBuilder(10,list(horizons),STATE_FEATURE_NAMES); b.fit_scaler(tr)
    def build(ds):
        seq=[]; states={k:[] for k in horizons}; bins={k:[] for k in horizons}
        for d in ds:
            d=b.transform_dataframe(d); f=np.nan_to_num(d[STATE_FEATURE_NAMES].values.astype('float32')); y=d.is_attack.values.astype('int64'); n=len(d); st=9; en=n-1-max_h
            if en<st: continue
            w=np.lib.stride_tricks.sliding_window_view(f,(10,54))[:,0,:,:]; seq.append(np.ascontiguousarray(w[:en-st+1]))
            for k in horizons:
                states[k].append(f[st+k:en+k+1]); bins[k].append(y[st+k:en+k+1])
        return torch.from_numpy(np.vstack(seq)).float(), {k:torch.from_numpy(np.vstack(v)).float() for k,v in states.items()}, {k:torch.from_numpy(np.concatenate(v)).long() for k,v in bins.items()}
    return build(tr),build(va),build(te)
def run_one(sp,k,args,device,data):
    out=Path(args.results_dir)/(('dense' if sp==1 else f'top{int(sp*100):02d}'))/f'k{k}'; out.mkdir(parents=True,exist_ok=True); marker=out/'DONE.json'
    if marker.exists() and not args.no_resume: print(f'SKIP {out}'); return
    (tr,va,te)=data
    model=SparseRSSM(sparsity_ratio=sp).to(device); opt=torch.optim.AdamW(model.parameters(),lr=args.lr); best=1e99
    for ep in tqdm(range(1,args.epochs+1),desc=f'RSSM {sp:g} K={k}',unit='epoch'):
        model.train(); total=0
        target_keys=list(range(1,k+1))
        ds=torch.utils.data.TensorDataset(tr[0],*[tr[1][h] for h in target_keys]); dl=DataLoader(ds,args.batch_size,shuffle=True)
        for batch in tqdm(dl,desc='train',unit='batch',leave=False):
            x=batch[0].to(device); ys=[batch[target_keys.index(h)+1].to(device) for h in range(1,k+1) if h in target_keys]
            # For extended horizons, use the requested target at each rollout
            # step when available; every predicted state remains supervised.
            ys = [batch[-1].to(device) for _ in range(k)] if len(ys)!=k else ys
            opt.zero_grad(); o=model(x,k); loss,_=model.loss(o,x[:,-1],ys); loss.backward(); torch.nn.utils.clip_grad_norm_(model.parameters(),1); opt.step(); total+=loss.item()
        model.eval(); mse=[]
        with torch.no_grad():
            for x,y in DataLoader(torch.utils.data.TensorDataset(va[0],va[1][k]),args.batch_size): mse.append(torch.mean((model(x.to(device),k)['states'][-1]-y.to(device))**2).item())
        score=float(np.mean(mse)); best=min(best,score); print(f'epoch={ep} train={total/max(1,len(dl)):.4f} val_state_mse={score:.6f}')
    model.eval(); probs=[]; ys=[]; sm=[]
    with torch.no_grad():
        for x,y,attack_y in DataLoader(torch.utils.data.TensorDataset(te[0],te[1][k],te[2][k]),args.batch_size):
            o=model(x.to(device),k); probs.extend(torch.sigmoid(o['attack'][-1]).squeeze(-1).cpu().numpy()); ys.extend(attack_y.numpy()); sm.append(0.0)
    yp=(np.asarray(probs)>=.5).astype(int); yt=np.asarray(ys); tn,fp,fn,tp=confusion_matrix(yt,yp,labels=[0,1]).ravel(); metrics={'state_dim':54,'sparsity_ratio':sp,'horizon_k':k,'val_state_mse':best,'test_f1':float(f1_score(yt,yp,zero_division=0)),'test_precision':float(precision_score(yt,yp,zero_division=0)),'test_recall':float(recall_score(yt,yp,zero_division=0)),'test_fpr':float(fp/max(1,fp+tn)),'epochs':args.epochs}
    print(f'Test F1={metrics["test_f1"]:.4f} Precision={metrics["test_precision"]:.4f} Recall={metrics["test_recall"]:.4f} FPR={metrics["test_fpr"]:.4f}',flush=True)
    np.savez_compressed(out/'test_probabilities.npz', attack_probability=np.asarray(probs), attack_label=yt)
    torch.save({'model_state_dict':model.state_dict(),'config':metrics},out/'checkpoint.pt'); json.dump(metrics,open(out/'metrics.json','w'),indent=2); marker.write_text(json.dumps({'complete':True}))
def main():
    p=argparse.ArgumentParser(); p.add_argument('--sparsity',type=float); p.add_argument('--horizon',type=int); p.add_argument('--run-all',action='store_true'); p.add_argument('--epochs',type=int,default=5); p.add_argument('--batch-size',type=int,default=512); p.add_argument('--lr',type=float,default=1e-3); p.add_argument('--results-dir',default='results_rebuilt_rssm'); p.add_argument('--no-resume',action='store_true'); a=p.parse_args(); seed_all(); dev=torch.device('cuda' if torch.cuda.is_available() else 'cpu'); print('device:',dev)
    ss=SPARSITIES if a.run_all else (a.sparsity,); ks=HORIZONS if a.run_all else (a.horizon,); data=load_data(ROOT/'data/processed/temporal_states',max(ks));
    for s in ss:
        for k in ks: run_one(s,k,a,dev,data)
if __name__=='__main__': main()
