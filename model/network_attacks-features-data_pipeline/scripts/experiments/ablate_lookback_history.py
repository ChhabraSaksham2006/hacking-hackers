import os
import sys
import torch
import numpy as np
import pandas as pd
from sklearn.metrics import mean_absolute_error, mean_squared_error

# Add src to path
sys.path.insert(0, ".")
from src.models.sparse_rssm import SparseRSSM
from src.temporal.dataset_builder import TemporalSequenceBuilder, TRAIN_DAYS, VAL_DAYS, TEST_DAYS

def run_lookback_ablation():
    print("=" * 75)
    print("SIH26153: HISTORICAL LOOKBACK CONTEXT ABLATION FOR SPARSERSSM")
    print("Evaluating whether Lookback Length P in {3, 5, 10, 15, 20} improves state rollout")
    print("=" * 75)
    
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Hardware: {device}")
    
    # Load dataset parquets
    state_dir = "data/processed/temporal_states"
    train_dfs = [pd.read_parquet(os.path.join(state_dir, f.replace(".parquet", "_states.parquet"))) for f in TRAIN_DAYS]
    test_dfs = [pd.read_parquet(os.path.join(state_dir, f.replace(".parquet", "_states.parquet"))) for f in TEST_DAYS]
    
    # Extract raw features
    from src.temporal.state_aggregator import STATE_FEATURE_NAMES
    from sklearn.preprocessing import StandardScaler
    
    scaler = StandardScaler()
    train_feats = [df[STATE_FEATURE_NAMES].values.astype(np.float32) for df in train_dfs]
    scaler.fit(np.vstack(train_feats))
    
    test_feats = [scaler.transform(df[STATE_FEATURE_NAMES].values.astype(np.float32)) for df in test_dfs]
    
    # We will test multiple lookback lengths P
    lookback_candidates = [3, 5, 10, 15, 20]
    forecast_k = 10 # 20 seconds ahead
    
    # Load frozen checkpoint weights
    model_path = "models/final/model.pt"
    assert os.path.exists(model_path), f"Missing {model_path}"
    
    # Note: SparseRSSM has an RNN/GRU core that accepts variable sequence lengths P!
    # Because for i in range(x.shape[1]): h = gru(encoder(x[:, i]), h)
    # The recurrent memory consumes any sequence length P smoothly.
    
    results = []
    
    for P in lookback_candidates:
        print(f"\nEvaluating Lookback History P = {P} windows ({P * 2.0} seconds of context)...")
        
        # Build test sequences of length P and target S_{t+K}
        X_test_list = []
        Y_test_state_list = []
        
        for feats in test_feats:
            N = len(feats)
            for t in range(P, N - forecast_k):
                x_seq = feats[t - P : t] # (P, 54)
                y_state = feats[t + forecast_k - 1] # S_{t+K} (54,)
                X_test_list.append(x_seq)
                Y_test_state_list.append(y_state)
                
        X_test = np.array(X_test_list, dtype=np.float32)
        Y_test = np.array(Y_test_state_list, dtype=np.float32)
        
        # Subsample for evaluation speed
        sub_idx = np.arange(0, len(X_test), 5)
        X_sub = torch.tensor(X_test[sub_idx]).to(device)
        Y_sub = Y_test[sub_idx]
        
        # Initialize model
        model = SparseRSSM(state_dim=54, latent_dim=128, hidden_dim=128, sparsity_ratio=1.0).to(device)
        state_dict = torch.load(model_path, map_location=device, weights_only=True)
        model.load_state_dict(state_dict)
        model.eval()
        
        with torch.no_grad():
            out = model.forward(X_sub, K=forecast_k)
            pred_state_k10 = out["states"][-1].cpu().numpy() # (N, 54)
            
        mae = float(mean_absolute_error(Y_sub, pred_state_k10))
        mse = float(mean_squared_error(Y_sub, pred_state_k10))
        
        # Also compute onset probability calibration metrics
        atk_logits = torch.cat([a.squeeze(-1) for a in out["attack"]], dim=-1)
        probs = torch.sigmoid(atk_logits.max(dim=-1).values).cpu().numpy()
        mean_prob = float(probs.mean())
        
        print(f"  -> Lookback P={P} ({P*2.0}s): State MAE = {mae:.4f} | State MSE = {mse:.4f} | Mean Onset Prob = {mean_prob:.4f}")
        results.append({
            "lookback_p": P,
            "lookback_seconds": P * 2.0,
            "samples_evaluated": len(sub_idx),
            "state_mae": round(mae, 4),
            "state_mse": round(mse, 4),
            "mean_onset_prob": round(mean_prob, 4)
        })
        
    df_res = pd.DataFrame(results)
    print("\n" + "=" * 75)
    print("LOOKBACK ABLATION SUMMARY TABLE")
    print("=" * 75)
    print(df_res.to_string(index=False))
    
    os.makedirs("reports/phase_1", exist_ok=True)
    df_res.to_csv("reports/phase_1/lookback_history_ablation.csv", index=False)
    print("\nSaved reports/phase_1/lookback_history_ablation.csv successfully.")

if __name__ == "__main__":
    run_lookback_ablation()
