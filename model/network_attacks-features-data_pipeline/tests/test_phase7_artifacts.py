# -*- coding: utf-8 -*-
"""
Smoke test to verify Phase 7 deployable artifacts:
1. model.pt loads cleanly into SparseRSSM
2. scaler.pkl loads and transforms inputs
3. feature_schema.json, config.json, metadata.json, inference_example.json are valid JSON
4. End-to-end forward inference produces valid 54-D state forecast and onset probabilities
"""

import sys, json, pickle
from pathlib import Path
import numpy as np
import torch

REPO_ROOT = Path(r"C:\CyberSecurityNetworkingAttackPredictionModel")
sys.path.insert(0, str(REPO_ROOT))

from src.models.sparse_rssm import SparseRSSM

ARTIFACTS_DIR = REPO_ROOT / "artifacts" / "phase7"

def test_artifacts_integrity():
    print("Testing Phase 7 Artifacts Integrity...")
    
    # 1. Check files existence
    expected_files = ["model.pt", "scaler.pkl", "feature_schema.json", "config.json", "metadata.json", "inference_example.json"]
    for f in expected_files:
        p = ARTIFACTS_DIR / f
        assert p.exists(), f"Missing artifact: {f}"
        print(f"  [OK] {f} exists ({p.stat().st_size} bytes)")
        
    # 2. Check JSON files
    for jf in ["feature_schema.json", "config.json", "metadata.json", "inference_example.json"]:
        with open(ARTIFACTS_DIR / jf, "r") as fp:
            d = json.load(fp)
            assert isinstance(d, dict), f"{jf} is not a valid dict"
        print(f"  [OK] {jf} valid JSON")
        
    # 3. Check scaler
    with open(ARTIFACTS_DIR / "scaler.pkl", "rb") as fp:
        scaler = pickle.load(fp)
    assert hasattr(scaler, "mean_"), "Scaler has no mean_"
    assert len(scaler.mean_) == 54, f"Scaler dimension {len(scaler.mean_)} != 54"
    print(f"  [OK] scaler.pkl valid (54 dimensions)")
    
    # 4. Check model loading and inference
    model = SparseRSSM(sparsity_ratio=1.0)
    state_dict = torch.load(ARTIFACTS_DIR / "model.pt", map_location='cpu')
    model.load_state_dict(state_dict)
    model.eval()
    print(f"  [OK] model.pt loaded into SparseRSSM")
    
    # Run dummy batch (B=2, P=10, D=54)
    dummy_input = torch.randn(2, 10, 54)
    with torch.no_grad():
        out = model(dummy_input, K=10)
    assert 'x_recon' in out, "Missing x_recon"
    assert 'states' in out, "Missing states"
    assert len(out['states']) == 10, f"Expected 10 rollout states, got {len(out['states'])}"
    assert 'attack' in out, "Missing attack head"
    assert len(out['attack']) == 10, f"Expected 10 rollout attack logits, got {len(out['attack'])}"
    
    prob = torch.sigmoid(out['attack'][-1]).numpy()
    assert prob.shape == (2, 1), f"Unexpected prob shape: {prob.shape}"
    print(f"  [OK] Forward inference smoke test successful! Prob range: [{prob.min():.4f}, {prob.max():.4f}]")
    print("ALL PHASE 7 ARTIFACT VERIFICATIONS PASSED!")

if __name__ == '__main__':
    test_artifacts_integrity()
