# Phase 5A — Forensic RSSM Code Audit & Untrained Head Diagnosis

## 1. Architectural Code Inspection

Prior to Phase 5, `src/models/sparse_rssm.py` defined the forward pass as:

```python
def forward(self, x, K=1):
    # Encodes x -> z, recurrent GRU -> h
    # Decodes state -> out['states']
    # Computes attack logits -> out['attack']
    # Computes stage logits -> out['stage']
    return out
```

However, the training objective in `SparseRSSM.loss()` was strictly implemented as:

```python
# PREVIOUS FLAWED IMPLEMENTATION:
def loss(self, out, target_init, target_rollout):
    loss_recon = F.mse_loss(out['recon'], target_init)
    loss_rollout = sum(F.mse_loss(out['states'][k], target_rollout[k]) for k in range(K)) / K
    return loss_recon + loss_rollout
```

## 2. Forensic Impact & Root Cause of the "Fake 0.55 F1"

1. **Zero Attack Head Gradient:** The binary attack forecasting head `self.attack_head` was NEVER referenced in `SparseRSSM.loss()`. Consequently, `attack_head.weight.grad` was strictly `0.0`.
2. **Random Logit Distribution:** Because the attack head was uninitialized and never trained, its output logits remained around zero.
3. **Artificial Decision Rule:** When evaluated with an aggressive decision rule or standard threshold, the uncalibrated head produced a ~75% positive prediction rate, masquerading as an F1 of ~0.55 purely by exploiting the test set attack class balance.
4. **Resolution:** Fixed in Phase 5B with a mathematically grounded joint multi-task loss combining state rollout MSE, BCEWithLogitsLoss, and CrossEntropyLoss.
