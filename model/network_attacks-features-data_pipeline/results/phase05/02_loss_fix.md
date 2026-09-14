# Phase 5B — Multi-Task Joint Loss Fix Report

## 1. Multi-Task Formulation

The attack classification head is now formally integrated into `SparseRSSM.loss()` in `src/models/sparse_rssm.py`:

$$\mathcal{L}_{	ext{total}} = \lambda_{	ext{state}} \cdot \mathcal{L}_{	ext{state}} + \lambda_{	ext{attack}} \cdot \mathcal{L}_{	ext{attack}} + \lambda_{	ext{mitre}} \cdot \mathcal{L}_{	ext{mitre}}$$

where:
1. **Continuous State Loss ($\mathcal{L}_{	ext{state}}$):**
   $$\mathcal{L}_{	ext{state}} = 	ext{MSE}(\hat{S}_t, S_t) + rac{1}{K} \sum_{k=1}^K 	ext{MSE}(\hat{S}_{t+k}, S_{t+k})$$
2. **Binary Attack Classification Loss ($\mathcal{L}_{	ext{attack}}$):**
   $$\mathcal{L}_{	ext{attack}} = rac{1}{K} \sum_{k=1}^K 	ext{BCEWithLogitsLoss}(	ext{logit}_{t+k}, Y_{t+k})$$
3. **MITRE Stage Multiclass Loss ($\mathcal{L}_{	ext{mitre}}$):**
   $$\mathcal{L}_{	ext{mitre}} = rac{1}{K} \sum_{k=1}^K 	ext{CrossEntropyLoss}(	ext{stage\_logits}_{t+k}, 	ext{Stage}_{t+k})$$

## 2. Gradient Verification

When $\lambda_{	ext{attack}} = 1.0$, `loss.backward()` propagates gradients directly through `self.attack_head`, the latent representation $z$, the GRU memory $h$, and the encoder.
