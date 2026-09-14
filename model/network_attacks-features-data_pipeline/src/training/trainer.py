"""
SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
Module: src.training.trainer

Training and Optimization Engine for Temporal Neural Sequence Models (GRU / Transformer).
Implements multi-task loss optimization, validation monitoring, early stopping,
and class-weighted gradient updates.
"""

import time
from typing import Dict, List, Optional, Tuple, Any
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
try:
    from tqdm.auto import tqdm
except ImportError:
    def tqdm(it, **kwargs): return it

from src.evaluation.metrics import compute_binary_metrics, find_optimal_threshold


class SequenceModelTrainer:
    """
    Trainer for PyTorch Temporal Forecasters (GRU and Transformer).
    """

    def __init__(
        self,
        model: nn.Module,
        horizons: Optional[List[int]] = None,
        lr: float = 1e-3,
        weight_decay: float = 1e-4,
        pos_weight: Optional[float] = None,
        state_loss_weight: float = 0.5,
        family_loss_weight: float = 0.5,
        tau_loss_weight: float = 0.01,
        device: Optional[torch.device] = None
    ):
        self.device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = model.to(self.device)
        self.horizons = horizons or [1, 3, 5, 10, 25, 50, 100, 200]
        self.state_loss_weight = state_loss_weight
        self.family_loss_weight = family_loss_weight
        self.tau_loss_weight = tau_loss_weight

        # Loss Functions
        if pos_weight is not None:
            pw_tensor = torch.tensor([pos_weight], device=self.device)
            self.bce_loss_fn = nn.BCEWithLogitsLoss(pos_weight=pw_tensor)
        else:
            self.bce_loss_fn = nn.BCEWithLogitsLoss()

        self.mse_loss_fn = nn.MSELoss()
        self.ce_loss_fn = nn.CrossEntropyLoss()
        self.smooth_l1_fn = nn.SmoothL1Loss()

        self.optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=lr,
            weight_decay=weight_decay
        )

    def train_epoch(self, train_loader: DataLoader) -> Dict[str, float]:
        """
        Executes one full training epoch.
        """
        self.model.train()
        total_loss = 0.0
        total_bce = 0.0
        total_mse = 0.0
        n_batches = len(train_loader)

        for batch in train_loader:
            x = batch['input_sequence'].to(self.device)
            tau_true = batch['target_tau'].to(self.device)

            self.optimizer.zero_grad()
            outputs = self.model(x)

            loss = 0.0
            # 1. Multi-horizon Binary & State & Family Losses
            for k in self.horizons:
                y_true = batch[f'target_binary_k{k}'].to(self.device).float()
                y_logits = outputs[f'binary_logits_k{k}']
                bce_k = self.bce_loss_fn(y_logits, y_true)
                loss += bce_k
                total_bce += bce_k.item()

                s_true = batch[f'target_state_k{k}'].to(self.device)
                s_pred = outputs[f'state_pred_k{k}']
                mse_k = self.mse_loss_fn(s_pred, s_true) * self.state_loss_weight
                loss += mse_k
                total_mse += mse_k.item()

                # Family CE loss (applied only where attack is present)
                fam_true = batch[f'target_family_k{k}'].to(self.device)
                fam_logits = outputs[f'family_logits_k{k}']
                atk_mask = y_true > 0
                if atk_mask.sum() > 0:
                    ce_k = self.ce_loss_fn(fam_logits[atk_mask], fam_true[atk_mask]) * self.family_loss_weight
                    loss += ce_k

            # 2. Tau Onset Loss
            tau_pred = outputs['tau_pred']
            tau_loss = self.smooth_l1_fn(tau_pred, tau_true) * self.tau_loss_weight
            loss += tau_loss

            loss.backward()
            nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            self.optimizer.step()

            total_loss += loss.item()

        return {
            'loss': round(total_loss / n_batches, 4),
            'bce_loss': round(total_bce / n_batches, 4),
            'mse_loss': round(total_mse / n_batches, 4)
        }

    @torch.no_grad()
    def evaluate(self, data_loader: DataLoader, desc: str = 'baseline eval') -> Dict[str, Any]:
        """
        Evaluates the model and extracts predictions across all horizons.
        """
        self.model.eval()
        predictions = {f'probs_k{k}': [] for k in self.horizons}
        predictions.update({f'states_k{k}': [] for k in self.horizons})
        predictions.update({f'families_k{k}': [] for k in self.horizons})
        predictions['tau_pred'] = []

        ground_truth = {f'binary_k{k}': [] for k in self.horizons}
        ground_truth.update({f'states_k{k}': [] for k in self.horizons})
        ground_truth.update({f'families_k{k}': [] for k in self.horizons})
        ground_truth['tau_true'] = []

        for batch in data_loader:
            x = batch['input_sequence'].to(self.device)
            outputs = self.model(x)

            for k in self.horizons:
                predictions[f'probs_k{k}'].append(outputs[f'binary_probs_k{k}'].cpu().numpy())
                predictions[f'states_k{k}'].append(outputs[f'state_pred_k{k}'].cpu().numpy())
                fam_preds = torch.argmax(outputs[f'family_logits_k{k}'], dim=-1).cpu().numpy()
                predictions[f'families_k{k}'].append(fam_preds)

                ground_truth[f'binary_k{k}'].append(batch[f'target_binary_k{k}'].numpy())
                ground_truth[f'states_k{k}'].append(batch[f'target_state_k{k}'].numpy())
                ground_truth[f'families_k{k}'].append(batch[f'target_family_k{k}'].numpy())

            predictions['tau_pred'].append(outputs['tau_pred'].cpu().numpy())
            ground_truth['tau_true'].append(batch['target_tau'].numpy())

        # Concatenate arrays
        results = {}
        for k in self.horizons:
            results[f'probs_k{k}'] = np.concatenate(predictions[f'probs_k{k}'])
            results[f'states_pred_k{k}'] = np.vstack(predictions[f'states_k{k}'])
            results[f'families_pred_k{k}'] = np.concatenate(predictions[f'families_k{k}'])

            results[f'binary_true_k{k}'] = np.concatenate(ground_truth[f'binary_k{k}'])
            results[f'states_true_k{k}'] = np.vstack(ground_truth[f'states_k{k}'])
            results[f'families_true_k{k}'] = np.concatenate(ground_truth[f'families_k{k}'])

        results['tau_pred'] = np.concatenate(predictions['tau_pred'])
        results['tau_true'] = np.concatenate(ground_truth['tau_true'])
        return results

    def fit(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        epochs: int = 15,
        patience: int = 4
    ) -> Dict[str, Any]:
        """
        Trains model with early stopping based on Validation PR-AUC.
        """
        best_val_score = -1.0
        best_weights = None
        history = []
        patience_counter = 0

        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            self.optimizer,
            T_max=epochs,
            eta_min=1e-5
        )

        for epoch in tqdm(range(1, epochs + 1), desc='baseline epochs', unit='epoch'):
            t0 = time.time()
            train_metrics = self.train_epoch(train_loader)
            scheduler.step()

            # Evaluate on Validation set
            val_results = self.evaluate(val_loader)
            # Validation metric: Mean PR-AUC across horizons
            pr_aucs = []
            for k in self.horizons:
                m = compute_binary_metrics(
                    val_results[f'binary_true_k{k}'],
                    (val_results[f'probs_k{k}'] >= 0.5).astype(int),
                    val_results[f'probs_k{k}']
                )
                pr_aucs.append(m['pr_auc'])

            mean_pr_auc = float(np.mean(pr_aucs))
            epoch_time = time.time() - t0

            history.append({
                'epoch': epoch,
                'train_loss': train_metrics['loss'],
                'val_mean_pr_auc': round(mean_pr_auc, 4),
                'epoch_time_sec': round(epoch_time, 1)
            })

            if mean_pr_auc > best_val_score:
                best_val_score = mean_pr_auc
                best_weights = {k: v.cpu().clone() for k, v in self.model.state_dict().items()}
                patience_counter = 0
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    break

        if best_weights is not None:
            self.model.load_state_dict(best_weights)

        return {
            'best_val_pr_auc': best_val_score,
            'epochs_trained': len(history),
            'history': history
        }
