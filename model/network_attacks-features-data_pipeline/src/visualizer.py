"""
Visualization and Feature Reasoning Module

Generates feature distribution plots, correlation heatmaps, temporal timeline charts,
and provides domain-specific cybersecurity reasoning for feature importance.
"""

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from typing import List, Dict, Optional

# Structured domain reasoning dictionary explaining why each feature family aids prediction
FEATURE_REASONING: Dict[str, Dict[str, str]] = {
    "Volume & Rates": {
        "packet_rate": "Surges during aggressive scanning, DoS attempts, or bulk file exfiltration; drops during stealthy low-and-slow reconnaissance.",
        "byte_rate": "Exposes volumetric anomalies; large spikes in outbound byte rates indicate staging or exfiltration, whereas uniform byte rates appear in C2 beaconing.",
        "tcp_ratio": "Shifts between TCP (interactive sessions, exploits, scans) and UDP (DNS tunneling, amplification floods)."
    },
    "Connectivity & Scan Signatures": {
        "unique_dst_ports": "Direct indicator of vertical reconnaissance where an adversary probes numerous ports on a target host to map services.",
        "max_dst_ports_per_ip": "Differentiates normal client traffic (few ports like 80/443) from scanning tools (probes across ports 21, 22, 80, 445, 3389).",
        "port_entropy": "High entropy reflects randomized port scanning targeting ephemeral ranges; low entropy reflects focused targeting on standard services (e.g. port 22)."
    },
    "TCP Flags & Handshake Dynamics": {
        "syn_ratio": "A high proportion of SYN packets without subsequent ACKs indicates SYN flood attacks or half-open port scans (e.g. Nmap -sS).",
        "rst_ratio": "Closed ports respond with RST packets; a high RST ratio indicates an attacker probing unassigned ports or closed services.",
        "rst_to_syn_ratio": "Direct metric of failed connection attempts; normal traffic completes handshakes, whereas reconnaissance triggers abundant resets.",
        "handshake_completion_ratio": "Quantifies the ratio of completed 3-way handshakes to connection attempts. Drops near zero during network discovery."
    },
    "Reliability & Retransmissions": {
        "retransmission_count": "Abnormal retransmissions indicate server congestion, overloaded service buffers during brute-force, or network tampering.",
        "retransmission_rate": "Distinguishes normal packet loss from abnormal burst retries during exploitation."
    },
    "Payload & Packet Attributes": {
        "payload_mean": "Reconnaissance packets typically carry 0 payload (only TCP headers), whereas Initial Access (exploit payloads) and Lateral Movement have larger payload sizes.",
        "zero_payload_ratio": "High zero-payload ratio confirms control/probing packets dominate the window.",
        "win_mean": "TCP advertised window size variations reflect client OS stack footprints and buffer utilization during data transfers."
    },
    "Timing & Inter-Arrival Time (IAT)": {
        "iat_mean": "Very short IAT (milliseconds) indicates automated scripting/scanning; long IAT with near-zero variance indicates scheduled C2 beaconing.",
        "iat_std": "Uniform timing (low variance) reveals automated periodic bots/implants; high variance is typical of human interactive typing (e.g. SSH/Telnet)."
    },
    "Temporal Velocity / Deltas": {
        "delta_syn_count": "Captures the onset (derivative) of a scanning burst before the absolute count reaches static alert thresholds.",
        "delta_unique_dst_ports": "Identifies the exact moment an adversary transitions from single-host probing to broad internal exploration."
    }
}

def plot_feature_distributions(df: pd.DataFrame, key_features: Optional[List[str]] = None, save_path: Optional[str] = None) -> plt.Figure:
    """Plots distribution boxplots of key features grouped by MITRE ATT&CK stage."""
    if key_features is None:
        key_features = [
            "packet_rate", "unique_dst_ports", "syn_ratio", 
            "rst_to_syn_ratio", "payload_mean", "iat_mean"
        ]
        
    num_feats = len(key_features)
    cols = 3
    rows = (num_feats + cols - 1) // cols
    
    fig, axes = plt.subplots(rows, cols, figsize=(15, 4 * rows))
    axes = np.array(axes).flatten()
    
    stage_labels = {0: "Benign", 1: "Recon", 2: "Initial Access", 3: "Lateral Move"}
    
    for i, feat in enumerate(key_features):
        ax = axes[i]
        if feat in df.columns:
            plot_df = df.copy()
            plot_df['Stage'] = plot_df['mitre_stage_code'].map(stage_labels)
            
            # Log transform skewed features for clean visual comparison
            if feat in ["packet_rate", "byte_rate", "unique_dst_ports", "payload_mean", "iat_mean"]:
                plot_df[f"{feat}_log"] = np.log1p(plot_df[feat].clip(lower=0))
                sns.boxplot(data=plot_df, x="Stage", y=f"{feat}_log", ax=ax, palette="Set2")
                ax.set_ylabel(f"log1p({feat})")
            else:
                sns.boxplot(data=plot_df, x="Stage", y=feat, ax=ax, palette="Set2")
                ax.set_ylabel(feat)
                
            ax.set_title(f"Distribution: {feat}")
            ax.grid(True, linestyle="--", alpha=0.5)
        else:
            ax.set_visible(False)
            
    for j in range(i + 1, len(axes)):
        axes[j].set_visible(False)
        
    plt.tight_layout()
    if save_path:
        fig.savefig(save_path, dpi=300)
    return fig

def plot_feature_correlation(df: pd.DataFrame, key_features: Optional[List[str]] = None, save_path: Optional[str] = None) -> plt.Figure:
    """Plots heatmap of correlations between features and the target MITRE attack stage."""
    if key_features is None:
        key_features = [
            "mitre_stage_code", "is_attack", "packet_rate", "byte_rate",
            "unique_dst_ports", "max_dst_ports_per_ip", "port_entropy",
            "syn_ratio", "rst_ratio", "rst_to_syn_ratio", "handshake_completion_ratio",
            "retransmission_count", "payload_mean", "zero_payload_ratio",
            "iat_mean", "iat_std"
        ]
        
    corr_cols = [col for col in key_features if col in df.columns]
    corr_matrix = df[corr_cols].corr()
    
    fig, ax = plt.subplots(figsize=(12, 10))
    sns.heatmap(corr_matrix, annot=True, fmt=".2f", cmap="coolwarm", cbar=True, ax=ax, linewidths=0.5)
    ax.set_title("Feature Correlation Matrix with MITRE Stage", fontsize=14)
    plt.tight_layout()
    if save_path:
        fig.savefig(save_path, dpi=300)
    return fig

def plot_temporal_timeline(df: pd.DataFrame, save_path: Optional[str] = None) -> plt.Figure:
    """Plots temporal evolution of network traffic features alongside shaded MITRE stages."""
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(15, 10), sharex=True)
    
    time_rel = df["window_start_time"] - df["window_start_time"].min()
    
    # 1. Packet and Byte Activity
    ax1.plot(time_rel, df["packet_rate"], color="navy", label="Packet Rate (pkts/s)", lw=1.8)
    ax1.set_ylabel("Packets / sec", color="navy")
    ax1.grid(True, linestyle="--", alpha=0.5)
    ax1.set_title("Network Activity & Telemetry Progression Over Time", fontsize=14)
    
    # 2. Port and Scan Intensity
    ax2.plot(time_rel, df["unique_dst_ports"], color="darkorange", label="Unique Dst Ports", lw=1.8)
    ax2.plot(time_rel, df["max_dst_ports_per_ip"], color="red", linestyle=":", label="Max Ports / Host", lw=1.5)
    ax2.set_ylabel("Port Count", color="darkorange")
    ax2.legend(loc="upper right")
    ax2.grid(True, linestyle="--", alpha=0.5)
    
    # 3. TCP Flags Ratios
    ax3.plot(time_rel, df["syn_ratio"], color="crimson", label="SYN Ratio", lw=1.8)
    ax3.plot(time_rel, df["rst_ratio"], color="purple", label="RST Ratio", lw=1.8)
    ax3.plot(time_rel, df["handshake_completion_ratio"], color="forestgreen", label="Handshake Completion", lw=1.5)
    ax3.set_ylabel("Flag Ratios")
    ax3.set_xlabel("Elapsed Time (seconds)")
    ax3.legend(loc="upper right")
    ax3.grid(True, linestyle="--", alpha=0.5)
    
    # Shading attack periods
    stage_colors = {
        1: ("gold", "Reconnaissance"),
        2: ("tomato", "Initial Access"),
        3: ("darkred", "Lateral Movement / Exec")
    }
    
    for stage_code, (color, name) in stage_colors.items():
        stage_mask = df["mitre_stage_code"] == stage_code
        if stage_mask.any():
            for ax in [ax1, ax2, ax3]:
                ax.fill_between(time_rel, 0, 1, where=stage_mask, color=color, alpha=0.25, 
                                transform=ax.get_xaxis_transform())
                                
    plt.tight_layout()
    if save_path:
        fig.savefig(save_path, dpi=300)
    return fig
