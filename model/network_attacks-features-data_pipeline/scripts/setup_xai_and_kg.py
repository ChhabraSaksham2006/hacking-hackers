import os
import json
import numpy as np
import pandas as pd

# 1. Write incident_intelligence.py
incident_intel_code = '''"""
incident_intelligence.py
========================
SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening

Generates automated SOC Incident Intelligence Cards by fusing:
1. Two-Stage Early Warning Alert & Lead Time
2. Explainable AI Feature Attribution & Temporal Saliency
3. MITRE ATT&CK Tactic, Technique, and Mitigation Playbook
"""

from __future__ import annotations
import os
import json
from typing import Dict, List, Tuple, Optional, Any

from src.xai.feature_attribution import PrecursorAttributionEngine
from src.knowledge_graph.mitre_attack_graph import MITREKnowledgeGraph


class IncidentIntelligenceGenerator:
    """
    Synthesizes forecasting alerts, XAI attributions, and MITRE graph knowledge
    into production-grade SOC Incident Intelligence Cards.
    """
    def __init__(self, feature_names: List[str]):
        self.xai_engine = PrecursorAttributionEngine(feature_names)
        self.kg_engine = MITREKnowledgeGraph()

    def generate_incident_card(
        self,
        incident_id: str,
        timestamp_str: str,
        lead_time_seconds: float,
        forecasting_confidence: float,
        trajectory_slope: float,
        predicted_attack_family: str,
        attributions: Any,      # (P=10, D=54)
        input_values: Any       # (P=10, D=54)
    ) -> Dict[str, Any]:
        """
        Creates an end-to-end actionable SOC card.
        """
        xai_summary = self.xai_engine.explain_precursor_window(
            attributions=attributions,
            input_values=input_values,
            top_k=5
        )
        
        mitre_mapping = self.kg_engine.get_attack_mapping(predicted_attack_family)
        
        urgency_level = "CRITICAL" if lead_time_seconds <= 10.0 else ("HIGH" if lead_time_seconds <= 20.0 else "ELEVATED")
        
        card = {
            "incident_id": incident_id,
            "timestamp": timestamp_str,
            "alert_status": "EARLY_WARNING_CONFIRMED",
            "urgency": urgency_level,
            "lead_time_seconds": round(lead_time_seconds, 1),
            "forecasting_confidence_pct": round(forecasting_confidence * 100.0, 2),
            "trajectory_slope": round(trajectory_slope, 4),
            
            "threat_classification": {
                "forecasted_attack_family": predicted_attack_family,
                "precursor_pattern_id": mitre_mapping["precursor_id"],
                "precursor_name": mitre_mapping["precursor_name"],
                "dominant_feature_group": xai_summary["dominant_feature_group"],
            },
            
            "mitre_attack_context": {
                "tactic_id": mitre_mapping["mitre_tactic_id"],
                "tactic_name": mitre_mapping["mitre_tactic_name"],
                "technique_id": mitre_mapping["mitre_technique_id"],
                "technique_name": mitre_mapping["mitre_technique_name"],
                "technique_description": mitre_mapping["technique_description"]
            },
            
            "xai_telemetry_evidence": {
                "group_attributions": xai_summary["group_attributions"],
                "top_salient_precursor_features": xai_summary["top_salient_features"]
            },
            
            "soc_defensive_playbook": {
                "recommended_mitigations": mitre_mapping["recommended_mitigations"],
                "automated_containment_ready": True
            }
        }
        
        return card
'''

os.makedirs('src/knowledge_graph', exist_ok=True)
with open('src/knowledge_graph/incident_intelligence.py', 'w', encoding='utf-8') as f:
    f.write(incident_intel_code.strip() + '\n')

# 2. Write __init__.py for knowledge_graph
kg_init_code = '''"""
Knowledge Graph package for SIH26153 Network Attack Forecasting.
"""

from src.knowledge_graph.mitre_attack_graph import MITREKnowledgeGraph, MITRE_KNOWLEDGE_BASE
from src.knowledge_graph.incident_intelligence import IncidentIntelligenceGenerator

__all__ = [
    "MITREKnowledgeGraph",
    "MITRE_KNOWLEDGE_BASE",
    "IncidentIntelligenceGenerator"
]
'''
with open('src/knowledge_graph/__init__.py', 'w', encoding='utf-8') as f:
    f.write(kg_init_code.strip() + '\n')

print('Knowledge Graph modules written successfully!')
