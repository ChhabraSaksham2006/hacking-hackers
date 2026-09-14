"""
Level 2: Continuous Real-Time Streaming Inference Pipeline

Maintains a sliding in-memory packet buffer and continuous P=10 state history window.
Emits real-time state drift metrics, multi-horizon MITRE stage forecasts, and proactive cyber alerts.
Supports live network sniffing and accelerated PCAP playback replay.
"""

import os
import sys
import time
import json
import argparse
import collections
import numpy as np
from typing import Dict, Any, List, Optional, Callable

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.inference_engine import WorldModelInferenceEngine
from src.feature_extractor import FeatureExtractor
from src.mitre_mapping import STAGE_NAMES


class RealTimeStreamingInference:
    """
    Continuous stream processor that ingests live packets or replay streams,
    maintains a rolling state buffer, and dispatches real-time attack forecasts.
    """
    def __init__(
        self,
        delta_t: float = 10.0,
        step_size: float = 2.0,
        lookback: int = 10,
        alert_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        output_stream_jsonl: Optional[str] = None
    ):
        self.delta_t = delta_t
        self.step_size = step_size
        self.lookback = lookback
        self.alert_callback = alert_callback
        self.output_stream_jsonl = output_stream_jsonl

        self.engine = WorldModelInferenceEngine()
        self.feature_cols = self.engine.feature_cols

        # In-memory rolling buffers
        self.packet_meta_buffer = []  # metadata of packets within current window horizon
        self.state_history = collections.deque(maxlen=lookback)  # rolling P state vectors
        self.window_count = 0
        self.current_window_start_time = None

        if self.output_stream_jsonl:
            os.makedirs(os.path.dirname(os.path.abspath(self.output_stream_jsonl)), exist_ok=True)
            # Clear previous log file
            open(self.output_stream_jsonl, "w").close()

    def ingest_packet(self, pkt, pkt_timestamp: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """
        Ingests a single packet into the streaming engine.
        When window step boundary is reached, triggers World Model prediction.
        """
        meta = FeatureExtractor.extract_packet_metadata(pkt)
        if pkt_timestamp is not None:
            meta["timestamp"] = pkt_timestamp
            
        ts = meta["timestamp"]
        self.packet_meta_buffer.append(meta)

        if self.current_window_start_time is None:
            self.current_window_start_time = ts

        # Check if a step boundary has elapsed
        if ts >= self.current_window_start_time + self.step_size:
            # Purge packets older than delta_t
            cutoff = ts - self.delta_t
            self.packet_meta_buffer = [m for m in self.packet_meta_buffer if m["timestamp"] >= cutoff]

            # 1. Extract continuous 47-D State Vector for current window
            features_dict = FeatureExtractor.extract_window_state_features(self.packet_meta_buffer, window_duration=self.delta_t)
            state_vector = np.array([features_dict.get(c, 0.0) for c in self.feature_cols], dtype=np.float32)
            self.state_history.append(state_vector)
            self.window_count += 1
            self.current_window_start_time = ts

            # 2. If lookback buffer is full (P=10), execute World Model prediction
            if len(self.state_history) == self.lookback:
                history_arr = np.array(list(self.state_history), dtype=np.float32)
                pred_result = self.engine.predict_step(history_arr)

                # Compute state drift between current state and predicted next state
                curr_dict = {col: float(val) for col, val in zip(self.feature_cols, state_vector)}
                pred_dict = pred_result["predicted_telemetry_summary"]

                drift_metrics = {
                    "pkt_rate_drift": f"{pred_dict['packet_rate'] - curr_dict['packet_rate']:+.1f} pkts/s",
                    "syn_ratio_drift": f"{pred_dict['syn_ratio'] - curr_dict['syn_ratio']:+.2f}",
                    "auth_ratio_drift": f"{pred_dict['auth_packet_ratio'] - curr_dict['auth_packet_ratio']:+.2f}"
                }

                alert_event = {
                    "timestamp": ts,
                    "window_index": self.window_count,
                    "event_type": "REAL_TIME_WORLD_MODEL_FORECAST",
                    "predicted_stage_code": pred_result["predicted_stage_code"],
                    "predicted_stage_name": pred_result["predicted_stage_name"],
                    "confidence": pred_result["confidence"],
                    "risk_score": pred_result["risk_score"],
                    "alert_level": pred_result["alert_level"],
                    "current_state_telemetry": {
                        "packet_rate": curr_dict.get("packet_rate", 0.0),
                        "byte_rate": curr_dict.get("byte_rate", 0.0),
                        "syn_ratio": curr_dict.get("syn_ratio", 0.0),
                        "auth_packet_ratio": curr_dict.get("auth_packet_ratio", 0.0)
                    },
                    "predicted_next_state_telemetry": pred_dict,
                    "state_drift_delta": drift_metrics
                }

                # Trigger alert callback
                if self.alert_callback:
                    self.alert_callback(alert_event)

                # Append to JSONL stream
                if self.output_stream_jsonl:
                    with open(self.output_stream_jsonl, "a") as f:
                        f.write(json.dumps(alert_event) + "\n")

                return alert_event

        return None

    def run_pcap_playback_stream(
        self,
        pcap_path: str,
        speed: float = 10.0,
        max_duration_sec: Optional[float] = None
    ):
        """
        Simulates live real-time packet streaming from a recorded PCAP file.
        """
        import scapy.all as scapy
        print(f"\n{'='*70}")
        print(f"  LEVEL 2 REAL-TIME STREAMING INFERENCE: {os.path.basename(pcap_path)}")
        print(f"  Playback Speed: {speed:.1f}x | Window: {self.delta_t}s | Step: {self.step_size}s")
        print(f"{'='*70}\n")

        reader = scapy.PcapReader(pcap_path)
        first_pkt_time = None
        stream_start_wall_time = time.time()
        pkt_count = 0
        events_emitted = 0

        for pkt in reader:
            if not hasattr(pkt, 'time'):
                continue
            pkt_ts = float(pkt.time)
            if first_pkt_time is None:
                first_pkt_time = pkt_ts

            simulated_elapsed = pkt_ts - first_pkt_time
            if max_duration_sec and simulated_elapsed > max_duration_sec:
                print(f"\n[Stream] Reached maximum simulated duration ({max_duration_sec}s).")
                break

            # Throttle playback to match simulated speed
            if speed > 0.0:
                expected_wall_elapsed = simulated_elapsed / speed
                actual_wall_elapsed = time.time() - stream_start_wall_time
                sleep_sec = expected_wall_elapsed - actual_wall_elapsed
                if sleep_sec > 0.001:
                    time.sleep(min(sleep_sec, 0.05))

            event = self.ingest_packet(pkt, pkt_timestamp=pkt_ts)
            pkt_count += 1

            if event:
                events_emitted += 1
                stage = event["predicted_stage_name"]
                risk = event["risk_score"]
                lvl = event["alert_level"]
                t_sim = simulated_elapsed
                drift = event["state_drift_delta"]
                
                # Format visual terminal alert
                badge = f"[{lvl}]"
                print(f"[T={t_sim:>6.1f}s | Win #{event['window_index']:>4}] {badge:<10} Forecast: {stage:<35} | Conf: {event['confidence']*100:>5.1f}% | Risk: {risk:.2f} | Drift: SYN {drift['syn_ratio_drift']}, Auth {drift['auth_ratio_drift']}")

        reader.close()
        print(f"\nStream Playback Complete. Packets Streamed: {pkt_count:,} | Forecast Events: {events_emitted}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Level 2 Continuous Streaming Inference")
    parser.add_argument("--source", required=True, help="Path to PCAP file for simulated live playback")
    parser.add_argument("--speed", type=float, default=20.0, help="Playback speed multiplier (default: 20x)")
    parser.add_argument("--duration", type=float, default=120.0, help="Max simulated duration in seconds")
    parser.add_argument("--output_jsonl", default="results/live_stream_alerts.jsonl", help="Output JSONL stream log")
    args = parser.parse_args()

    streamer = RealTimeStreamingInference(
        delta_t=10.0,
        step_size=2.0,
        lookback=10,
        output_stream_jsonl=args.output_jsonl
    )
    streamer.run_pcap_playback_stream(
        pcap_path=args.source,
        speed=args.speed,
        max_duration_sec=args.duration
    )
