#!/usr/bin/env python3
"""
Aegis Vantage — Distributed Edge Sensor Agent
High-performance, lightweight network edge probe for real-time packet ingestion,
flow tracking, 54-D feature extraction, and edge heuristic triage.

Usage:
    python run_sensor.py --mode demo                  # Run synthetic multi-stage demonstration
    python run_sensor.py --mode pcap --file <path>    # Ingest and process a real binary PCAP capture
    python run_sensor.py --mode headless              # Headless daemon streaming telemetry to NDJSON
"""

import argparse
import os
import sys
import time

# Ensure package path is resolved
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from core.packet_ingress import PacketIngress
from core.flow_tracker import FlowTracker
from core.feature_extractor import FeatureExtractor
from core.edge_sentinel import EdgeSentinel
from core.telemetry_dispatcher import TelemetryDispatcher
from demo.traffic_generator import generate_synthetic_traffic_stream
from demo.visualizer import TerminalVisualizer


def run_pipeline(
    mode: str = "demo",
    pcap_file: str = "",
    window_sec: float = 2.0,
    speed: float = 2.0,
    upstream_url: str = "",
    output_file: str = "telemetry_edge.ndjson",
    sensor_id: str = "edge-probe-vanguard-01",
    headless: bool = False,
    duration: float = 30.0,
):
    print(f"[*] Initializing Aegis Vantage Edge Sensor Agent [{sensor_id}]...")
    print(f"[*] Operating Mode: {mode.upper()} | Observation Window: {window_sec}s | Replay Speed: {speed}x")

    # 1. Initialize Pipeline Stages
    flow_tracker = FlowTracker(idle_timeout=60.0)
    feature_extractor = FeatureExtractor(window_seconds=window_sec)
    edge_sentinel = EdgeSentinel()
    dispatcher = TelemetryDispatcher(
        sensor_id=sensor_id,
        upstream_url=upstream_url if upstream_url else None,
        ndjson_path=output_file if output_file else None,
    )
    visualizer = TerminalVisualizer(sensor_id=sensor_id, mode=f"{mode.upper()} (Speed: {speed}x)")

    # 2. Select Ingress Packet Source
    if mode == "pcap":
        if not pcap_file or not os.path.exists(pcap_file):
            # Try default sample captures if relative
            candidates = [
                pcap_file,
                os.path.join(REPO_ROOT, pcap_file),
                os.path.join(REPO_ROOT, "sample_captures", "sample_2_ransomware_eternalblue_smb.pcap"),
            ]
            found = None
            for c in candidates:
                if c and os.path.exists(c):
                    found = c
                    break
            if not found:
                print(f"[!] Error: PCAP file not found: {pcap_file}")
                return 1
            pcap_file = found

        print(f"[*] Ingress Source: libpcap dump -> {pcap_file}")
        packet_generator = PacketIngress.stream_pcap_paced(pcap_file, speed_multiplier=speed)
    else:
        print(f"[*] Ingress Source: Synthetic Multi-Stage Enterprise Traffic Generator")
        packet_generator = generate_synthetic_traffic_stream(duration_seconds=duration, speed_multiplier=speed)

    # 3. Main Streaming Loop
    last_render_time = time.time()
    start_time = time.time()
    total_packets = 0
    total_alerts = 0

    try:
        for packet in packet_generator:
            total_packets += 1

            # Stage 2: Stateful Flow Tracking
            flow = flow_tracker.update(packet)

            # Stage 3: Temporal Windowing & 54-D State Vector Extraction
            window = feature_extractor.add_packet(packet, flow)

            # If 2.0s window ticked
            if window is not None:
                # Stage 4 & 5: Edge Sentinel Local Triage & Dispatch
                alerts = edge_sentinel.evaluate(window)
                if alerts:
                    total_alerts += len(alerts)

                dispatcher.dispatch(window, alerts)
                visualizer.update_window(window, alerts)

                if headless:
                    print(
                        f"[WINDOW #{window.window_idx:03d}] Pkts: {window.packet_count:4d} | "
                        f"Bytes: {window.byte_count:7d} | Flows: {window.flow_count:3d} | "
                        f"Entropy: {window.feature_dict['dst_port_entropy']:4.2f} | "
                        f"AuthRatio: {window.feature_dict['auth_port_ratio']*100:4.1f}% | "
                        f"Alerts: {len(alerts)}"
                    )

            visualizer.update_packet(packet)

            # Render UI frame (every ~80ms to prevent terminal stutter)
            now = time.time()
            if not headless and (now - last_render_time) >= 0.08:
                active_flows = flow_tracker.get_active_flows()
                # Compute fraction of current 2.0s window
                elapsed_in_win = packet.timestamp - (feature_extractor.window_start_time or packet.timestamp)
                progress = max(0.0, min(1.0, elapsed_in_win / window_sec))
                visualizer.render(active_flows=active_flows, current_progress=progress)
                last_render_time = now

        # Flush final partial window if any
        if feature_extractor.current_packets:
            final_window = feature_extractor.flush()
            final_alerts = edge_sentinel.evaluate(final_window)
            dispatcher.dispatch(final_window, final_alerts)
            visualizer.update_window(final_window, final_alerts)

    except KeyboardInterrupt:
        print("\n[*] Detaching edge sensor agent on user interrupt...")

    finally:
        dispatcher.close()
        total_time = time.time() - start_time
        print(f"\n{'=' * 65}")
        print(f"[*] Edge Sensor Agent Session Summary:")
        print(f"    - Execution Time:       {total_time:.2f}s")
        print(f"    - Packets Processed:    {total_packets}")
        print(f"    - Cumulative Flows:     {flow_tracker.flow_count_cumulative}")
        print(f"    - Windows Dispatched:   {feature_extractor.window_idx}")
        print(f"    - Triage Alerts Raised: {total_alerts}")
        print(f"    - Telemetry Log Sink:   {os.path.abspath(output_file) if output_file else 'None'}")
        print(f"{'=' * 65}")

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Aegis Vantage Distributed Edge Sensor Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["demo", "pcap", "headless"],
        default="demo",
        help="Sensor operating mode: 'demo' (synthetic traffic visualizer), 'pcap' (binary capture replay), 'headless' (NDJSON stream)",
    )
    parser.add_argument("--headless", action="store_true", help="Run in headless daemon mode without terminal visualizer")
    parser.add_argument("--file", type=str, default="", help="Path to input .pcap file for pcap replay mode")
    parser.add_argument("--window", type=float, default=2.0, help="Temporal observation window in seconds (default 2.0)")
    parser.add_argument("--speed", type=float, default=2.5, help="Replay speed multiplier (1.0 = realtime, 2.5 = 2.5x faster, 0 = max)")
    parser.add_argument("--upstream", type=str, default="", help="Upstream Aegis Vantage ingestion endpoint URL")
    parser.add_argument("--output", type=str, default="telemetry_edge.ndjson", help="Path to local telemetry log file")
    parser.add_argument("--sensor-id", type=str, default="edge-sensor-alpha-01", help="Sensor agent identifier")
    parser.add_argument("--duration", type=float, default=25.0, help="Demo run duration in seconds")

    args = parser.parse_args()

    is_headless = args.mode == "headless" or args.headless
    actual_mode = "demo" if args.mode == "headless" and not args.file else ("pcap" if args.file else args.mode)
    return run_pipeline(
        mode=actual_mode,
        pcap_file=args.file,
        window_sec=args.window,
        speed=args.speed,
        upstream_url=args.upstream,
        output_file=args.output,
        sensor_id=args.sensor_id,
        headless=is_headless,
        duration=args.duration,
    )


if __name__ == "__main__":
    sys.exit(main())
