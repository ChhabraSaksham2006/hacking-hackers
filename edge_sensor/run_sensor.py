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

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure package path is resolved
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import queue
import threading
from typing import Optional

from core.packet_ingress import PacketIngress
from core.flow_tracker import FlowTracker
from core.feature_extractor import FeatureExtractor
from core.edge_sentinel import EdgeSentinel
from core.neural_evaluator import NeuralEvaluator
from core.telemetry_dispatcher import TelemetryDispatcher
from core.live_gateway import LiveEdgeGateway, get_all_host_ips
from demo.traffic_generator import generate_synthetic_traffic_stream
from demo.visualizer import TerminalVisualizer


def check_raw_socket_permission() -> bool:
    """Checks whether the current process has administrator/root privilege for raw packet capture."""
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    elif hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return False


def run_pipeline(
    mode: str = "demo",
    pcap_file: str = "",
    window_sec: float = 2.0,
    speed: float = 2.0,
    upstream_url: str = "",
    api_key: str = "",
    kafka_brokers: str = "",
    kafka_topic: str = "aegis.telemetry.raw",
    model_url: str = "",
    enable_heuristics: bool = False,
    output_file: str = "telemetry_edge.ndjson",
    ingress_log: str = "live_ingress.log",
    sensor_id: str = "edge-probe-vanguard-01",
    headless: bool = False,
    duration: float = 30.0,
    port: int = 8888,
    with_baseline: bool = True,
    interface: str = "",
):
    print(f"[*] Initializing Aegis Vantage Edge Sensor Agent [{sensor_id}]...")
    display_mode = f"LIVE GATEWAY (Port {port})" if mode == "live" else f"PASSIVE TAP ({interface or 'auto'})" if mode == "tap" else f"{mode.upper()} (Speed: {speed}x)"
    print(f"[*] Operating Mode: {display_mode} | Observation Window: {window_sec}s")

    # 1. Initialize Pipeline Stages
    flow_tracker = FlowTracker(idle_timeout=60.0)
    feature_extractor = FeatureExtractor(window_seconds=window_sec)
    edge_sentinel = EdgeSentinel(enable_heuristics=enable_heuristics)
    neural_evaluator = NeuralEvaluator(model_url=model_url if model_url else None)
    dispatcher = TelemetryDispatcher(
        sensor_id=sensor_id,
        upstream_url=upstream_url if upstream_url else None,
        api_key=api_key if api_key else None,
        kafka_brokers=kafka_brokers if kafka_brokers else None,
        kafka_topic=kafka_topic,
        ndjson_path=output_file if output_file else None,
    )
    visualizer = TerminalVisualizer(sensor_id=sensor_id, mode=display_mode)

    gateway: Optional[LiveEdgeGateway] = None
    gateway_url: Optional[str] = None
    baseline_stream = None
    tap_stop_event: Optional[threading.Event] = None
    tap_thread: Optional[threading.Thread] = None

    # 2. Select Ingress Packet Source
    if mode in ("live", "tap"):
        if mode == "tap" and not check_raw_socket_permission():
            print("\n[!] Access Denied: Windows raw packet interface sniffing requires Administrator privileges.")
            print("[*] To sniff raw interface on Windows: Open PowerShell as Administrator and run the command.")
            print("[*] Alternatively: Use '--mode live' for interactive user gateway without elevated privileges.\n")
            return 1

        gateway = LiveEdgeGateway(host="0.0.0.0", port=port, log_path=ingress_log, sensor_id=sensor_id)
        gateway.start()
        gateway_url = f"http://{gateway.lan_ip}:{gateway.port}"

        print("\n" + "=" * 68)
        title_suffix = f"Passive Physical Interface Tap ({interface or 'auto'})" if mode == "tap" else f"Interactive Device Gateway (Port {port})"
        print(f"[*] Live Edge Ingress Gateway Active: {title_suffix}")
        print("[*] Connect any Phone or Laptop via any of these URLs:")
        for label, ip in gateway.all_ips:
            print(f"    - {label:<25s} -> http://{ip}:{port}")
        print("    - Public Internet (Anywhere)   -> Run: npx localtunnel --port " + str(port))
        print("=" * 68 + "\n")

        if mode == "tap":
            tap_stop_event = threading.Event()

            def tap_worker():
                try:
                    for pkt in PacketIngress.open_live_interface(
                        interface=interface if interface else None, stop_event=tap_stop_event
                    ):
                        if tap_stop_event.is_set():
                            break
                        gateway.packet_queue.put(pkt)
                except Exception:
                    pass

            tap_thread = threading.Thread(target=tap_worker, daemon=True)
            tap_thread.start()
        elif with_baseline:
            baseline_stream = generate_synthetic_traffic_stream(duration_seconds=999999.0, speed_multiplier=1.0)
    elif mode == "pcap":
        if not pcap_file or not os.path.exists(pcap_file):
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
        if mode in ("live", "tap"):
            last_baseline_time = time.time()
            while True:
                # 3a. Drain any packets received from live external devices / tap sniffer
                pkts_to_process = []
                try:
                    while True:
                        pkts_to_process.append(gateway.packet_queue.get_nowait())
                except queue.Empty:
                    pass

                # 3b. In live mode only: if no external packets and ambient baseline is active, pull 1 frame
                now = time.time()
                if mode == "live" and not pkts_to_process and baseline_stream and (now - last_baseline_time) >= 0.15:
                    try:
                        pkts_to_process.append(next(baseline_stream))
                        last_baseline_time = now
                    except StopIteration:
                        baseline_stream = generate_synthetic_traffic_stream(duration_seconds=999999.0, speed_multiplier=1.0)

                # If duration limit reached in live mode (if specified > 0)
                if duration > 0 and (now - start_time) >= duration:
                    break

                for packet in pkts_to_process:
                    total_packets += 1
                    flow = flow_tracker.update(packet)
                    window = feature_extractor.add_packet(packet, flow)
                    if window is not None:
                        # 1. Evaluate via Neural Cyber World Model Ensemble
                        pred = neural_evaluator.evaluate(window)
                        alerts = list(pred.alerts)
                        if enable_heuristics:
                            alerts.extend(edge_sentinel.evaluate(window))

                        if alerts:
                            total_alerts += len(alerts)
                        dispatcher.dispatch(window, alerts, pred)
                        visualizer.update_window(window, alerts)

                        # 2. Update live mobile prediction dashboard directly from neural model output
                        gateway.update_telemetry(
                            window, alerts, pred.calibrated_probability, pred.stage, pred.risk_level
                        )

                    visualizer.update_packet(packet)

                # Render UI frame
                if not headless and (now - last_render_time) >= 0.08:
                    active_flows = flow_tracker.get_active_flows()
                    curr_ts = time.time()
                    elapsed_in_win = curr_ts - (feature_extractor.window_start_time or curr_ts)
                    progress = max(0.0, min(1.0, elapsed_in_win / window_sec))
                    visualizer.render(
                        active_flows=active_flows,
                        current_progress=progress,
                        gateway_url=gateway_url,
                        connected_devices=gateway.get_connected_devices() if gateway else None,
                        recent_logs=gateway.get_recent_logs() if gateway else None,
                    )
                    last_render_time = now

                if not pkts_to_process:
                    time.sleep(0.02)

        else:
            for packet in packet_generator:
                total_packets += 1
                flow = flow_tracker.update(packet)
                window = feature_extractor.add_packet(packet, flow)

                if window is not None:
                    pred = neural_evaluator.evaluate(window)
                    alerts = list(pred.alerts)
                    if enable_heuristics:
                        alerts.extend(edge_sentinel.evaluate(window))

                    if alerts:
                        total_alerts += len(alerts)

                    dispatcher.dispatch(window, alerts, pred)
                    visualizer.update_window(window, alerts)

                    if headless:
                        print(
                            f"[WINDOW #{window.window_idx:03d}] Pkts: {window.packet_count:4d} | "
                            f"Bytes: {window.byte_count:7d} | Flows: {window.flow_count:3d} | "
                            f"Entropy: {window.feature_dict['dst_port_entropy']:4.2f} | "
                            f"Stage: {pred.stage} ({pred.calibrated_probability*100:.1f}%) | "
                            f"Alerts: {len(alerts)}"
                        )

                visualizer.update_packet(packet)

                now = time.time()
                if not headless and (now - last_render_time) >= 0.08:
                    active_flows = flow_tracker.get_active_flows()
                    elapsed_in_win = packet.timestamp - (feature_extractor.window_start_time or packet.timestamp)
                    progress = max(0.0, min(1.0, elapsed_in_win / window_sec))
                    visualizer.render(active_flows=active_flows, current_progress=progress)
                    last_render_time = now

        # Flush final partial window if any
        if feature_extractor.current_packets:
            final_window = feature_extractor.flush()
            pred = neural_evaluator.evaluate(final_window)
            final_alerts = list(pred.alerts)
            if enable_heuristics:
                final_alerts.extend(edge_sentinel.evaluate(final_window))
            dispatcher.dispatch(final_window, final_alerts, pred)
            visualizer.update_window(final_window, final_alerts)

    except KeyboardInterrupt:
        print("\n[*] Detaching edge sensor agent on user interrupt...")

    finally:
        if tap_stop_event:
            tap_stop_event.set()
        if gateway:
            gateway.stop()
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
        if mode in ("live", "tap"):
            print(f"    - Ingress Log Sink:     {os.path.abspath(ingress_log)}")
        print(f"{'=' * 65}")

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Aegis Vantage Distributed Edge Sensor Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["live", "tap", "demo", "pcap", "headless"],
        default="live",
        help="Sensor operating mode: 'live' (interactive mobile/LAN device gateway), 'tap' (passive live network interface sniffer), 'demo' (synthetic traffic visualizer), 'pcap' (binary capture replay), 'headless' (NDJSON stream)",
    )
    parser.add_argument("--interface", type=str, default=os.environ.get("AEGIS_INTERFACE", ""), help="Network interface name for live passive tap (e.g., 'eth0', 'enp3s0')")
    parser.add_argument("--headless", action="store_true", help="Run in headless daemon mode without terminal visualizer")
    parser.add_argument("--file", type=str, default="", help="Path to input .pcap file for pcap replay mode")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8888")), help="Port for live external device ingress portal (default: 8888)")
    parser.add_argument("--no-baseline", action="store_true", help="Disable ambient background enterprise baseline traffic in live mode")
    parser.add_argument("--window", type=float, default=2.0, help="Temporal observation window in seconds (default 2.0)")
    parser.add_argument("--speed", type=float, default=2.5, help="Replay speed multiplier (1.0 = realtime, 2.5 = 2.5x faster, 0 = max)")
    parser.add_argument("--upstream", type=str, default=os.environ.get("AEGIS_UPSTREAM_URL", ""), help="Upstream Aegis Vantage ingestion endpoint URL (e.g. 'http://localhost:5000/api/sensors/telemetry')")
    parser.add_argument("--api-key", type=str, default=os.environ.get("AEGIS_API_KEY", ""), help="Aegis Vantage organization sensor API key (av_sec_...)")
    parser.add_argument("--kafka-brokers", type=str, default=os.environ.get("AEGIS_KAFKA_BROKERS", ""), help="Kafka bootstrap broker addresses (e.g. 'localhost:9092') for direct message broker dispatch")
    parser.add_argument("--kafka-topic", type=str, default=os.environ.get("AEGIS_KAFKA_TOPIC", "aegis.telemetry.raw"), help="Kafka destination topic (default: 'aegis.telemetry.raw')")
    parser.add_argument("--model-url", type=str, default=os.environ.get("AEGIS_MODEL_URL", ""), help="Remote HTTP URL for Cyber World Model service (e.g. 'http://localhost:8000/predict'). Defaults to in-process PyTorch model.")
    parser.add_argument("--heuristics", action="store_true", help="Enable legacy rule-based heuristic alerts alongside neural model (default: False)")
    parser.add_argument("--output", type=str, default="telemetry_edge.ndjson", help="Path to local telemetry log file")
    parser.add_argument("--ingress-log", type=str, default="live_ingress.log", help="Path to structured live ingress verification log")
    parser.add_argument("--sensor-id", type=str, default=os.environ.get("AEGIS_SENSOR_ID", "edge-sensor-alpha-01"), help="Sensor agent identifier")
    parser.add_argument("--duration", type=float, default=0.0, help="Run duration in seconds (0 = run indefinitely until Ctrl+C)")

    args = parser.parse_args()

    is_headless = args.mode == "headless" or args.headless
    actual_mode = "demo" if args.mode == "headless" and not args.file else ("pcap" if args.file else args.mode)
    
    # If duration wasn't explicitly passed and running in demo mode, set sensible 25s default
    duration = args.duration
    if duration == 0.0 and actual_mode == "demo":
        duration = 25.0

    return run_pipeline(
        mode=actual_mode,
        pcap_file=args.file,
        window_sec=args.window,
        speed=args.speed,
        upstream_url=args.upstream,
        api_key=args.api_key,
        kafka_brokers=args.kafka_brokers,
        kafka_topic=args.kafka_topic,
        model_url=args.model_url,
        enable_heuristics=args.heuristics,
        output_file=args.output,
        ingress_log=args.ingress_log,
        sensor_id=args.sensor_id,
        headless=is_headless,
        duration=duration,
        port=args.port,
        with_baseline=not args.no_baseline,
        interface=args.interface,
    )


if __name__ == "__main__":
    sys.exit(main())
