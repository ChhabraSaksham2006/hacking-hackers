"""
Telemetry Dispatcher
Formats, queues, and transmits edge telemetry frames upstream to the Flow Drishti backend
or local telemetry sinks (JSON/NDJSON).
"""

import json
import os
import queue
import threading
import time
import urllib.request
import urllib.error
from dataclasses import asdict
from typing import Dict, List, Optional, Any
from .feature_extractor import TemporalWindow
from .edge_sentinel import TriageAlert


class TelemetryDispatcher:
    """
    Asynchronous telemetry dispatcher for edge sensors.
    Queues windows and alerts and streams them upstream without blocking packet capture.
    """

    def __init__(
        self,
        sensor_id: str = "edge-sensor-01",
        upstream_url: Optional[str] = None,
        api_key: Optional[str] = None,
        kafka_brokers: Optional[str] = None,
        kafka_topic: str = "aegis.telemetry.raw",
        ndjson_path: Optional[str] = None,
        max_queue_size: int = 1000,
    ):
        self.sensor_id = sensor_id
        self.upstream_url = upstream_url
        self.api_key = api_key
        self.kafka_brokers = kafka_brokers
        self.kafka_topic = kafka_topic
        self.ndjson_path = ndjson_path
        self.dispatch_queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self.running = True
        self.frames_dispatched = 0
        self.dispatch_errors = 0

        # Optional Direct Kafka Producer
        self._kafka_producer = None
        if self.kafka_brokers:
            try:
                from kafka import KafkaProducer  # type: ignore
                self._kafka_producer = KafkaProducer(
                    bootstrap_servers=[b.strip() for b in self.kafka_brokers.split(",") if b.strip()],
                    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                    key_serializer=lambda k: k.encode("utf-8") if isinstance(k, str) else k,
                    request_timeout_ms=3000,
                )
                print(f"📡 [Edge Sensor] Direct Kafka producer connected to {self.kafka_brokers}")
            except ImportError:
                print("ℹ️ [Edge Sensor] kafka-python not installed for direct broker dispatch. Using HTTP upstream.")
            except Exception as e:
                print(f"⚠️ [Edge Sensor] Kafka broker connection warning: {e}. Falling back to HTTP.")

        # Background worker thread
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()

    def dispatch(
        self,
        window: TemporalWindow,
        alerts: Optional[List[TriageAlert]] = None,
        prediction: Optional[Any] = None,
    ):
        """Pushes a temporal window frame into the dispatch queue."""
        frame = {
            "sensor_id": self.sensor_id,
            "window_idx": window.window_idx,
            "timestamp_start": window.timestamp_start,
            "timestamp_end": window.timestamp_end,
            "packet_count": window.packet_count,
            "byte_count": window.byte_count,
            "flow_count": window.flow_count,
            "features_54": window.vector_54,
            "top_flows": window.top_flows,
            "alerts": [asdict(a) for a in alerts] if alerts else [],
            "dispatched_at": time.time(),
        }

        if prediction is not None:
            if hasattr(prediction, "calibrated_probability"):
                frame["calibrated_probability"] = prediction.calibrated_probability
            if hasattr(prediction, "probability"):
                frame["probability"] = prediction.probability
            if hasattr(prediction, "stage"):
                frame["stage"] = prediction.stage
            if hasattr(prediction, "risk_level"):
                frame["risk_level"] = prediction.risk_level
            if hasattr(prediction, "confidence"):
                frame["confidence"] = prediction.confidence

        try:
            self.dispatch_queue.put_nowait(frame)
        except queue.Full:
            self.dispatch_errors += 1

    def _worker_loop(self):
        """Background worker consuming frames and writing/sending them."""
        while self.running:
            try:
                frame = self.dispatch_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                # 1. Write to local NDJSON file if specified
                if self.ndjson_path:
                    os.makedirs(os.path.dirname(os.path.abspath(self.ndjson_path)), exist_ok=True)
                    with open(self.ndjson_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(frame) + "\n")

                # 2. Transmit directly to Kafka if configured
                if self._kafka_producer is not None:
                    self._kafka_producer.send(
                        self.kafka_topic,
                        key=self.api_key or self.sensor_id,
                        value=frame,
                    )

                # 3. Transmit to remote upstream HTTP endpoint if configured
                if self.upstream_url:
                    data = json.dumps(frame).encode("utf-8")
                    headers = {
                        "Content-Type": "application/json",
                        "User-Agent": f"AegisEdge/{self.sensor_id}",
                    }
                    if self.api_key:
                        headers["x-sensor-key"] = self.api_key
                        headers["Authorization"] = f"Bearer {self.api_key}"

                    req = urllib.request.Request(
                        self.upstream_url,
                        data=data,
                        headers=headers,
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=3.0) as resp:
                        pass

                self.frames_dispatched += 1
            except Exception:
                self.dispatch_errors += 1
            finally:
                self.dispatch_queue.task_done()

    def close(self):
        """Flushes remaining frames and shuts down."""
        try:
            self.dispatch_queue.join()
        except Exception:
            pass
        if self._kafka_producer is not None:
            try:
                self._kafka_producer.flush(timeout=2.0)
                self._kafka_producer.close(timeout=2.0)
            except Exception:
                pass
        self.running = False
        if self.worker_thread.is_alive():
            self.worker_thread.join(timeout=2.0)
