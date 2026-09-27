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
from typing import Dict, List, Optional
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
        ndjson_path: Optional[str] = None,
        max_queue_size: int = 1000,
    ):
        self.sensor_id = sensor_id
        self.upstream_url = upstream_url
        self.ndjson_path = ndjson_path
        self.dispatch_queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self.running = True
        self.frames_dispatched = 0
        self.dispatch_errors = 0

        # Background worker thread
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()

    def dispatch(self, window: TemporalWindow, alerts: Optional[List[TriageAlert]] = None):
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

                # 2. Transmit to remote upstream HTTP endpoint if configured
                if self.upstream_url:
                    data = json.dumps(frame).encode("utf-8")
                    req = urllib.request.Request(
                        self.upstream_url,
                        data=data,
                        headers={"Content-Type": "application/json", "User-Agent": f"AegisEdge/{self.sensor_id}"},
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
        self.running = False
        if self.worker_thread.is_alive():
            self.worker_thread.join(timeout=2.0)
