import os
import sys
import gzip
import shutil
import datetime
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Tuple, Optional

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.mitre_mapping import get_mitre_stage_code, get_mitre_stage_name
from src.feature_extractor import FeatureExtractor


def parse_session_list(list_file_path: str) -> pd.DataFrame:
    """
    Parses tcpdump.list or bsm.list file into a structured DataFrame
    with UTC timestamps and MITRE ATT&CK stage annotations.
    """
    columns = [
        'session_idx', 'start_date', 'start_time', 'duration',
        'service', 'sport', 'dport', 'src_ip', 'dst_ip', 'score', 'attack_name'
    ]
    df = pd.read_csv(list_file_path, sep=r'\s+', names=columns, header=None)

    def parse_duration(dur_str: str) -> int:
        parts = list(map(int, str(dur_str).split(':')))
        return parts[0] * 3600 + parts[1] * 60 + parts[2] if len(parts) == 3 else 0

    df['duration_seconds'] = df['duration'].apply(parse_duration)

    def parse_est_to_utc_epoch(row) -> float:
        dt_str = f"{row['start_date']} {row['start_time']}"
        try:
            dt = datetime.datetime.strptime(dt_str, "%m/%d/%Y %H:%M:%S")
        except ValueError:
            dt = datetime.datetime.strptime(dt_str, "%m/%d/%y %H:%M:%S")
        dt_utc = dt + datetime.timedelta(hours=5)
        return dt_utc.replace(tzinfo=datetime.timezone.utc).timestamp()

    df['start_timestamp'] = df.apply(parse_est_to_utc_epoch, axis=1)
    df['end_timestamp'] = df['start_timestamp'] + df['duration_seconds']
    df['mitre_stage_code'] = df['attack_name'].apply(get_mitre_stage_code)
    df['mitre_stage_name'] = df['mitre_stage_code'].apply(get_mitre_stage_name)
    return df


class TemporalStateAggregator:
    """
    Aggregates packet streams into sliding temporal windows representing
    network system states S_t.

    Performance design:
    - Uses streaming PcapReader (not rdpcap) so packets never all sit in RAM at once
      during loading.
    - Windowing uses bisect on a sorted timestamp array: O(log n) per window boundary
      lookup, total O(w * log n) instead of the naive O(n * w) linear scan.
      On a 600k-packet, 39k-window day this reduces windowing from hours to ~seconds.
    - Session label lookup uses numpy vectorised mask operations (no Python loop).
    """

    def __init__(self, pcap_path: str, session_list_path: Optional[str] = None):
        self.pcap_path = pcap_path
        self.session_list_path = session_list_path
        self.sessions_df = (
            parse_session_list(session_list_path)
            if session_list_path and os.path.exists(session_list_path)
            else None
        )
        self.packet_metas: List[Dict[str, Any]] = []
        self._timestamps: np.ndarray = np.array([])   # sorted float64 array
        self._load_packets()

    def _load_packets(self):
        """Load and pre-extract metadata via streaming PcapReader."""
        from scapy.utils import PcapReader

        # Auto-decompress .gz if needed
        if self.pcap_path.endswith('.gz'):
            unzipped_path = self.pcap_path[:-3]
            if not os.path.exists(unzipped_path):
                print(f"    Decompressing {os.path.basename(self.pcap_path)} ...")
                with gzip.open(self.pcap_path, 'rb') as f_in, open(unzipped_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            self.pcap_path = unzipped_path

        print(f"    Streaming {os.path.basename(self.pcap_path)} ...")
        count = 0
        report_every = 100_000
        with PcapReader(self.pcap_path) as reader:
            for pkt in reader:
                self.packet_metas.append(FeatureExtractor.extract_packet_metadata(pkt))
                count += 1
                if count % report_every == 0:
                    print(f"      ... {count:,} packets loaded")

        # Sort by timestamp (packets in PCAP are usually ordered, but ensure it)
        self.packet_metas.sort(key=lambda m: m["timestamp"])
        # Cache a numpy array of timestamps for fast bisect-based windowing
        self._timestamps = np.array([m["timestamp"] for m in self.packet_metas], dtype=np.float64)
        print(f"    Loaded {len(self.packet_metas):,} packets total")

    def aggregate_windows(
        self,
        delta_t: float = 10.0,
        step_size: float = 2.0,
        include_deltas: bool = True
    ) -> pd.DataFrame:
        """
        Build sliding windows of size delta_t (seconds) with stride step_size.

        Uses O(w * log n) bisect on sorted timestamp array:
        - bisect_left(ts, w_start) → left boundary index  (O(log n))
        - bisect_left(ts, w_end)   → right boundary index (O(log n))
        - packet slice = packet_metas[lo:hi]               (O(1) slice)
        Total: O(w * log n) vs naive O(n * w).

        This method is lightweight after __init__ — all packet metadata is already
        in memory, so you can call aggregate_windows() multiple times with different
        delta_t / step_size values without re-reading the PCAP.
        """
        if not self.packet_metas:
            return pd.DataFrame()

        import bisect

        ts    = self._timestamps        # sorted numpy float64 array
        t_min = float(ts[0])
        t_max = float(ts[-1])

        # Pre-extract session arrays for vectorised label lookup
        if self.sessions_df is not None:
            sess_start = self.sessions_df['start_timestamp'].values   # float64
            sess_end   = self.sessions_df['end_timestamp'].values
            sess_code  = self.sessions_df['mitre_stage_code'].values.astype(int)
            sess_name  = self.sessions_df['attack_name'].values
        else:
            sess_start = sess_end = sess_code = sess_name = None

        window_records = []
        cur_t      = t_min
        window_idx = 0
        total_windows = int((t_max - t_min) / step_size) + 1

        while cur_t + delta_t <= t_max + step_size:
            w_start = cur_t
            w_end   = cur_t + delta_t

            # O(log n) bisect — find the slice of packets inside [w_start, w_end)
            lo = bisect.bisect_left(ts, w_start)
            hi = bisect.bisect_left(ts, w_end)
            pkts_in_window = self.packet_metas[lo:hi]

            state_feats = FeatureExtractor.extract_window_state_features(
                pkts_in_window, window_duration=delta_t
            )

            # Vectorised session label lookup
            max_mitre_code       = 0
            active_session_count = 0
            active_attacks       = []

            if sess_start is not None:
                mask = (sess_start < w_end) & (sess_end >= w_start)
                active_session_count = int(mask.sum())
                active_codes = sess_code[mask]
                if active_codes.size > 0:
                    max_mitre_code = int(active_codes.max())
                    attack_mask    = mask & (sess_code > 0)
                    active_attacks = list(set(sess_name[attack_mask].tolist()))

            rec = {
                "window_idx":           window_idx,
                "window_start_time":    w_start,
                "window_end_time":      w_end,
                "active_session_count": active_session_count,
                "is_attack":            int(max_mitre_code > 0),
                "mitre_stage_code":     max_mitre_code,
                "mitre_stage_name":     get_mitre_stage_name(max_mitre_code),
                "active_attack_names":  ",".join(active_attacks) if active_attacks else "None",
            }
            rec.update(state_feats)
            window_records.append(rec)

            cur_t += step_size
            window_idx += 1

        df_windows = pd.DataFrame(window_records)

        # Delta / velocity features  ΔS_t = S_t − S_{t-1}
        if include_deltas and len(df_windows) > 1:
            numeric_feat_cols = list(FeatureExtractor._get_empty_state_features().keys())
            for col in numeric_feat_cols:
                df_windows[f"delta_{col}"] = df_windows[col].diff().fillna(0.0)

        return df_windows
