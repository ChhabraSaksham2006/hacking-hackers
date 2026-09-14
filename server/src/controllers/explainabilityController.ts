import type { Request, Response, NextFunction } from 'express';
import { getReplayDataset } from '../services/replayService.js';
import { dashboardStore } from '../models/dashboardModel.js';

export interface IFeatureCategory {
  id: string;
  name: string;
  description: string;
  features: Array<{
    key: string;
    label: string;
    value: number;
    formattedValue: string;
    unit: string;
    isAnomaly: boolean;
    anomalyDirection?: 'elevated' | 'depressed';
    attributionWeight?: number;
  }>;
}

const FEATURE_METADATA: Record<string, { label: string; unit: string; category: string; description: string; format?: (v: number) => string }> = {
  // Volume & Rates
  flow_count: { label: 'Flow Count', unit: 'flows', category: 'volume', description: 'Active concurrent flows observed in telemetry window' },
  total_ip_bytes: { label: 'Total IP Bytes', unit: 'bytes', category: 'volume', description: 'Aggregated packet payload and header bytes', format: (v) => `${(v / 1024).toFixed(1)} KB` },
  total_packets: { label: 'Total Packets', unit: 'pkts', category: 'volume', description: 'Total IP packets routed across active segment' },
  flow_rate: { label: 'Flow Arrival Rate', unit: 'flows/s', category: 'volume', description: 'New distinct flow initiation velocity', format: (v) => `${v.toFixed(2)}/s` },
  byte_rate: { label: 'Data Transfer Rate', unit: 'B/s', category: 'volume', description: 'Instantaneous bandwidth consumption', format: (v) => `${(v / 1024).toFixed(1)} KB/s` },
  packet_rate: { label: 'Packet Throughput', unit: 'pkts/s', category: 'volume', description: 'Packet forwarding rate', format: (v) => `${v.toFixed(1)} pkts/s` },

  // Protocols
  tcp_ratio: { label: 'TCP Traffic Proportion', unit: '%', category: 'protocols', description: 'Fraction of total flows running over TCP', format: (v) => `${(v * 100).toFixed(1)}%` },
  udp_ratio: { label: 'UDP Traffic Proportion', unit: '%', category: 'protocols', description: 'Fraction of total flows running over UDP', format: (v) => `${(v * 100).toFixed(1)}%` },
  icmp_ratio: { label: 'ICMP Ratio', unit: '%', category: 'protocols', description: 'Control message frequency', format: (v) => `${(v * 100).toFixed(2)}%` },

  // Port & Dispersion
  unique_dst_ports: { label: 'Unique Target Ports', unit: 'ports', category: 'entropy', description: 'Number of distinct destination service ports probed' },
  port_concentration: { label: 'Port Concentration', unit: 'ratio', category: 'entropy', description: 'Gini coefficient of port access distribution', format: (v) => v.toFixed(3) },
  dst_port_entropy: { label: 'Destination Port Entropy', unit: 'bits', category: 'entropy', description: 'Shannon entropy across destination ports (high = broad scan)', format: (v) => `${v.toFixed(2)} bits` },
  auth_port_ratio: { label: 'Auth Port Affinity (445/22/3389)', unit: '%', category: 'entropy', description: 'Ratio of traffic directed at administrative & remote services', format: (v) => `${(v * 100).toFixed(1)}%` },

  // Flags & Handshake
  syn_count: { label: 'SYN Flags Count', unit: 'flags', category: 'flags', description: 'Raw count of SYN connection initiation flags' },
  ack_count: { label: 'ACK Flags Count', unit: 'flags', category: 'flags', description: 'Raw count of acknowledged segments' },
  rst_count: { label: 'RST Teardowns', unit: 'flags', category: 'flags', description: 'Count of connection abort / reset signals' },
  fin_count: { label: 'FIN Terminations', unit: 'flags', category: 'flags', description: 'Graceful TCP connection termination signals' },
  psh_count: { label: 'PSH Expedited Data', unit: 'flags', category: 'flags', description: 'Segments requesting immediate push to application' },
  syn_ratio: { label: 'SYN / Total Flags Ratio', unit: '%', category: 'flags', description: 'SYN frequency; elevated values signal syn-floods or port sweeps', format: (v) => `${(v * 100).toFixed(1)}%` },
  ack_ratio: { label: 'ACK / Total Flags Ratio', unit: '%', category: 'flags', description: 'ACK frequency; low values indicate incomplete handshakes', format: (v) => `${(v * 100).toFixed(1)}%` },
  rst_ratio: { label: 'RST Anomaly Ratio', unit: '%', category: 'flags', description: 'Proportion of connection aborts indicating closed port hitting', format: (v) => `${(v * 100).toFixed(2)}%` },
  rst_to_syn_ratio: { label: 'RST to SYN Disparity', unit: 'ratio', category: 'flags', description: 'Ratio of rejected connection attempts to initiated requests', format: (v) => v.toFixed(3) },
  handshake_completion_ratio: { label: 'Handshake Completion Rate', unit: '%', category: 'flags', description: 'Ratio of completed 3-way handshakes to SYN probes', format: (v) => `${(v * 100).toFixed(1)}%` },

  // Packet Dimensions & Payload
  fwd_packet_ratio: { label: 'Forward Packet Share', unit: '%', category: 'payload', description: 'Fraction of packets moving client -> server', format: (v) => `${(v * 100).toFixed(1)}%` },
  fwd_byte_ratio: { label: 'Forward Byte Share', unit: '%', category: 'payload', description: 'Fraction of volume transmitted egress-bound', format: (v) => `${(v * 100).toFixed(1)}%` },
  down_up_ratio_mean: { label: 'Down / Up Ratio Mean', unit: 'ratio', category: 'payload', description: 'Symmetry between ingress response and egress request volume', format: (v) => v.toFixed(2) },
  down_up_ratio_std: { label: 'Down / Up Ratio Std', unit: 'variance', category: 'payload', description: 'Dispersion in asymmetric packet exchange', format: (v) => v.toFixed(2) },
  pkt_len_mean: { label: 'Mean Packet Length', unit: 'bytes', category: 'payload', description: 'Average frame size across all flows', format: (v) => `${v.toFixed(1)} B` },
  pkt_len_std: { label: 'Packet Length Std Dev', unit: 'bytes', category: 'payload', description: 'Standard deviation of packet sizing', format: (v) => `${v.toFixed(1)} B` },
  pkt_len_max: { label: 'Max Packet Length', unit: 'bytes', category: 'payload', description: 'Maximum observed frame length in window', format: (v) => `${v.toFixed(0)} B` },
  pkt_len_min: { label: 'Min Packet Length', unit: 'bytes', category: 'payload', description: 'Smallest observed frame (e.g. naked TCP ACKs)', format: (v) => `${v.toFixed(0)} B` },
  zero_payload_ratio: { label: 'Zero-Payload Packet Share', unit: '%', category: 'payload', description: 'Ratio of header-only control packets to payload packets', format: (v) => `${(v * 100).toFixed(1)}%` },

  // Inter-Arrival Timing & Lifetimes
  flow_iat_mean: { label: 'Flow Inter-Arrival Mean', unit: 's', category: 'timing', description: 'Average time delta separating consecutive flows', format: (v) => `${v.toFixed(3)}s` },
  flow_iat_std: { label: 'Flow Inter-Arrival Variance', unit: 's', category: 'timing', description: 'Jitter in connection frequency; low jitter indicates automation', format: (v) => `${v.toFixed(3)}s` },
  flow_iat_max: { label: 'Max Flow Inter-Arrival', unit: 's', category: 'timing', description: 'Longest idle interval between flow starts', format: (v) => `${v.toFixed(2)}s` },
  flow_iat_min: { label: 'Min Flow Inter-Arrival', unit: 's', category: 'timing', description: 'Burst density interval', format: (v) => `${v.toFixed(4)}s` },
  active_connection_lifetime_mean: { label: 'Mean Connection Lifetime', unit: 's', category: 'timing', description: 'Average session hold time before close', format: (v) => `${v.toFixed(2)}s` },

  // World Model Dynamic Velocity / Deltas
  delta_flow_count: { label: 'Δ Flow Count Acceleration', unit: 'flows/step', category: 'deltas', description: 'World model forecasted acceleration in concurrent sessions' },
  delta_total_ip_bytes: { label: 'Δ Data Volume Shock', unit: 'bytes', category: 'deltas', description: 'Temporal derivative of transmitted payload volume', format: (v) => `${(v / 1024).toFixed(1)} KB` },
  delta_total_packets: { label: 'Δ Packet Rate Surge', unit: 'pkts', category: 'deltas', description: 'Packet density divergence from temporal prior' },
  delta_flow_rate: { label: 'Δ Flow Velocity', unit: 'flows/s²', category: 'deltas', description: 'Second-order rate of change of new connections', format: (v) => v.toFixed(2) },
  delta_byte_rate: { label: 'Δ Throughput Delta', unit: 'B/s²', category: 'deltas', description: 'Velocity of bandwidth shift', format: (v) => `${(v / 1024).toFixed(1)} KB/s` },
  delta_packet_rate: { label: 'Δ Packet Rate Delta', unit: 'pkts/s²', category: 'deltas', description: 'Packet velocity shift', format: (v) => v.toFixed(1) },
  delta_dst_port_entropy: { label: 'Δ Port Entropy Drift', unit: 'bits', category: 'deltas', description: 'Rapid expansion or contraction of targeted service attack surface', format: (v) => `${v.toFixed(3)} bits` },
  delta_port_concentration: { label: 'Δ Port Concentration Shift', unit: 'ratio', category: 'deltas', description: 'Focus shift from wide reconnaissance to target service', format: (v) => v.toFixed(3) },
  delta_auth_port_ratio: { label: 'Δ Auth Port Targeting', unit: '%', category: 'deltas', description: 'Shift towards privileged services (SMB/SSH/RDP)', format: (v) => `${(v * 100).toFixed(1)}%` },
  delta_syn_ratio: { label: 'Δ SYN Ratio Spike', unit: '%', category: 'deltas', description: 'Acceleration in unfinished probe initiation', format: (v) => `${(v * 100).toFixed(2)}%` },
  delta_ack_ratio: { label: 'Δ ACK Ratio Shift', unit: '%', category: 'deltas', description: 'Alteration in session handshake dynamics', format: (v) => `${(v * 100).toFixed(2)}%` },
  delta_rst_ratio: { label: 'Δ RST Error Surge', unit: '%', category: 'deltas', description: 'Rate of closed port rejections indicating scanning', format: (v) => `${(v * 100).toFixed(2)}%` },
  delta_rst_to_syn_ratio: { label: 'Δ Rejection Disparity', unit: 'ratio', category: 'deltas', description: 'Change in probe rejection rate', format: (v) => v.toFixed(3) },
  delta_fwd_packet_ratio: { label: 'Δ Directional Asymmetry', unit: '%', category: 'deltas', description: 'Shift in inbound vs outbound routing ratio', format: (v) => `${(v * 100).toFixed(1)}%` },
  delta_pkt_len_mean: { label: 'Δ Mean Frame Length', unit: 'bytes', category: 'deltas', description: 'Frame size inflation/deflation indicator', format: (v) => `${v.toFixed(1)} B` },
  delta_flow_iat_mean: { label: 'Δ Inter-Arrival Jitter', unit: 's', category: 'deltas', description: 'Tempo shift in connection intervals', format: (v) => `${v.toFixed(3)}s` },
  delta_active_connection_lifetime_mean: { label: 'Δ Connection Lifetime', unit: 's', category: 'deltas', description: 'Holding time variation across active sockets', format: (v) => `${v.toFixed(2)}s` },
};

const CATEGORY_NAMES: Record<string, { name: string; description: string }> = {
  volume: { name: 'Flow Volume & Rates', description: 'Aggregated flow, packet, and byte transmission rates across the monitored segment' },
  protocols: { name: 'Protocol Distribution', description: 'Transport and network protocol composition (TCP / UDP / ICMP)' },
  entropy: { name: 'Port & Attack Surface Entropy', description: 'Target dispersion, port entropy, and privileged service targeting' },
  flags: { name: 'TCP Flags & Handshake Dynamics', description: 'TCP connection state, SYN sweeps, teardowns, and handshake completion rates' },
  payload: { name: 'Packet Sizing & Payload Characteristics', description: 'Frame length distribution, payload ratios, and directional asymmetry' },
  timing: { name: 'Inter-Arrival Timing & Lifetimes', description: 'Flow timing variance, jitter, burstiness, and socket persistence' },
  deltas: { name: 'SparseRSSM World Model State Deltas', description: 'First and second order temporal gradients predicting impending state transitions' },
};

export async function getExplainability(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const dataset = getReplayDataset();
    let targetIndex: number;

    if (req.query.windowIndex !== undefined && req.query.windowIndex !== '') {
      targetIndex = Number(req.query.windowIndex);
    } else if (req.query.scrub !== undefined && req.query.scrub !== '') {
      const scrub = Math.max(0, Math.min(100, Number(req.query.scrub)));
      targetIndex = Math.round(dataset.startIndex + (scrub / 100) * (dataset.endIndex - dataset.startIndex));
    } else {
      targetIndex = dashboardStore.actual_window_index;
    }

    // Clamp to valid range
    targetIndex = Math.max(dataset.startIndex, Math.min(dataset.endIndex, targetIndex));

    const win = dataset.windows.find((w) => w.windowIndex === targetIndex) || dataset.windows[0]!;

    // Format feature contributions
    const contributions = win.featureContributions.map((fc) => {
      const meta = FEATURE_METADATA[fc.feature];
      return {
        feature: fc.feature,
        label: meta?.label || fc.feature.replace(/_/g, ' '),
        category: meta?.category || 'general',
        description: meta?.description || 'Extracted network flow metric',
        value: fc.value,
        weight: fc.weight,
        direction: fc.weight > 0 ? ('elevates_threat' as const) : ('mitigates_threat' as const),
      };
    }).sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight));

    // Group 54 features into domain categories
    const categoriesMap = new Map<string, IFeatureCategory>();
    for (const [catId, catInfo] of Object.entries(CATEGORY_NAMES)) {
      categoriesMap.set(catId, {
        id: catId,
        name: catInfo.name,
        description: catInfo.description,
        features: [],
      });
    }

    const featureKeys = Object.keys(win.features || {});
    for (const key of featureKeys) {
      const val = win.features[key] ?? 0;
      const meta = FEATURE_METADATA[key] || {
        label: key.replace(/_/g, ' '),
        unit: 'val',
        category: 'volume',
        description: 'Network metric',
      };

      const matchedContrib = win.featureContributions.find((c) => c.feature === key);
      const isAnomaly = matchedContrib ? Math.abs(matchedContrib.weight) >= 0.15 : false;

      const formattedValue = meta.format ? meta.format(val) : typeof val === 'number' ? (Number.isInteger(val) ? val.toLocaleString() : val.toFixed(3)) : String(val);

      const categoryObj = categoriesMap.get(meta.category) || categoriesMap.get('volume')!;
      categoryObj.features.push({
        key,
        label: meta.label,
        value: val,
        formattedValue,
        unit: meta.unit,
        isAnomaly,
        anomalyDirection: matchedContrib ? (matchedContrib.weight > 0 ? 'elevated' : 'depressed') : undefined,
        attributionWeight: matchedContrib?.weight,
      });
    }

    const categories = Array.from(categoriesMap.values()).filter((c) => c.features.length > 0);

    res.json({
      windowIndex: win.windowIndex,
      timestampStart: win.timestampStart,
      timestampEnd: win.timestampEnd,
      phase: win.phase,
      stage: win.stage,
      probability: win.probability,
      confidence: win.confidence,
      riskState: win.riskState,
      isAttack: win.isAttack,
      leadTimeSeconds: win.riskState === 'critical' ? 20.0 : win.riskState === 'watch' ? 14.0 : 0.0,
      mitre: {
        techniqueId: win.techniqueId,
        techniqueName: win.techniqueName,
        tactic: win.stage,
      },
      summary: win.summary,
      reason: win.reason,
      featureContributions: contributions,
      featureCategories: categories,
      rawFeaturesCount: featureKeys.length,
      modelEnsemble: {
        architecture: 'SparseRSSM + TFCNet Ensemble',
        sparseRssmWeight: 0.60,
        tfcnetWeight: 0.40,
        latentDimensions: 256,
        timeFrequencyHeads: 4,
        f1Threshold: 0.65,
        dataset: dataset.dataset,
        targetEpisode: dataset.targetEpisode,
      },
      timelineBounds: {
        min: dataset.startIndex,
        max: dataset.endIndex,
        current: win.windowIndex,
        attackOnset: dataset.attackOnsetInterval,
      },
      presets: [
        { label: 'Benign Baseline', windowIndex: 1750, scrub: 0, stage: 'Normal' },
        { label: 'Port Reconnaissance', windowIndex: 1785, scrub: 58, stage: 'Recon' },
        { label: 'Initial Exploitation', windowIndex: 1792, scrub: 70, stage: 'Initial Access' },
        { label: 'Lateral SMB Pivot', windowIndex: 1796, scrub: 77, stage: 'Lateral Movement' },
        { label: 'C2 Beacon Egress', windowIndex: 1805, scrub: 92, stage: 'C2' },
      ],
    });
  } catch (err) {
    next(err);
  }
}
