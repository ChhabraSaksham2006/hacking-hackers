export type RiskState = "normal" | "watch" | "critical";

export const riskLabel: Record<RiskState, string> = {
  normal: "Normal",
  watch: "Watch",
  critical: "Critical",
};

export const stateColorVar: Record<RiskState, string> = {
  normal: "var(--signal-teal)",
  watch: "var(--watch-amber)",
  critical: "var(--critical-crimson)",
};

export const stateTextClass: Record<RiskState, string> = {
  normal: "text-teal",
  watch: "text-amber",
  critical: "text-crimson",
};

export function riskFromProbability(p: number): RiskState {
  if (p >= 0.72) return "critical";
  if (p >= 0.45) return "watch";
  return "normal";
}

/** Deterministic sample probability trajectory (48 five-minute windows). */
export const probabilitySeries: number[] = [
  0.08, 0.11, 0.09, 0.13, 0.1, 0.12, 0.15, 0.14, 0.12, 0.18, 0.21, 0.19, 0.17,
  0.22, 0.26, 0.24, 0.29, 0.27, 0.33, 0.31, 0.36, 0.34, 0.4, 0.38, 0.44, 0.47,
  0.43, 0.5, 0.55, 0.52, 0.49, 0.58, 0.63, 0.6, 0.57, 0.66, 0.71, 0.68, 0.74,
  0.79, 0.76, 0.72, 0.81, 0.86, 0.83, 0.79, 0.84, 0.88,
];

export const forecastSeries: number[] = [
  0.88, 0.9, 0.91, 0.89, 0.93, 0.95, 0.94, 0.96,
];

export const actualSeries: number[] = [
  0.88, 0.87, 0.85, 0.88, 0.84, 0.81, 0.83, 0.8,
];

export const threshold = 0.65;

export function windowLabel(index: number, total = probabilitySeries.length) {
  const minutesAgo = (total - 1 - index) * 5;
  const d = new Date(Date.UTC(2026, 8, 6, 14, 40) - minutesAgo * 60_000);
  return d.toISOString().slice(11, 16) + "Z";
}

export const attackStages = [
  "Recon",
  "Initial access",
  "Lateral movement",
  "C2",
  "Exfiltration",
] as const;

export const currentStageIndex = 2;

export type Alert = {
  id: string;
  host: string;
  ip: string;
  stage: string;
  probability: number;
  state: RiskState;
  reason: string;
  at: string;
  status: "New" | "Acknowledged" | "Investigating" | "Resolved";
  analyst: string;
};

export const alerts: Alert[] = [
  {
    id: "AV-4821",
    host: "fin-db-02",
    ip: "10.24.8.31",
    stage: "Lateral movement",
    probability: 0.88,
    state: "critical",
    reason: "Sequential SMB session setup across 14 hosts in 90s",
    at: "14:38Z",
    status: "New",
    analyst: "SC",
  },
  {
    id: "AV-4820",
    host: "edge-gw-01",
    ip: "10.24.1.4",
    stage: "C2",
    probability: 0.74,
    state: "critical",
    reason: "Periodic 58s beacon to unclassified ASN",
    at: "14:21Z",
    status: "New",
    analyst: "RM",
  },
  {
    id: "AV-4817",
    host: "ops-jump-05",
    ip: "10.24.4.19",
    stage: "Initial access",
    probability: 0.61,
    state: "watch",
    reason: "Elevated SYN/ACK ratio on ports 22, 23, 445",
    at: "13:57Z",
    status: "Acknowledged",
    analyst: "SC",
  },
  {
    id: "AV-4814",
    host: "hr-file-11",
    ip: "10.24.12.77",
    stage: "Recon",
    probability: 0.52,
    state: "watch",
    reason: "Sweep of 212 closed ports from single source",
    at: "13:12Z",
    status: "Investigating",
    analyst: "AK",
  },
  {
    id: "AV-4809",
    host: "dev-ci-03",
    ip: "10.24.19.8",
    stage: "Exfiltration",
    probability: 0.69,
    state: "watch",
    reason: "Outbound volume 41x host baseline over 6 windows",
    at: "12:40Z",
    status: "Investigating",
    analyst: "RM",
  },
  {
    id: "AV-4801",
    host: "print-svc-02",
    ip: "10.24.3.55",
    stage: "Recon",
    probability: 0.28,
    state: "normal",
    reason: "Scan traced to scheduled vulnerability assessment",
    at: "11:04Z",
    status: "Resolved",
    analyst: "AK",
  },
];

export type Flow = {
  src: string;
  dst: string;
  proto: string;
  flags: string;
  bytes: number;
  packets: number;
  duration: number;
  iatMean: number;
  iatVar: number;
  iatMax: number;
  ttlVar: number;
  window: number;
  retrans: number;
  score: number;
};

export const flows: Flow[] = [
  { src: "10.24.8.31:49722", dst: "10.24.8.14:445", proto: "TCP", flags: "0x018", bytes: 1284551, packets: 2210, duration: 88.4, iatMean: 0.04, iatVar: 0.0011, iatMax: 0.91, ttlVar: 3.2, window: 64240, retrans: 41, score: 0.91 },
  { src: "10.24.1.4:51344", dst: "203.0.113.77:8443", proto: "TCP", flags: "0x010", bytes: 44120, packets: 388, duration: 604.1, iatMean: 58.02, iatVar: 0.44, iatMax: 59.9, ttlVar: 0.4, window: 29200, retrans: 2, score: 0.83 },
  { src: "10.24.4.19:44100", dst: "10.24.4.20:22", proto: "TCP", flags: "0x002", bytes: 3120, packets: 52, duration: 4.2, iatMean: 0.08, iatVar: 0.0004, iatMax: 0.22, ttlVar: 0.0, window: 64240, retrans: 0, score: 0.66 },
  { src: "10.24.12.77:60122", dst: "10.24.12.0/24:*", proto: "TCP", flags: "0x002", bytes: 18422, packets: 424, duration: 31.7, iatMean: 0.07, iatVar: 0.0002, iatMax: 0.19, ttlVar: 0.1, window: 1024, retrans: 0, score: 0.58 },
  { src: "10.24.19.8:33012", dst: "198.51.100.20:443", proto: "TCP", flags: "0x018", bytes: 88214773, packets: 61240, duration: 1811.9, iatMean: 0.03, iatVar: 0.0009, iatMax: 2.14, ttlVar: 1.8, window: 65535, retrans: 118, score: 0.71 },
  { src: "10.24.6.42:57812", dst: "10.24.6.9:3389", proto: "TCP", flags: "0x012", bytes: 240110, packets: 1804, duration: 402.6, iatMean: 0.22, iatVar: 0.014, iatMax: 3.4, ttlVar: 0.6, window: 64240, retrans: 6, score: 0.44 },
  { src: "10.24.3.55:5353", dst: "224.0.0.251:5353", proto: "UDP", flags: "—", bytes: 9820, packets: 142, duration: 300.0, iatMean: 2.11, iatVar: 0.08, iatMax: 4.9, ttlVar: 0.0, window: 0, retrans: 0, score: 0.12 },
  { src: "10.24.9.18:49001", dst: "10.24.2.5:53", proto: "UDP", flags: "—", bytes: 4210, packets: 88, duration: 120.4, iatMean: 1.37, iatVar: 0.05, iatMax: 3.1, ttlVar: 0.0, window: 0, retrans: 0, score: 0.09 },
];

export const featureContributions = [
  { feature: "syn_ack_ratio", value: "4.82", weight: 0.31 },
  { feature: "dst_port_entropy", value: "0.94", weight: 0.24 },
  { feature: "smb_session_rate", value: "14 / 90s", weight: 0.18 },
  { feature: "iat_variance", value: "0.0011", weight: 0.11 },
  { feature: "retransmit_count", value: "41", weight: 0.08 },
  { feature: "ttl_variance", value: "3.2", weight: -0.06 },
  { feature: "flow_duration", value: "88.4s", weight: -0.09 },
];

export const segments = [
  { name: "corp-core", hosts: 412, alerts: 2, volume: 34, state: "watch" as RiskState, last: "14:38Z" },
  { name: "finance", hosts: 128, alerts: 3, volume: 22, state: "critical" as RiskState, last: "14:38Z" },
  { name: "ot-plant-a", hosts: 96, alerts: 0, volume: 14, state: "normal" as RiskState, last: "—" },
  { name: "dmz-edge", hosts: 34, alerts: 1, volume: 11, state: "watch" as RiskState, last: "14:21Z" },
  { name: "dev-build", hosts: 210, alerts: 1, volume: 9, state: "watch" as RiskState, last: "12:40Z" },
  { name: "guest-wifi", hosts: 508, alerts: 0, volume: 6, state: "normal" as RiskState, last: "—" },
  { name: "ot-plant-b", hosts: 74, alerts: 0, volume: 4, state: "normal" as RiskState, last: "—" },
];

export const auditEntries = [
  { at: "2026-09-06 14:39:02Z", actor: "s.chhabra", action: "alert.acknowledge", target: "AV-4817" },
  { at: "2026-09-06 14:31:44Z", actor: "system", action: "inference.run", target: "window 14:25–14:30" },
  { at: "2026-09-06 14:02:10Z", actor: "r.mehta", action: "export.create", target: "report/weekly-fin" },
  { at: "2026-09-06 13:48:51Z", actor: "a.kaur", action: "alert.status_change", target: "AV-4814 → Investigating" },
  { at: "2026-09-06 12:20:03Z", actor: "s.chhabra", action: "model.promote", target: "wm-v4.2.1" },
  { at: "2026-09-06 11:59:17Z", actor: "system", action: "ingest.complete", target: "cicids-2018-day3.pcap" },
  { at: "2026-09-06 09:14:38Z", actor: "admin", action: "user.role_change", target: "a.kaur → SOC Lead" },
];

export const benchmark = [
  { metric: "F1", wmA: 0.943, lrA: 0.812, wmB: 0.918, lrB: 0.774 },
  { metric: "Precision", wmA: 0.951, lrA: 0.796, wmB: 0.927, lrB: 0.761 },
  { metric: "Recall", wmA: 0.936, lrA: 0.829, wmB: 0.909, lrB: 0.788 },
  { metric: "False positive rate", wmA: 0.014, lrA: 0.092, wmB: 0.021, lrB: 0.114 },
];

export const lossCurve = {
  train: [0.68, 0.51, 0.4, 0.33, 0.28, 0.24, 0.21, 0.19, 0.17, 0.16, 0.15, 0.14],
  val: [0.71, 0.55, 0.45, 0.38, 0.34, 0.31, 0.29, 0.28, 0.27, 0.27, 0.26, 0.26],
};
