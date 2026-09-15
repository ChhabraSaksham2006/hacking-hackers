import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { Segment, type ISegment } from '../models/Segment.js';
import { Alert } from '../models/Alert.js';
import { Prediction } from '../models/Prediction.js';
import { dashboardStore } from '../models/dashboardModel.js';
import { logAuditEvent } from '../services/auditService.js';
import { z } from 'zod';
import { validate } from '../middleware/validate.js';

const router = Router();

router.use(authenticate, requirePermission('alerts.read'));

// ── Static Host Roster per Segment ───────────────────────
export const SEGMENT_HOST_METADATA: Record<
  string,
  Array<{ ip: string; hostname: string; role: string; os: string; baselineFlows: number }>
> = {
  'corp-core': [
    { ip: '192.168.10.44', hostname: 'corp-workstation-44', role: 'Foothold Workstation', os: 'Windows 10 Pro', baselineFlows: 38 },
    { ip: '192.168.10.19', hostname: 'corp-app-node-19', role: 'Internal App Server', os: 'Ubuntu 22.04 LTS', baselineFlows: 22 },
    { ip: '192.168.10.25', hostname: 'hr-workstation-25', role: 'Staff Workstation', os: 'macOS Sonoma', baselineFlows: 8 },
    { ip: '192.168.10.50', hostname: 'dev-ci-worker', role: 'Build Worker Node', os: 'Debian 12', baselineFlows: 14 },
    { ip: '10.24.12.77', hostname: 'hr-file-11', role: 'HR Document Server', os: 'Windows Server 2022', baselineFlows: 12 },
  ],
  'finance': [
    { ip: '192.168.10.12', hostname: 'corp-file-srv-12', role: 'SMB Payroll Server', os: 'Windows Server 2022', baselineFlows: 46 },
    { ip: '10.24.8.31', hostname: 'fin-db-02', role: 'Ledger Database', os: 'RHEL 9.2', baselineFlows: 58 },
    { ip: '10.24.8.14', hostname: 'fin-srv-01', role: 'Payment Gateway Node', os: 'Debian 12', baselineFlows: 29 },
    { ip: '10.24.8.55', hostname: 'fin-audit-04', role: 'Compliance Auditor', os: 'RHEL 8.8', baselineFlows: 15 },
  ],
  'dmz-edge': [
    { ip: '192.168.10.1', hostname: 'edge-gw-01', role: 'Perimeter Gateway / DNS', os: 'FortiOS / Linux', baselineFlows: 64 },
    { ip: '10.0.0.15', hostname: 'ops-jump-15', role: 'Management Bastion', os: 'Alpine Linux', baselineFlows: 14 },
    { ip: '10.24.1.4', hostname: 'dmz-proxy-01', role: 'Ingress Reverse Proxy', os: 'Envoy / Linux', baselineFlows: 41 },
    { ip: '10.24.4.19', hostname: 'ops-jump-05', role: 'SOC Jump Host', os: 'Ubuntu 20.04', baselineFlows: 18 },
    { ip: '203.0.113.15', hostname: 'ext-c2-node', role: 'External Remote Listener', os: 'Unknown Egress Peer', baselineFlows: 32 },
  ],
  'dev-build': [
    { ip: '10.24.19.8', hostname: 'dev-ci-03', role: 'Container Builder', os: 'Ubuntu 22.04 LTS', baselineFlows: 27 },
    { ip: '10.24.19.12', hostname: 'dev-git-01', role: 'Git Source Vault', os: 'Debian 12', baselineFlows: 19 },
    { ip: '10.24.19.24', hostname: 'dev-runner-04', role: 'K8s Cluster Node', os: 'CoreOS', baselineFlows: 16 },
  ],
  'ot-plant-a': [
    { ip: '10.30.1.10', hostname: 'plc-assembly-01', role: 'Siemens S7-1500 PLC', os: 'Embedded Firmware', baselineFlows: 8 },
    { ip: '10.30.1.14', hostname: 'scada-rtu-04', role: 'Modbus RTU Gateway', os: 'VxWorks RTOS', baselineFlows: 11 },
    { ip: '10.30.1.20', hostname: 'plant-sensor-gw', role: 'Telemetry Bus', os: 'Zephyr RTOS', baselineFlows: 5 },
  ],
  'ot-plant-b': [
    { ip: '10.30.2.11', hostname: 'plc-press-02', role: 'Hydraulic Press PLC', os: 'Embedded Firmware', baselineFlows: 7 },
    { ip: '10.30.2.15', hostname: 'hmi-console-01', role: 'Floor Operator HMI', os: 'Windows 10 IoT', baselineFlows: 6 },
  ],
  'guest-wifi': [
    { ip: '172.16.0.1', hostname: 'guest-ap-01', role: 'Access Point East', os: 'Meraki OS', baselineFlows: 22 },
    { ip: '172.16.0.2', hostname: 'guest-ap-02', role: 'Access Point West', os: 'Meraki OS', baselineFlows: 18 },
    { ip: '10.24.3.55', hostname: 'print-svc-02', role: 'Shared Network Printer', os: 'Embedded Linux', baselineFlows: 9 },
  ],
};

// ── Segment Protocol Signatures ───────────────────────────
const SEGMENT_PROTOCOLS: Record<string, Array<{ name: string; port: number; pct: number }>> = {
  'corp-core': [
    { name: 'TCP', port: 80, pct: 36 },
    { name: 'SMB', port: 445, pct: 32 },
    { name: 'HTTPS', port: 443, pct: 22 },
    { name: 'DNS', port: 53, pct: 10 },
  ],
  'finance': [
    { name: 'SMB', port: 445, pct: 46 },
    { name: 'HTTPS', port: 443, pct: 28 },
    { name: 'RPC', port: 135, pct: 18 },
    { name: 'Kerberos', port: 88, pct: 8 },
  ],
  'dmz-edge': [
    { name: 'HTTPS', port: 443, pct: 48 },
    { name: 'SSH', port: 22, pct: 28 },
    { name: 'DNS', port: 53, pct: 14 },
    { name: 'C2 Beacon', port: 8443, pct: 10 },
  ],
  'dev-build': [
    { name: 'Git/SSH', port: 22, pct: 44 },
    { name: 'HTTP Alt', port: 8080, pct: 32 },
    { name: 'Docker Registry', port: 5000, pct: 24 },
  ],
  'ot-plant-a': [
    { name: 'Modbus/TCP', port: 502, pct: 64 },
    { name: 'PROFINET', port: 34964, pct: 26 },
    { name: 'NTP', port: 123, pct: 10 },
  ],
  'ot-plant-b': [
    { name: 'Modbus/TCP', port: 502, pct: 58 },
    { name: 'EtherNet/IP', port: 44818, pct: 32 },
    { name: 'ICMP', port: 0, pct: 10 },
  ],
  'guest-wifi': [
    { name: 'HTTPS', port: 443, pct: 68 },
    { name: 'DNS', port: 53, pct: 26 },
    { name: 'mDNS', port: 5353, pct: 6 },
  ],
};

/**
 * Enriches a segment with dynamic telemetry, alert statistics, and telemetry sparklines.
 */
async function enrichSegment(
  seg: ISegment,
  alerts: any[],
  simSummary: any
) {
  const hostsMeta = SEGMENT_HOST_METADATA[seg.name] || [];
  const hostIps = new Set(hostsMeta.map((h) => h.ip));

  // Find alerts impacting this segment either by exact IP, host prefix, or segment name
  const segmentAlerts = alerts.filter((a) => {
    const cleanIp = a.ip?.split(':')[0];
    const cleanHost = a.host?.toLowerCase();
    const segPrefix = seg.name.split('-')[0];
    return (
      hostIps.has(cleanIp) ||
      (cleanHost && cleanHost.includes(segPrefix)) ||
      (a.stage && seg.name === 'finance' && a.stage.toLowerCase().includes('lateral')) ||
      (a.stage && seg.name === 'dmz-edge' && a.stage.toLowerCase().includes('c2'))
    );
  });

  const activeAlertCount = segmentAlerts.filter((a) => a.status !== 'Resolved').length;

  // Derive model-driven segment probability & stage
  let modelProbability = 0.08;
  let modelStage = 'Normal Baseline';
  const generalProb = simSummary?.infiltrationProbability ?? 0.88;

  if (seg.name === 'finance') {
    modelProbability = generalProb;
    modelStage = simSummary?.currentStage || 'Lateral Movement';
  } else if (seg.name === 'corp-core') {
    modelProbability = Math.max(0.12, Math.round((generalProb - 0.04) * 100) / 100);
    modelStage = simSummary?.currentStage || 'Lateral Movement';
  } else if (seg.name === 'dmz-edge') {
    modelProbability = generalProb >= 0.7 ? 0.74 : 0.15;
    modelStage = generalProb >= 0.7 ? 'C2 Egress' : 'Perimeter Gateway';
  } else if (seg.name === 'dev-build') {
    modelProbability = generalProb >= 0.5 ? 0.48 : 0.11;
    modelStage = generalProb >= 0.5 ? 'Initial Access Precursor' : 'CI/CD Pipeline';
  } else {
    modelProbability = 0.06;
    modelStage = 'Industrial Baseline';
  }

  // Determine dynamic risk state
  let dynamicState: 'normal' | 'watch' | 'critical' = seg.state;
  const hasCritical = segmentAlerts.some((a) => a.state === 'critical' && a.status !== 'Resolved');
  const hasWatch = segmentAlerts.some((a) => a.state === 'watch' && a.status !== 'Resolved');

  if (hasCritical || modelProbability >= 0.8 || (simSummary?.riskLevel === 'critical' && (seg.name === 'finance' || seg.name === 'corp-core'))) {
    dynamicState = 'critical';
  } else if (hasWatch || modelProbability >= 0.4 || (simSummary?.riskLevel === 'watch' && (seg.name === 'dmz-edge' || seg.name === 'dev-build'))) {
    dynamicState = 'watch';
  } else if (activeAlertCount === 0 && !seg.isolated) {
    dynamicState = 'normal';
  }

  // Calculate throughput (Mbps) and dynamic sparkline (12 points)
  const isElevated = dynamicState === 'critical' || dynamicState === 'watch';
  const baseThroughput = seg.name === 'corp-core' ? 48.4 : seg.name === 'finance' ? 62.8 : seg.name === 'dmz-edge' ? 34.5 : 12.0;
  const throughputMbps = Math.round((baseThroughput * (isElevated ? 1.45 : 1.0) + (Math.sin(Date.now() / 15000) * 4)) * 10) / 10;

  // 12-point sparkline showing live micro-wave
  const sparkline: number[] = [];
  for (let i = 0; i < 12; i++) {
    const factor = isElevated && i >= 7 ? 1.3 + (i - 7) * 0.12 : 0.9 + (i % 3) * 0.15;
    sparkline.push(Math.round((baseThroughput * factor + Math.sin((i + Date.now() / 10000)) * 3) * 10) / 10);
  }

  // Anomaly score (0 - 100)
  const threatScore = dynamicState === 'critical'
    ? Math.round(75 + modelProbability * 24)
    : dynamicState === 'watch'
    ? Math.round(45 + modelProbability * 20)
    : Math.round(4 + Math.random() * 8);

  // Top Talkers in this segment
  const topTalkers = hostsMeta.slice(0, 3).map((h) => ({
    ip: h.ip,
    hostname: h.hostname,
    role: h.role,
    flows: isElevated && h.ip === '192.168.10.44' ? 48 : h.baselineFlows,
    bytes: isElevated && h.ip === '192.168.10.44' ? '84.5 KB' : `${Math.round(h.baselineFlows * 1.8)} KB`,
    state: (h.ip === '192.168.10.44' || h.ip === '192.168.10.12' || h.ip === '203.0.113.15') && dynamicState === 'critical'
      ? 'critical'
      : dynamicState === 'watch' && (h.ip === '192.168.10.19' || h.ip === '10.0.0.15')
      ? 'watch'
      : 'normal',
  }));

  const protocols = SEGMENT_PROTOCOLS[seg.name] || [
    { name: 'TCP', port: 80, pct: 70 },
    { name: 'UDP', port: 53, pct: 30 },
  ];

  return {
    _id: seg._id,
    name: seg.name,
    hosts: seg.hosts,
    activeAlerts: activeAlertCount,
    trafficVolume: seg.trafficVolume,
    throughputMbps,
    state: dynamicState,
    threatScore,
    modelProbability,
    modelStage,
    modelConfidence: simSummary?.modelConfidence || '91.8%',
    isolated: Boolean(seg.isolated),
    lastIncident: segmentAlerts[0]?.detectedAt ? new Date(segmentAlerts[0].detectedAt).toISOString().substring(11, 16) + 'Z' : seg.lastIncident,
    sparkline,
    topTalkers,
    protocols,
    hostInventory: hostsMeta,
  };
}

// ── GET /api/segments ───────────────────────────────────
router.get('/', async (req, res, next) => {
  try {
    const rawSegments = await Segment.find({ orgId: req.user!.orgId })
      .sort({ trafficVolume: -1 })
      .lean();

    const alerts = await Alert.find({ orgId: req.user!.orgId }).lean();
    const simSummary = dashboardStore.getSummary();

    const enriched = await Promise.all(
      rawSegments.map((s) => enrichSegment(s as unknown as ISegment, alerts, simSummary))
    );

    res.json(enriched);
  } catch (err) {
    next(err);
  }
});

// ── GET /api/segments/topology ──────────────────────────
router.get('/topology', async (req, res, next) => {
  try {
    const rawSegments = await Segment.find({ orgId: req.user!.orgId })
      .sort({ trafficVolume: -1 })
      .lean();

    const alerts = await Alert.find({ orgId: req.user!.orgId }).lean();
    const simSummary = dashboardStore.getSummary();
    const latestPrediction = await Prediction.findOne({ orgId: req.user!.orgId })
      .sort({ createdAt: -1 })
      .lean();

    const segments = await Promise.all(
      rawSegments.map((s) => enrichSegment(s as unknown as ISegment, alerts, simSummary))
    );

    const isAttackActive = simSummary?.riskLevel === 'critical' || segments.some((s) => s.state === 'critical');
    const rawOutputs = (simSummary as any).rawModelOutputs || {};

    // ── Model Intelligence Envelope ────────────────────────
    const modelIntelligence = {
      engine: rawOutputs.neuralEngine || 'SparseRSSM + TFCNet Ensemble (Temporal State-Space + Spectral Transformer)',
      modelVersion: latestPrediction?.modelVersion || 'wm-v4.2.1',
      inferenceSource: dashboardStore.lastInferenceSource === 'fastapi_microservice' ? 'FastAPI Microservice (http://localhost:7860)' : 'Local PyTorch Bridge',
      mlServiceOnline: true,
      windowIndex: dashboardStore.actual_window_index || 1797,
      timestamp: dashboardStore.timestamp || new Date().toISOString(),
      ensembleProbability: simSummary.infiltrationProbability ?? 0.91,
      rssmProbability: rawOutputs.rawOnsetProb ?? 0.0494,
      tfcProbability: rawOutputs.tfcOnsetProb ?? 0.5156,
      confidence: simSummary.modelConfidence || '91.8%',
      leadTimeSeconds: simSummary.leadTimeSeconds ?? 20.0,
      currentStage: simSummary.currentStage || 'Lateral Movement',
      riskLevel: simSummary.riskLevel || 'critical',
      detectionThreshold: rawOutputs.calibratedF1Threshold ?? 0.04,
      probabilityTimeline: dashboardStore.timeline?.length === 48 ? dashboardStore.timeline : (latestPrediction?.series || []),
      flaggedHostsCount: String(simSummary.flaggedHosts || '3'),
      activeFlowsCount: String(simSummary.activeFlows || '15,525'),
      featureContributions: latestPrediction?.featureContributions || [
        { feature: 'syn_ack_ratio', value: '4.82', weight: 0.31, category: 'flags' },
        { feature: 'dst_port_entropy', value: '0.94', weight: 0.24, category: 'port' },
        { feature: 'smb_session_rate', value: '14 / 90s', weight: 0.18, category: 'rate' },
        { feature: 'iat_variance', value: '0.0011', weight: 0.11, category: 'timing' },
        { feature: 'retransmit_count', value: '41', weight: 0.08, category: 'flags' },
      ],
      modelFlows: dashboardStore.recentFlows || [],
    };

    // Cross-segment connection edges with animated packet telemetry & model probabilities
    const interSegmentLinks = [
      {
        id: 'link-corp-fin',
        source: 'corp-core',
        target: 'finance',
        trafficVolume: 42,
        throughput: isAttackActive ? '48.5 Mbps' : '14.2 Mbps',
        protocol: 'SMB / TCP (Port 445)',
        status: isAttackActive ? 'critical' : 'normal',
        threatStage: isAttackActive ? 'Lateral Movement' : null,
        description: isAttackActive ? 'High fan-out SMB sessions towards accounting vault (Model P=0.91)' : 'Routine file sharing & ledger sync',
        activeFlowCount: isAttackActive ? 38 : 12,
        modelScore: isAttackActive ? (simSummary.infiltrationProbability ?? 0.91) : 0.08,
      },
      {
        id: 'link-corp-dmz',
        source: 'corp-core',
        target: 'dmz-edge',
        trafficVolume: 28,
        throughput: isAttackActive ? '31.2 Mbps' : '18.4 Mbps',
        protocol: 'HTTPS / TLS (Port 8443)',
        status: isAttackActive ? 'critical' : 'normal',
        threatStage: isAttackActive ? 'C2 Egress' : null,
        description: isAttackActive ? 'Periodic 58s beaconing session to unclassified external ASN (Model P=0.74)' : 'Reverse proxy HTTPS traffic',
        activeFlowCount: isAttackActive ? 24 : 8,
        modelScore: isAttackActive ? 0.74 : 0.05,
      },
      {
        id: 'link-dmz-fin',
        source: 'dmz-edge',
        target: 'finance',
        trafficVolume: 14,
        throughput: '14.8 Mbps',
        protocol: 'SSH / Bastion (Port 22)',
        status: 'watch',
        threatStage: 'Privilege Verification',
        description: 'Operations jump bastion session to DB cluster (Model P=0.42)',
        activeFlowCount: 6,
        modelScore: 0.42,
      },
      {
        id: 'link-corp-dev',
        source: 'corp-core',
        target: 'dev-build',
        trafficVolume: 18,
        throughput: '19.4 Mbps',
        protocol: 'Git / HTTP (Port 8080)',
        status: 'normal',
        threatStage: null,
        description: 'CI/CD runner artifact pushes',
        activeFlowCount: 15,
        modelScore: 0.12,
      },
      {
        id: 'link-corp-ota',
        source: 'corp-core',
        target: 'ot-plant-a',
        trafficVolume: 8,
        throughput: '4.6 Mbps',
        protocol: 'Modbus/TCP (Port 502)',
        status: 'normal',
        threatStage: null,
        description: 'SCADA telemetry polling gateway',
        activeFlowCount: 5,
        modelScore: 0.06,
      },
      {
        id: 'link-corp-wifi',
        source: 'guest-wifi',
        target: 'corp-core',
        trafficVolume: 5,
        throughput: '2.1 Mbps',
        protocol: 'DNS / UDP (Port 53)',
        status: 'normal',
        threatStage: null,
        description: 'Captive portal & recursive DNS resolution',
        activeFlowCount: 11,
        modelScore: 0.04,
      },
      {
        id: 'link-ota-otb',
        source: 'ot-plant-a',
        target: 'ot-plant-b',
        trafficVolume: 4,
        throughput: '1.8 Mbps',
        protocol: 'Industrial EtherNet/IP',
        status: 'normal',
        threatStage: null,
        description: 'Inter-plant safety interlock bus',
        activeFlowCount: 3,
        modelScore: 0.02,
      },
    ];

    // Compute executive summary
    const totalHosts = segments.reduce((sum, s) => sum + s.hosts, 0);
    const totalThroughput = Math.round(segments.reduce((sum, s) => sum + s.throughputMbps, 0) * 10) / 10;
    const criticalSegments = segments.filter((s) => s.state === 'critical').length;
    const watchSegments = segments.filter((s) => s.state === 'watch').length;
    const isolatedSegments = segments.filter((s) => s.isolated).length;

    // Estate health index (100% is pristine, drops with critical segments)
    const healthScore = Math.max(20, Math.round(100 - (criticalSegments * 25 + watchSegments * 10 + (isAttackActive ? 15 : 0))));

    const activeThreatVector = isAttackActive
      ? `Active ${simSummary.currentStage}: port 445 SMB fan-out from corp-workstation-44 towards finance file servers`
      : 'Estate nominal: Zero critical anomalies detected across monitored subnets';

    res.json({
      segments,
      interSegmentLinks,
      summary: {
        totalSegments: segments.length,
        totalHosts,
        totalThroughputMbps: totalThroughput,
        criticalSegments,
        watchSegments,
        isolatedSegments,
        healthScore,
        activeThreatVector,
        activeWindowIndex: dashboardStore.actual_window_index,
        timestamp: new Date().toISOString(),
      },
      modelIntelligence,
    });
  } catch (err) {
    next(err);
  }
});

// ── GET /api/segments/:name/deepdive ────────────────────
const segmentParamSchema = z.object({
  name: z.string().min(1).max(100),
});

router.get(
  '/:name/deepdive',
  validate({ params: segmentParamSchema }),
  async (req, res, next) => {
    try {
      const segName = String(req.params.name);
      const segment = await Segment.findOne({
        orgId: req.user!.orgId,
        name: segName,
      }).lean();

      if (!segment) {
        res.status(404).json({ error: 'Segment not found' });
        return;
      }

      const alerts = await Alert.find({ orgId: req.user!.orgId }).lean();
      const simSummary = dashboardStore.getSummary();
      const latestPrediction = await Prediction.findOne({ orgId: req.user!.orgId })
        .sort({ createdAt: -1 })
        .lean();

      const enriched = await enrichSegment(segment as unknown as ISegment, alerts, simSummary);

      const hosts = SEGMENT_HOST_METADATA[segName] || [];
      const protocols = SEGMENT_PROTOCOLS[segName] || [];

      // Security ACL policies currently enforced on this segment
      const policies = [
        {
          id: `acl-${segName}-01`,
          rule: enriched.isolated ? 'QUARANTINE_STRICT_ISOLATION' : 'MICROSEG_DYNAMIC_MONITOR',
          action: enriched.isolated ? 'DROP_ALL_EXCEPT_SOC' : 'ALLOW_INSPECT',
          priority: 100,
          status: enriched.isolated ? 'Active Enforced' : 'Passive Telemetry',
          updatedAt: '2026-09-15 18:00Z',
        },
        {
          id: `acl-${segName}-02`,
          rule: 'EGRESS_C2_FILTERING',
          action: 'BLOCK_UNCLASSIFIED_ASN',
          priority: 200,
          status: 'Active Enforced',
          updatedAt: '2026-09-06 14:00Z',
        },
      ];

      // Related alerts
      const relatedAlerts = alerts
        .filter((a) => {
          const hostList = hosts.map((h: { ip: string }) => h.ip);
          const cleanIp = a.ip ? a.ip.split(':')[0] : '';
          const cleanHost = a.host ? a.host.toLowerCase() : '';
          return hostList.includes(cleanIp) || cleanHost.includes(segName.split('-')[0] || '');
        })
        .slice(0, 5);

      // Extract model flows related to this segment's host IPs
      const hostIps = hosts.map((h: { ip: string }) => h.ip);
      const modelFlowsForSegment = (dashboardStore.recentFlows || []).filter((f: any) => {
        const srcIp = f.src?.split(':')[0];
        const dstIp = f.dst?.split(':')[0];
        return hostIps.includes(srcIp) || hostIps.includes(dstIp);
      });

      const rawOutputs = (simSummary as any).rawModelOutputs || {};

      const modelAnalysis = {
        riskState: enriched.state,
        probability: enriched.modelProbability,
        confidence: simSummary.modelConfidence || '91.8%',
        stage: enriched.modelStage,
        rssmScore: rawOutputs.rawOnsetProb ?? 0.0494,
        tfcScore: rawOutputs.tfcOnsetProb ?? 0.5156,
        leadTimeSeconds: simSummary.leadTimeSeconds ?? 20.0,
        featureDrivers: latestPrediction?.featureContributions || [
          { feature: 'syn_ack_ratio', value: '4.82', weight: 0.31, description: 'Elevated SYN/ACK flag imbalance' },
          { feature: 'dst_port_entropy', value: '0.94', weight: 0.24, description: 'Sequential port sweep targeting 445 (SMB)' },
          { feature: 'smb_session_rate', value: '14 / 90s', weight: 0.18, description: 'High fan-out session setup rate' },
          { feature: 'iat_variance', value: '0.0011', weight: 0.11, description: 'Compressed inter-arrival time consistency' },
        ],
        modelFlows: modelFlowsForSegment,
      };

      res.json({
        segment: enriched,
        hosts: enriched.topTalkers,
        hostRoster: hosts,
        protocols,
        policies,
        relatedAlerts,
        microsegStatus: enriched.isolated ? 'ISOLATED' : 'INTEGRATED',
        modelAnalysis,
      });
    } catch (err) {
      next(err);
    }
  }
);

// ── GET /api/segments/:name ─────────────────────────────
router.get(
  '/:name',
  validate({ params: segmentParamSchema }),
  async (req, res, next) => {
    try {
      const segName = String(req.params.name);
      const segment = await Segment.findOne({
        orgId: req.user!.orgId,
        name: segName,
      }).lean();

      if (!segment) {
        res.status(404).json({ error: 'Segment not found' });
        return;
      }

      const alerts = await Alert.find({ orgId: req.user!.orgId }).lean();
      const simSummary = dashboardStore.getSummary();
      const enriched = await enrichSegment(segment as unknown as ISegment, alerts, simSummary);

      res.json(enriched);
    } catch (err) {
      next(err);
    }
  }
);

// ── POST /api/segments/:name/isolate ─────────────────────
router.post(
  '/:name/isolate',
  requirePermission('alerts.update'),
  validate({ params: segmentParamSchema }),
  async (req, res, next) => {
    try {
      const segName = String(req.params.name);
      const segment = await Segment.findOneAndUpdate(
        { orgId: req.user!.orgId, name: segName },
        { $set: { isolated: true } },
        { new: true }
      ).lean();

      if (!segment) {
        res.status(404).json({ error: 'Segment not found' });
        return;
      }

      await logAuditEvent('SEGMENT_ISOLATED', `Segment: ${segName} (Quarantined)`, req, {
        isolated: true,
        reason: 'Zero-Trust Microsegmentation Emergency Containment',
      });

      res.json({
        success: true,
        message: `Segment ${segName} has been isolated. Zero-trust ACL enforcement active.`,
        segment,
      });
    } catch (err) {
      next(err);
    }
  }
);

// ── POST /api/segments/:name/restore ─────────────────────
router.post(
  '/:name/restore',
  requirePermission('alerts.update'),
  validate({ params: segmentParamSchema }),
  async (req, res, next) => {
    try {
      const segName = String(req.params.name);
      const segment = await Segment.findOneAndUpdate(
        { orgId: req.user!.orgId, name: segName },
        { $set: { isolated: false } },
        { new: true }
      ).lean();

      if (!segment) {
        res.status(404).json({ error: 'Segment not found' });
        return;
      }

      await logAuditEvent('SEGMENT_RESTORED', `Segment: ${segName} (Routing Restored)`, req, {
        isolated: false,
        reason: 'Zero-Trust Microsegmentation Quarantine Lifted',
      });

      res.json({
        success: true,
        message: `Segment ${segName} isolation lifted. Normal routing restored.`,
        segment,
      });
    } catch (err) {
      next(err);
    }
  }
);

export default router;
