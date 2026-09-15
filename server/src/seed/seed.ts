import mongoose from 'mongoose';
import { config } from 'dotenv';
config();

import { connectDB } from '../config/db.js';
import { Organisation } from '../models/Organisation.js';
import { User } from '../models/User.js';
import { Alert } from '../models/Alert.js';
import { Flow } from '../models/Flow.js';
import { Prediction } from '../models/Prediction.js';
import { Segment } from '../models/Segment.js';
import { AuditEntry } from '../models/AuditEntry.js';
import { ModelVersion } from '../models/ModelVersion.js';
import { Ingestion } from '../models/Ingestion.js';
import { Report } from '../models/Report.js';
import { Simulation } from '../models/Simulation.js';
import { Settings } from '../models/Settings.js';
import { hashPassword } from '../utils/hash.js';

async function seed() {
  await connectDB();
  console.log('🌱 Seeding database...\n');

  // Clear all collections
  await Promise.all([
    Organisation.deleteMany({}),
    User.deleteMany({}),
    Alert.deleteMany({}),
    Flow.deleteMany({}),
    Prediction.deleteMany({}),
    Segment.deleteMany({}),
    AuditEntry.deleteMany({}),
    ModelVersion.deleteMany({}),
    Ingestion.deleteMany({}),
    Report.deleteMany({}),
    Simulation.deleteMany({}),
    Settings.deleteMany({}),
  ]);

  // ── Organisations ───────────────────────────────────────
  const [northwind, harbour, meridian] = await Organisation.insertMany([
    { name: 'Northwind Energy', hosts: 1462, modelVersion: 'wm-v4.2.1', datasetAccess: ['CIC-IDS-2018', 'CTU-13'] },
    { name: 'Harbour Freight Rail', hosts: 884, modelVersion: 'wm-v4.1.0', datasetAccess: ['CTU-13'] },
    { name: 'Meridian Health', hosts: 2210, modelVersion: 'wm-v4.2.1', datasetAccess: ['CIC-IDS-2018'] },
  ]);
  console.log('✅ Organisations: 3');

  // ── Users ───────────────────────────────────────────────
  const pw = await hashPassword('Aegis2026!test');
  const pwReal = await hashPassword('1234ASdf@/12');

  const [userSC, userRM, userAK, userAdmin] = await User.insertMany([
    { email: 'hackinghackers2026@gmail.com', passwordHash: pwReal, name: 'Saksham Chhabra', initials: 'SC', role: 'SOC Lead', orgId: northwind._id, emailVerified: true },
    { email: 'r.mehta@northwind.example', passwordHash: pw, name: 'Riya Mehta', initials: 'RM', role: 'Analyst', orgId: northwind._id, emailVerified: true },
    { email: 'a.kaur@northwind.example', passwordHash: pw, name: 'Amrit Kaur', initials: 'AK', role: 'SOC Lead', orgId: northwind._id, emailVerified: true },
    { email: 'admin@northwind.example', passwordHash: pw, name: 'System Admin', initials: 'SA', role: 'Super Admin', orgId: northwind._id, emailVerified: true },
  ]);
  console.log('✅ Users: 4');

  // ── Alerts (from telemetry.ts) ──────────────────────────
  const baseTime = new Date('2026-09-06T14:40:00Z');

  await Alert.insertMany([
    { alertId: 'AV-4821', host: 'fin-db-02', ip: '10.24.8.31', stage: 'Lateral movement', probability: 0.88, state: 'critical', reason: 'Sequential SMB session setup across 14 hosts in 90s', detectedAt: new Date('2026-09-06T14:38:00Z'), status: 'New', assignedTo: userSC._id, orgId: northwind._id },
    { alertId: 'AV-4820', host: 'edge-gw-01', ip: '10.24.1.4', stage: 'C2', probability: 0.74, state: 'critical', reason: 'Periodic 58s beacon to unclassified ASN', detectedAt: new Date('2026-09-06T14:21:00Z'), status: 'New', assignedTo: userRM._id, orgId: northwind._id },
    { alertId: 'AV-4817', host: 'ops-jump-05', ip: '10.24.4.19', stage: 'Initial access', probability: 0.61, state: 'watch', reason: 'Elevated SYN/ACK ratio on ports 22, 23, 445', detectedAt: new Date('2026-09-06T13:57:00Z'), status: 'Acknowledged', assignedTo: userSC._id, orgId: northwind._id },
    { alertId: 'AV-4814', host: 'hr-file-11', ip: '10.24.12.77', stage: 'Recon', probability: 0.52, state: 'watch', reason: 'Sweep of 212 closed ports from single source', detectedAt: new Date('2026-09-06T13:12:00Z'), status: 'Investigating', assignedTo: userAK._id, orgId: northwind._id },
    { alertId: 'AV-4809', host: 'dev-ci-03', ip: '10.24.19.8', stage: 'Exfiltration', probability: 0.69, state: 'watch', reason: 'Outbound volume 41x host baseline over 6 windows', detectedAt: new Date('2026-09-06T12:40:00Z'), status: 'Investigating', assignedTo: userRM._id, orgId: northwind._id },
    { alertId: 'AV-4801', host: 'print-svc-02', ip: '10.24.3.55', stage: 'Recon', probability: 0.28, state: 'normal', reason: 'Scan traced to scheduled vulnerability assessment', detectedAt: new Date('2026-09-06T11:04:00Z'), status: 'Resolved', assignedTo: userAK._id, orgId: northwind._id },
  ]);
  console.log('✅ Alerts: 6');

  // ── Flows (from telemetry.ts) ───────────────────────────
  await Flow.insertMany([
    { src: '10.24.8.31:49722', dst: '10.24.8.14:445', proto: 'TCP', flags: '0x018', bytes: 1284551, packets: 2210, duration: 88.4, iatMean: 0.04, iatVar: 0.0011, iatMax: 0.91, ttlVar: 3.2, window: 64240, retrans: 41, score: 0.91, orgId: northwind._id, timestamp: baseTime },
    { src: '10.24.1.4:51344', dst: '203.0.113.77:8443', proto: 'TCP', flags: '0x010', bytes: 44120, packets: 388, duration: 604.1, iatMean: 58.02, iatVar: 0.44, iatMax: 59.9, ttlVar: 0.4, window: 29200, retrans: 2, score: 0.83, orgId: northwind._id, timestamp: baseTime },
    { src: '10.24.4.19:44100', dst: '10.24.4.20:22', proto: 'TCP', flags: '0x002', bytes: 3120, packets: 52, duration: 4.2, iatMean: 0.08, iatVar: 0.0004, iatMax: 0.22, ttlVar: 0.0, window: 64240, retrans: 0, score: 0.66, orgId: northwind._id, timestamp: baseTime },
    { src: '10.24.12.77:60122', dst: '10.24.12.0/24:*', proto: 'TCP', flags: '0x002', bytes: 18422, packets: 424, duration: 31.7, iatMean: 0.07, iatVar: 0.0002, iatMax: 0.19, ttlVar: 0.1, window: 1024, retrans: 0, score: 0.58, orgId: northwind._id, timestamp: baseTime },
    { src: '10.24.19.8:33012', dst: '198.51.100.20:443', proto: 'TCP', flags: '0x018', bytes: 88214773, packets: 61240, duration: 1811.9, iatMean: 0.03, iatVar: 0.0009, iatMax: 2.14, ttlVar: 1.8, window: 65535, retrans: 118, score: 0.71, orgId: northwind._id, timestamp: baseTime },
    { src: '10.24.6.42:57812', dst: '10.24.6.9:3389', proto: 'TCP', flags: '0x012', bytes: 240110, packets: 1804, duration: 402.6, iatMean: 0.22, iatVar: 0.014, iatMax: 3.4, ttlVar: 0.6, window: 64240, retrans: 6, score: 0.44, orgId: northwind._id, timestamp: baseTime },
    { src: '10.24.3.55:5353', dst: '224.0.0.251:5353', proto: 'UDP', flags: '—', bytes: 9820, packets: 142, duration: 300.0, iatMean: 2.11, iatVar: 0.08, iatMax: 4.9, ttlVar: 0.0, window: 0, retrans: 0, score: 0.12, orgId: northwind._id, timestamp: baseTime },
    { src: '10.24.9.18:49001', dst: '10.24.2.5:53', proto: 'UDP', flags: '—', bytes: 4210, packets: 88, duration: 120.4, iatMean: 1.37, iatVar: 0.05, iatMax: 3.1, ttlVar: 0.0, window: 0, retrans: 0, score: 0.09, orgId: northwind._id, timestamp: baseTime },
  ]);
  console.log('✅ Flows: 8');

  // ── Prediction (latest) ─────────────────────────────────
  const probabilitySeries = [
    0.08, 0.11, 0.09, 0.13, 0.1, 0.12, 0.15, 0.14, 0.12, 0.18, 0.21, 0.19, 0.17,
    0.22, 0.26, 0.24, 0.29, 0.27, 0.33, 0.31, 0.36, 0.34, 0.4, 0.38, 0.44, 0.47,
    0.43, 0.5, 0.55, 0.52, 0.49, 0.58, 0.63, 0.6, 0.57, 0.66, 0.71, 0.68, 0.74,
    0.79, 0.76, 0.72, 0.81, 0.86, 0.83, 0.79, 0.84, 0.88,
  ];

  await Prediction.create({
    orgId: northwind._id,
    segmentName: 'corp-core',
    windowStart: new Date('2026-09-06T14:35:00Z'),
    windowEnd: new Date('2026-09-06T14:40:00Z'),
    probability: 0.88,
    stage: 'Lateral movement',
    confidence: 0.94,
    series: probabilitySeries,
    featureContributions: [
      { feature: 'syn_ack_ratio', value: '4.82', weight: 0.31 },
      { feature: 'dst_port_entropy', value: '0.94', weight: 0.24 },
      { feature: 'smb_session_rate', value: '14 / 90s', weight: 0.18 },
      { feature: 'iat_variance', value: '0.0011', weight: 0.11 },
      { feature: 'retransmit_count', value: '41', weight: 0.08 },
      { feature: 'ttl_variance', value: '3.2', weight: -0.06 },
      { feature: 'flow_duration', value: '88.4s', weight: -0.09 },
    ],
    summary: 'This window was flagged primarily due to elevated SYN/ACK ratio and sequential port access on ports 22, 23 and 445, combined with 14 SMB session setups from fin-db-02 to distinct hosts inside 90 seconds. Flow duration and TTL variance argue slightly against compromise but do not offset the session fan-out.',
    modelVersion: 'wm-v4.2.1',
  });
  console.log('✅ Predictions: 1');

  // ── Segments (from telemetry.ts) ────────────────────────
  await Segment.insertMany([
    { name: 'corp-core', hosts: 412, activeAlerts: 2, trafficVolume: 34, state: 'watch', lastIncident: '14:38Z', orgId: northwind._id },
    { name: 'finance', hosts: 128, activeAlerts: 3, trafficVolume: 22, state: 'critical', lastIncident: '14:38Z', orgId: northwind._id },
    { name: 'ot-plant-a', hosts: 96, activeAlerts: 0, trafficVolume: 14, state: 'normal', lastIncident: '—', orgId: northwind._id },
    { name: 'dmz-edge', hosts: 34, activeAlerts: 1, trafficVolume: 11, state: 'watch', lastIncident: '14:21Z', orgId: northwind._id },
    { name: 'dev-build', hosts: 210, activeAlerts: 1, trafficVolume: 9, state: 'watch', lastIncident: '12:40Z', orgId: northwind._id },
    { name: 'guest-wifi', hosts: 508, activeAlerts: 0, trafficVolume: 6, state: 'normal', lastIncident: '—', orgId: northwind._id },
    { name: 'ot-plant-b', hosts: 74, activeAlerts: 0, trafficVolume: 4, state: 'normal', lastIncident: '—', orgId: northwind._id },
  ]);
  console.log('✅ Segments: 7');

  // ── Audit entries (from telemetry.ts) ───────────────────
  await AuditEntry.insertMany([
    { timestamp: new Date('2026-09-06T14:39:02Z'), actor: 's.chhabra@northwind.example', event: 'ALERT_ACKNOWLEDGED', target: 'AV-4817', orgId: northwind._id },
    { timestamp: new Date('2026-09-06T14:31:44Z'), actor: 'system', event: 'INFERENCE_RUN', target: 'window 14:25–14:30', orgId: northwind._id },
    { timestamp: new Date('2026-09-06T14:02:10Z'), actor: 'r.mehta@northwind.example', event: 'REPORT_GENERATED', target: 'report/weekly-fin', orgId: northwind._id },
    { timestamp: new Date('2026-09-06T13:48:51Z'), actor: 'a.kaur@northwind.example', event: 'ALERT_ACKNOWLEDGED', target: 'AV-4814 → Investigating', orgId: northwind._id },
    { timestamp: new Date('2026-09-06T12:20:03Z'), actor: 's.chhabra@northwind.example', event: 'MODEL_PROMOTED', target: 'wm-v4.2.1', orgId: northwind._id },
    { timestamp: new Date('2026-09-06T11:59:17Z'), actor: 'system', event: 'INGESTION_COMPLETED', target: 'cicids-2018-day3.pcap', orgId: northwind._id },
    { timestamp: new Date('2026-09-06T09:14:38Z'), actor: 'admin@northwind.example', event: 'USER_ROLE_CHANGED', target: 'a.kaur → SOC Lead', orgId: northwind._id },
  ]);
  console.log('✅ Audit entries: 7');

  // ── Model versions ──────────────────────────────────────
  await ModelVersion.insertMany([
    {
      version: 'wm-v4.2.1', releasedAt: new Date('2026-09-06'), note: 'F1 +0.021, FPR −0.006', isProduction: true, promotedBy: userSC._id,
      metrics: { cicIds: { f1: 0.943, precision: 0.951, recall: 0.936, fpr: 0.014 }, ctu13: { f1: 0.918, precision: 0.927, recall: 0.909, fpr: 0.021 } },
      confusionMatrices: { cicIds: { cells: [948, 14, 39, 999] }, ctu13: { cells: [930, 22, 48, 980] } },
      lossCurve: { train: [0.68, 0.51, 0.4, 0.33, 0.28, 0.24, 0.21, 0.19, 0.17, 0.16, 0.15, 0.14], val: [0.71, 0.55, 0.45, 0.38, 0.34, 0.31, 0.29, 0.28, 0.27, 0.27, 0.26, 0.26] },
    },
    {
      version: 'wm-v4.1.0', releasedAt: new Date('2026-08-22'), note: 'F1 +0.014, recall +0.019', isProduction: false,
      metrics: { cicIds: { f1: 0.922, precision: 0.935, recall: 0.917, fpr: 0.02 }, ctu13: { f1: 0.901, precision: 0.912, recall: 0.895, fpr: 0.028 } },
      confusionMatrices: { cicIds: { cells: [812, 91, 143, 954] }, ctu13: { cells: [820, 85, 130, 945] } },
      lossCurve: { train: [0.7, 0.54, 0.43, 0.36, 0.31, 0.27, 0.24, 0.22, 0.2, 0.19, 0.18, 0.17], val: [0.74, 0.58, 0.48, 0.42, 0.38, 0.35, 0.33, 0.32, 0.31, 0.3, 0.3, 0.29] },
    },
    {
      version: 'wm-v4.0.3', releasedAt: new Date('2026-08-04'), note: 'FPR −0.011', isProduction: false,
      metrics: { cicIds: { f1: 0.908, precision: 0.92, recall: 0.898, fpr: 0.031 }, ctu13: { f1: 0.887, precision: 0.9, recall: 0.876, fpr: 0.039 } },
      confusionMatrices: { cicIds: { cells: [800, 98, 155, 947] }, ctu13: { cells: [790, 100, 160, 930] } },
      lossCurve: { train: [0.72, 0.56, 0.45, 0.39, 0.34, 0.3, 0.27, 0.25, 0.23, 0.22, 0.21, 0.2], val: [0.76, 0.6, 0.5, 0.44, 0.4, 0.37, 0.35, 0.34, 0.33, 0.32, 0.32, 0.31] },
    },
    {
      version: 'wm-v3.9.0', releasedAt: new Date('2026-07-15'), note: 'baseline for current architecture', isProduction: false,
      metrics: { cicIds: { f1: 0.894, precision: 0.905, recall: 0.884, fpr: 0.042 }, ctu13: { f1: 0.871, precision: 0.885, recall: 0.86, fpr: 0.05 } },
      confusionMatrices: { cicIds: { cells: [780, 110, 170, 940] }, ctu13: { cells: [760, 120, 175, 925] } },
      lossCurve: { train: [0.75, 0.6, 0.5, 0.44, 0.39, 0.35, 0.32, 0.3, 0.28, 0.27, 0.26, 0.25], val: [0.8, 0.65, 0.55, 0.49, 0.45, 0.42, 0.4, 0.38, 0.37, 0.36, 0.36, 0.35] },
    },
  ]);
  console.log('✅ Model versions: 4');

  // ── Ingestion history ───────────────────────────────────
  await Ingestion.insertMany([
    { filename: 'cicids-2018-day3.pcap', datasetType: 'CIC-IDS-2018', fileSize: 4509715660, storagePath: 's3://pcap-store-eu-west/cicids-2018-day3.pcap', orgId: northwind._id, uploadedBy: userSC._id, status: 'complete', pipelineSteps: [{ name: 'Parsing', status: 'done' }, { name: 'Feature extraction', status: 'done' }, { name: 'Normalisation', status: 'done' }, { name: 'Inference', status: 'done' }, { name: 'Explanation', status: 'done' }], createdAt: new Date('2026-09-06T11:59:00Z') },
    { filename: 'ctu13-scenario-9.pcap', datasetType: 'CTU-13', fileSize: 1181116006, storagePath: 's3://pcap-store-eu-west/ctu13-scenario-9.pcap', orgId: northwind._id, uploadedBy: userRM._id, status: 'complete', pipelineSteps: [{ name: 'Parsing', status: 'done' }, { name: 'Feature extraction', status: 'done' }, { name: 'Normalisation', status: 'done' }, { name: 'Inference', status: 'done' }, { name: 'Explanation', status: 'done' }], createdAt: new Date('2026-09-05T22:14:00Z') },
    { filename: 'corp-core-netflow.csv', datasetType: 'Custom upload', fileSize: 192937984, storagePath: 's3://pcap-store-eu-west/corp-core-netflow.csv', orgId: northwind._id, uploadedBy: userAK._id, status: 'complete', pipelineSteps: [{ name: 'Parsing', status: 'done' }, { name: 'Feature extraction', status: 'done' }, { name: 'Normalisation', status: 'done' }, { name: 'Inference', status: 'done' }, { name: 'Explanation', status: 'done' }], createdAt: new Date('2026-09-05T09:02:00Z') },
    { filename: 'dmz-edge-partial.pcap', datasetType: 'Custom upload', fileSize: 641728512, storagePath: 's3://pcap-store-eu-west/dmz-edge-partial.pcap', orgId: northwind._id, uploadedBy: userSC._id, status: 'failed', pipelineSteps: [{ name: 'Parsing', status: 'failed' }, { name: 'Feature extraction', status: 'pending' }, { name: 'Normalisation', status: 'pending' }, { name: 'Inference', status: 'pending' }, { name: 'Explanation', status: 'pending' }], createdAt: new Date('2026-09-04T17:41:00Z') },
  ]);
  console.log('✅ Ingestions: 4');

  // ── Reports ─────────────────────────────────────────────
  await Report.insertMany([
    { name: 'weekly-fin-2026-w36.pdf', scope: 'finance · 7d', format: 'PDF', timeWindow: { start: new Date('2026-08-30'), end: new Date('2026-09-06') }, segmentOrAlert: 'finance', fileSize: 2516582, storagePath: 'reports/weekly-fin-2026-w36.pdf', orgId: northwind._id, createdBy: userRM._id, status: 'complete', createdAt: new Date('2026-09-06T14:02:00Z') },
    { name: 'AV-4814-incident.pdf', scope: 'alert AV-4814', format: 'PDF', timeWindow: { start: new Date('2026-09-05'), end: new Date('2026-09-05') }, segmentOrAlert: 'AV-4814', fileSize: 1153433, storagePath: 'reports/AV-4814-incident.pdf', orgId: northwind._id, createdBy: userAK._id, status: 'complete', createdAt: new Date('2026-09-05T18:20:00Z') },
    { name: 'corp-core-flows.csv', scope: 'corp-core · 24h', format: 'CSV', timeWindow: { start: new Date('2026-09-03'), end: new Date('2026-09-04') }, segmentOrAlert: 'corp-core', fileSize: 19818086, storagePath: 'reports/corp-core-flows.csv', orgId: northwind._id, createdBy: userSC._id, status: 'complete', createdAt: new Date('2026-09-04T09:44:00Z') },
  ]);
  console.log('✅ Reports: 3');

  // ── Simulation ──────────────────────────────────────────
  await Simulation.create({
    orgId: northwind._id,
    segmentName: 'corp-core',
    perturbation: 'Simulate lateral movement from fin-db-02',
    baseState: { hosts: 412, flows: 12481, probability: 0.88 },
    forecastSeries: [0.88, 0.9, 0.91, 0.89, 0.93, 0.95, 0.94, 0.96],
    actualSeries: [0.88, 0.87, 0.85, 0.88, 0.84, 0.81, 0.83, 0.8],
    divergence: [
      { step: 'k+1', predicted: 0.9, observed: 0.87 },
      { step: 'k+2', predicted: 0.91, observed: 0.85 },
      { step: 'k+4', predicted: 0.95, observed: 0.81 },
      { step: 'k+6', predicted: 0.96, observed: 0.8 },
    ],
    steps: 8,
    status: 'complete',
  });
  console.log('✅ Simulations: 1');

  // ── Settings ────────────────────────────────────────────
  await Settings.create({
    orgId: northwind._id,
    modelConfig: { windowK: 8, alertThreshold: 0.65, retrainingSchedule: 'nightly 02:00Z' },
    dataSources: [
      { name: 'pcap-store-eu-west', type: 'S3', status: 'connected', note: 'S3 · 4.2 TB retained' },
      { name: 'netflow-collector-01', type: 'IPFIX', status: 'connected', note: 'IPFIX · 12k flows/min' },
      { name: 'netflow-collector-02', type: 'IPFIX', status: 'disconnected', note: 'no data for 41m' },
    ],
    notifications: [
      { label: 'Email me when probability crosses the threshold', enabled: true },
      { label: 'Notify the on-call channel for critical states only', enabled: true },
      { label: 'Daily digest of watch-state segments', enabled: true },
    ],
    integrations: {
      apiKeyHash: '',
      apiKeyLastFour: '3f9c',
      webhookUrl: 'https://soc.northwind.example/hooks/aegis',
    },
  });
  console.log('✅ Settings: 1');

  // ── Summary ─────────────────────────────────────────────
  console.log('\n🎉 Seed complete!');
  console.log('\n📋 Login credentials:');
  console.log('   hackinghackers2026@gmail.com / 1234ASdf@/12  (SOC Lead) ← YOUR LOGIN');
  console.log('   r.mehta@northwind.example    / Aegis2026!test (Analyst)');
  console.log('   a.kaur@northwind.example     / Aegis2026!test (SOC Lead)');
  console.log('   admin@northwind.example      / Aegis2026!test (Super Admin)');

  await mongoose.disconnect();
  process.exit(0);
}

seed().catch((err) => {
  console.error('Seed failed:', err);
  process.exit(1);
});
