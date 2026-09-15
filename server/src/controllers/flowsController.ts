import type { Request, Response, NextFunction } from 'express';
import { Flow } from '../models/Flow.js';
import { Settings } from '../models/Settings.js';
import { dashboardStore } from '../models/dashboardModel.js';
import { getReplayDataset } from '../services/replayService.js';
import { generatePacketSequence, type IPacketFrame } from '../services/packetDissectorService.js';

export interface IEnrichedFlow {
  _id: string;
  src: string;
  dst: string;
  proto: string;
  service: string;
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
  riskState: 'normal' | 'watch' | 'critical';
  mitreTactic?: string;
  mitreTechnique?: string;
  timestamp: string;
  packetSequence: IPacketFrame[];
}

function resolveService(portStr?: string): string {
  const port = Number(portStr);
  switch (port) {
    case 53:
      return 'DNS';
    case 80:
      return 'HTTP';
    case 443:
      return 'HTTPS';
    case 445:
      return 'SMB';
    case 139:
      return 'NetBIOS';
    case 22:
      return 'SSH';
    case 3389:
      return 'RDP';
    case 8080:
      return 'HTTP-Alt';
    case 8443:
      return 'HTTPS-Alt';
    case 88:
      return 'Kerberos';
    case 389:
    case 636:
      return 'LDAP';
    case 1433:
      return 'MSSQL';
    default:
      return 'TCP-Custom';
  }
}

function getBackgroundBaselineFlows(windowIndex: number, baseTimestamp: string): Array<Omit<IEnrichedFlow, '_id' | 'packetSequence'>> {
  // Deterministic background traffic variations based on window index
  const jitter = (windowIndex % 10) * 0.05;
  return [
    {
      src: '172.31.69.28:51220',
      dst: '172.31.0.2:53',
      proto: 'UDP',
      service: 'DNS',
      flags: '—',
      bytes: 840 + Math.round(jitter * 200),
      packets: 12,
      duration: 1.2,
      iatMean: 0.12,
      iatVar: 0.005,
      iatMax: 0.32,
      ttlVar: 0.0,
      window: 0,
      retrans: 0,
      score: 0.08,
      riskState: 'normal',
      timestamp: baseTimestamp,
    },
    {
      src: '172.31.69.44:49810',
      dst: '172.31.69.1:88',
      proto: 'TCP',
      service: 'Kerberos',
      flags: '0x018',
      bytes: 3420 + Math.round(jitter * 500),
      packets: 48,
      duration: 3.4,
      iatMean: 0.08,
      iatVar: 0.001,
      iatMax: 0.22,
      ttlVar: 0.2,
      window: 64240,
      retrans: 0,
      score: 0.09,
      riskState: 'normal',
      timestamp: baseTimestamp,
    },
    {
      src: '172.31.69.28:49910',
      dst: '52.216.144.32:443',
      proto: 'TCP',
      service: 'HTTPS',
      flags: '0x018',
      bytes: 48200 + Math.round(jitter * 8000),
      packets: 320,
      duration: 14.8,
      iatMean: 0.04,
      iatVar: 0.002,
      iatMax: 0.45,
      ttlVar: 0.8,
      window: 65535,
      retrans: 1,
      score: 0.12,
      riskState: 'normal',
      timestamp: baseTimestamp,
    },
    {
      src: '172.31.69.44:50110',
      dst: '172.31.69.12:1433',
      proto: 'TCP',
      service: 'MSSQL',
      flags: '0x018',
      bytes: 28400 + Math.round(jitter * 4000),
      packets: 190,
      duration: 8.5,
      iatMean: 0.05,
      iatVar: 0.003,
      iatMax: 0.38,
      ttlVar: 0.4,
      window: 64240,
      retrans: 0,
      score: 0.11,
      riskState: 'normal',
      timestamp: baseTimestamp,
    },
    {
      src: '172.31.69.19:49230',
      dst: '172.31.0.2:53',
      proto: 'UDP',
      service: 'DNS',
      flags: '—',
      bytes: 1240,
      packets: 18,
      duration: 1.8,
      iatMean: 0.09,
      iatVar: 0.004,
      iatMax: 0.28,
      ttlVar: 0.0,
      window: 0,
      retrans: 0,
      score: 0.07,
      riskState: 'normal',
      timestamp: baseTimestamp,
    },
    {
      src: '172.31.69.25:51440',
      dst: '172.31.69.1:389',
      proto: 'TCP',
      service: 'LDAP',
      flags: '0x018',
      bytes: 14200,
      packets: 96,
      duration: 6.2,
      iatMean: 0.06,
      iatVar: 0.002,
      iatMax: 0.24,
      ttlVar: 0.1,
      window: 64240,
      retrans: 0,
      score: 0.10,
      riskState: 'normal',
      timestamp: baseTimestamp,
    },
  ];
}

// ── GET /api/flows ──────────────────────────────────────
export async function listFlows(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const dataset = getReplayDataset();
    const query = req.query as any;

    const page = Math.max(1, Number(query.page) || 1);
    const limit = Math.max(1, Math.min(100, Number(query.limit) || 50));
    const search = (query.search as string)?.trim().toLowerCase();
    const minScore = query.minScore !== undefined && query.minScore !== '' ? Number(query.minScore) : undefined;
    const flaggedOnly = query.flaggedOnly === 'true' || query.flaggedOnly === true;
    const protoFilter = (query.proto as string)?.toUpperCase();
    const serviceFilter = (query.service as string)?.toUpperCase();

    // Determine target window index & live state
    const isLive = query.live === 'true' || (query.windowIndex === undefined && query.scrub === undefined);
    let targetIndex: number;

    if (isLive) {
      targetIndex = dashboardStore.actual_window_index;
    } else if (query.windowIndex !== undefined && query.windowIndex !== '') {
      targetIndex = Number(query.windowIndex);
    } else if (query.scrub !== undefined && query.scrub !== '') {
      const scrub = Math.max(0, Math.min(100, Number(query.scrub)));
      targetIndex = Math.round(dataset.startIndex + (scrub / 100) * (dataset.endIndex - dataset.startIndex));
    } else {
      targetIndex = dashboardStore.actual_window_index;
    }

    targetIndex = Math.max(dataset.startIndex, Math.min(dataset.endIndex, targetIndex));
    const win = dataset.windows.find((w) => w.windowIndex === targetIndex) || dataset.windows[0]!;

    const currentProbability = isLive ? dashboardStore.summary.infiltrationProbability : win.probability;
    const currentStage = isLive ? dashboardStore.summary.currentStage : win.stage;

    // 1. Gather benchmark flows for this window
    const windowFlows: Array<Omit<IEnrichedFlow, '_id' | 'packetSequence'>> = (win.flows || []).map((f) => {
      const [, dstPortStr] = f.dst.split(':');
      const service = resolveService(dstPortStr);
      const score = Number(f.score.toFixed(2));
      const riskState: 'normal' | 'watch' | 'critical' =
        score >= 0.7 ? 'critical' : score >= 0.4 ? 'watch' : 'normal';

      let mitreTactic: string | undefined;
      let mitreTechnique: string | undefined;
      if (score >= 0.7) {
        mitreTactic = currentStage;
        mitreTechnique = win.techniqueId ? `${win.techniqueId}: ${win.techniqueName}` : 'T1021.002: SMB Admin Shares';
      } else if (score >= 0.4) {
        mitreTactic = 'Reconnaissance';
        mitreTechnique = 'T1046: Network Service Scanning';
      }

      const packetsCount = Math.max(12, Math.round(f.bytes / 120));
      const duration = Number((f.bytes > 50000 ? 45.2 : 2.4).toFixed(1));
      const iatMean = Number((f.bytes > 50000 ? 0.04 : 0.08).toFixed(3));
      const iatVar = Number((f.bytes > 50000 ? 0.001 : 0.004).toFixed(4));
      const iatMax = Number((f.bytes > 50000 ? 0.91 : 0.22).toFixed(2));
      const flags = f.proto === 'TCP' ? (score >= 0.7 ? '0x018' : score >= 0.4 ? '0x002' : '0x010') : '—';

      return {
        src: f.src,
        dst: f.dst,
        proto: f.proto,
        service,
        flags,
        bytes: f.bytes,
        packets: packetsCount,
        duration,
        iatMean,
        iatVar,
        iatMax,
        ttlVar: score >= 0.7 ? 2.8 : 0.4,
        window: f.proto === 'TCP' ? 64240 : 0,
        retrans: score >= 0.7 ? 14 : 0,
        score,
        riskState,
        mitreTactic,
        mitreTechnique,
        timestamp: win.timestampStart,
      };
    });

    // 2. Add realistic concurrent baseline flows
    const baselineFlows = getBackgroundBaselineFlows(targetIndex, win.timestampStart);

    // 3. Optional DB flows if user is authenticated and DB has flows
    let dbFlows: Array<Omit<IEnrichedFlow, '_id' | 'packetSequence'>> = [];
    if (req.user?.orgId) {
      try {
        const stored = await Flow.find({ orgId: req.user.orgId }).limit(10).lean();
        if (stored && stored.length > 0) {
          dbFlows = stored.map((sf) => {
            const [, dstPortStr] = sf.dst.split(':');
            return {
              src: sf.src,
              dst: sf.dst,
              proto: sf.proto,
              service: resolveService(dstPortStr),
              flags: sf.flags,
              bytes: sf.bytes,
              packets: sf.packets,
              duration: sf.duration,
              iatMean: sf.iatMean,
              iatVar: sf.iatVar,
              iatMax: sf.iatMax,
              ttlVar: sf.ttlVar,
              window: sf.window,
              retrans: sf.retrans,
              score: sf.score,
              riskState: sf.score >= 0.7 ? 'critical' : sf.score >= 0.4 ? 'watch' : 'normal',
              timestamp: sf.timestamp ? new Date(sf.timestamp).toISOString() : win.timestampStart,
            };
          });
        }
      } catch {
        // Continue with memory flows if DB query fails
      }
    }

    // Combine all flow candidates
    const allCandidates = [...windowFlows, ...dbFlows, ...baselineFlows];

    // Deduplicate by src + dst + proto
    const seen = new Set<string>();
    const deduplicated: Array<Omit<IEnrichedFlow, '_id' | 'packetSequence'>> = [];
    for (const f of allCandidates) {
      const key = `${f.src}->${f.dst}:${f.proto}`;
      if (!seen.has(key)) {
        seen.add(key);
        deduplicated.push(f);
      }
    }

    // Filter flows
    let filtered = deduplicated.filter((f) => {
      if (minScore !== undefined && f.score < minScore) return false;
      if (flaggedOnly && f.score < 0.65) return false;
      if (protoFilter && protoFilter !== 'ALL' && f.proto.toUpperCase() !== protoFilter) return false;
      if (serviceFilter && serviceFilter !== 'ALL' && f.service.toUpperCase() !== serviceFilter) return false;
      if (search) {
        const matchSrc = f.src.toLowerCase().includes(search);
        const matchDst = f.dst.toLowerCase().includes(search);
        const matchProto = f.proto.toLowerCase().includes(search);
        const matchService = f.service.toLowerCase().includes(search);
        const matchFlags = f.flags.toLowerCase().includes(search);
        const matchTactic = f.mitreTactic?.toLowerCase().includes(search);
        const matchTech = f.mitreTechnique?.toLowerCase().includes(search);
        if (!matchSrc && !matchDst && !matchProto && !matchService && !matchFlags && !matchTactic && !matchTech) {
          return false;
        }
      }
      return true;
    });

    // Sort by threat score descending
    filtered.sort((a, b) => b.score - a.score);

    const total = filtered.length;
    const totalPages = Math.ceil(total / limit) || 1;
    const skip = (page - 1) * limit;
    const paginatedSlice = filtered.slice(skip, skip + limit);

    // Enrich with unique ID and authentic packet sequence
    const enrichedData: IEnrichedFlow[] = paginatedSlice.map((f, i) => {
      const _id = `flow-${targetIndex}-${skip + i}`;
      const packetSequence = generatePacketSequence(f);
      return {
        _id,
        ...f,
        packetSequence,
      };
    });

    // Calculate aggregated summary statistics
    const threatFlows = filtered.filter((f) => f.score >= 0.65).length;
    const totalBytes = filtered.reduce((sum, f) => sum + f.bytes, 0);
    const totalPackets = filtered.reduce((sum, f) => sum + f.packets, 0);

    const serviceCounts: Record<string, number> = {};
    for (const f of filtered) {
      serviceCounts[f.service] = (serviceCounts[f.service] || 0) + 1;
    }
    const topService = Object.entries(serviceCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || 'TCP';

    res.json({
      isLive,
      activeLiveWindowIndex: dashboardStore.actual_window_index,
      windowIndex: targetIndex,
      timestampStart: win.timestampStart,
      phase: win.phase,
      stage: currentStage,
      probability: currentProbability,
      data: enrichedData,
      pagination: {
        page,
        limit,
        total,
        totalPages,
      },
      summary: {
        totalFlows: total,
        threatFlows,
        totalBytes,
        totalPackets,
        topService,
      },
    });
  } catch (err) {
    next(err);
  }
}

// ── GET /api/flows/:id ──────────────────────────────────
export async function getFlowById(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const id = String(req.params.id);

    // Check if it is a synthetic window flow ID: flow-<windowIndex>-<index>
    if (id.startsWith('flow-')) {
      const parts = id.split('-');
      const winIdx = Number(parts[1]) || dashboardStore.actual_window_index;
      const dataset = getReplayDataset();
      const win = dataset.windows.find((w) => w.windowIndex === winIdx) || dataset.windows[0]!;

      const targetFlow = win.flows?.[0] || {
        src: '18.219.211.138:50102',
        dst: '172.31.69.28:445',
        proto: 'TCP',
        bytes: 1284551,
        score: 0.94,
      };

      const packetSequence = generatePacketSequence(targetFlow);
      const [, dstPortStr] = targetFlow.dst.split(':');

      res.json({
        _id: id,
        ...targetFlow,
        service: resolveService(dstPortStr),
        flags: '0x018',
        packets: Math.max(12, Math.round(targetFlow.bytes / 120)),
        duration: 45.2,
        iatMean: 0.04,
        iatVar: 0.001,
        iatMax: 0.91,
        ttlVar: 2.8,
        window: 64240,
        retrans: targetFlow.score >= 0.7 ? 14 : 0,
        riskState: targetFlow.score >= 0.7 ? 'critical' : targetFlow.score >= 0.4 ? 'watch' : 'normal',
        timestamp: win.timestampStart,
        packetSequence,
      });
      return;
    }

    // Otherwise check MongoDB
    const flow = await Flow.findById(id).lean();
    if (!flow) {
      res.status(404).json({ error: 'Flow not found' });
      return;
    }

    const packetSequence = generatePacketSequence(flow);
    const [, dstPortStr] = flow.dst.split(':');

    res.json({
      ...flow,
      service: resolveService(dstPortStr),
      riskState: flow.score >= 0.7 ? 'critical' : flow.score >= 0.4 ? 'watch' : 'normal',
      packetSequence,
    });
  } catch (err) {
    next(err);
  }
}
