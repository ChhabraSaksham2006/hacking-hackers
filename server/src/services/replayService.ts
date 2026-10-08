import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import mongoose from 'mongoose';
import { Prediction, type IFeatureContribution } from '../models/Prediction.js';
import { Alert } from '../models/Alert.js';
import { Flow } from '../models/Flow.js';
import { notifyOrgUsersOfAlert } from './emailService.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let REPLAY_FILE = path.resolve(__dirname, '../data/cic_ids_2018_thursday_replay.json');
if (!fs.existsSync(REPLAY_FILE)) {
  const fallback = path.resolve(__dirname, '../../src/data/cic_ids_2018_thursday_replay.json');
  if (fs.existsSync(fallback)) {
    REPLAY_FILE = fallback;
  }
}

export interface IReplayFlow {
  src: string;
  dst: string;
  proto: string;
  bytes: number;
  score: number;
}

export interface IReplayWindow {
  windowIndex: number;
  timestampStart: string;
  timestampEnd: string;
  phase: string;
  stage: string;
  probability: number;
  confidence: number;
  riskState: 'normal' | 'watch' | 'critical';
  flowCount: number;
  isAttack: number;
  reason: string;
  techniqueId: string | null;
  techniqueName: string | null;
  featureContributions: IFeatureContribution[];
  summary: string;
  features: Record<string, number>;
  flows: IReplayFlow[];
  series: number[];
}

export interface IReplayDataset {
  dataset: string;
  targetEpisode: string;
  sourceFile: string;
  totalRecordedWindowsInFile: number;
  startIndex: number;
  attackOnsetInterval: number;
  endIndex: number;
  defaultIndex: number;
  windows: IReplayWindow[];
}

// In-memory cache of dataset and current replay pointer per org
let cachedDataset: IReplayDataset | null = null;
const orgCurrentWindow = new Map<string, number>();

/**
 * Latest prediction per org, kept in memory so automatic (ticker-driven) replay
 * steps don't have to write a Prediction document to MongoDB every 3 seconds.
 * Shape mirrors a lean Prediction document so readers can use it interchangeably.
 */
export interface ILivePredictionSnapshot {
  _id: string;
  orgId: mongoose.Types.ObjectId;
  segmentName: string;
  windowStart: Date;
  windowEnd: Date;
  probability: number;
  stage: string;
  confidence: number;
  series: number[];
  featureContributions: IFeatureContribution[];
  summary: string;
  modelVersion: string;
  createdAt: Date;
  isLiveSnapshot: true;
}

const orgLiveSnapshot = new Map<string, ILivePredictionSnapshot>();
// Last risk state seen per org — used to only touch the Alerts collection on transitions
const orgLastRiskState = new Map<string, IReplayWindow['riskState']>();

export interface IApplyWindowOptions {
  /**
   * When true (default — manual actions), writes Prediction + Flow documents and
   * always syncs the alert. When false (automatic ticker), only updates the
   * in-memory snapshot and touches Alerts only when the risk state changes.
   */
  persist?: boolean;
}

/**
 * Returns the freshest prediction for an org: the in-memory live snapshot if
 * one exists, otherwise the most recent persisted Prediction document.
 */
export async function getLatestPrediction(orgId: string | { toString(): string }) {
  const key = orgId.toString();
  const snapshot = orgLiveSnapshot.get(key);
  if (snapshot) return snapshot;
  return Prediction.findOne({ orgId: key }).sort({ windowEnd: -1 }).lean();
}

export function getReplayDataset(): IReplayDataset {
  if (!cachedDataset) {
    const raw = fs.readFileSync(REPLAY_FILE, 'utf-8');
    cachedDataset = JSON.parse(raw) as IReplayDataset;
  }
  return cachedDataset;
}

export function getCurrentWindowIndex(orgId: string): number {
  const dataset = getReplayDataset();
  return orgCurrentWindow.get(orgId) ?? dataset.attackOnsetInterval;
}

export function setCurrentWindowIndex(orgId: string, index: number): void {
  const dataset = getReplayDataset();
  const clamped = Math.max(dataset.startIndex, Math.min(dataset.endIndex, index));
  orgCurrentWindow.set(orgId, clamped);
}

export async function applyWindowToDatabase(
  orgId: string,
  windowIndex?: number,
  options: IApplyWindowOptions = {},
) {
  const persist = options.persist !== false;
  const dataset = getReplayDataset();
  const idx = windowIndex !== undefined ? windowIndex : getCurrentWindowIndex(orgId);
  const clampedIdx = Math.max(dataset.startIndex, Math.min(dataset.endIndex, idx));
  orgCurrentWindow.set(orgId, clampedIdx);

  const win = dataset.windows.find((w) => w.windowIndex === clampedIdx) || dataset.windows[0];
  const orgObjectId = new mongoose.Types.ObjectId(orgId);
  const now = new Date();

  const predictionFields = {
    orgId: orgObjectId,
    segmentName: 'corp-core',
    windowStart: new Date(now.getTime() - 20 * 1000),
    windowEnd: now,
    probability: win.probability,
    stage: win.stage,
    confidence: win.confidence,
    series: win.series,
    featureContributions: win.featureContributions,
    summary: win.summary,
    modelVersion: 'wm-v4.2.1-cicids2018',
  };

  // 1. Prediction: persist on manual actions, otherwise keep in memory only
  let prediction: any;
  if (persist) {
    prediction = await Prediction.create(predictionFields);
    orgLiveSnapshot.delete(orgId); // persisted doc is now the freshest
  } else {
    const snapshot: ILivePredictionSnapshot = {
      _id: `live-${orgId}-${win.windowIndex}`,
      ...predictionFields,
      createdAt: now,
      isLiveSnapshot: true,
    };
    orgLiveSnapshot.set(orgId, snapshot);
    prediction = snapshot;
  }

  const previousRisk = orgLastRiskState.get(orgId);
  orgLastRiskState.set(orgId, win.riskState);
  const riskChanged = previousRisk !== win.riskState;

  // 2. Generate Alert if in watch or critical phase.
  // Automatic ticks only touch MongoDB when the risk state transitions.
  if ((win.riskState === 'critical' || win.riskState === 'watch') && (persist || riskChanged)) {
    // Append the last 6 chars of the orgId to the alertId to ensure global uniqueness 
    // across multiple orgs, since alertId has a unique index in the schema.
    const alertId = `AV-EP0001-${orgId.slice(-6)}`; 
    
    // Check if it already exists to avoid duplicate emails on replay
    const existingAlert = await Alert.findOne({ alertId, orgId: orgObjectId });
    
    const isNewAlert = !existingAlert;
    const isEscalation = existingAlert && existingAlert.state === 'watch' && win.riskState === 'critical';
    
    const updatePayload: any = {
      alertId,
      host: '172.31.69.28',
      ip: '172.31.69.28',
      stage: win.stage,
      probability: win.probability,
      state: win.riskState,
      reason: win.reason,
      detectedAt: now,
      orgId: orgObjectId,
      notes: `Telemetry extracted from CIC-IDS-2018 (Window #${win.windowIndex}). Technique: ${win.techniqueId || 'T1046'}.`,
    };

    if (isNewAlert || isEscalation) {
      updatePayload.status = 'New';
    }

    const alertDoc = await Alert.findOneAndUpdate(
      { alertId, orgId: orgObjectId },
      { $set: updatePayload },
      { upsert: true, new: true },
    );

    if (isNewAlert || isEscalation) {
      if (win.riskState === 'critical') {
        notifyOrgUsersOfAlert(orgId, {
          alertId: alertDoc.alertId,
          host: alertDoc.host,
          ip: alertDoc.ip,
          stage: alertDoc.stage,
          probability: alertDoc.probability,
          state: alertDoc.state,
          reason: alertDoc.reason,
          detectedAt: alertDoc.detectedAt
        });
      }

      // Create persistent in-app notification
      import('../models/Notification.js').then(async ({ Notification }) => {
        const notif = await Notification.create({
          orgId: orgObjectId,
          type: isEscalation ? 'alert_escalated' : 'alert_created',
          title: isEscalation ? `Alert Escalated to Critical: ${alertDoc.alertId}` : `New Alert: ${alertDoc.alertId}`,
          message: `Detected ${alertDoc.stage} activity on ${alertDoc.host}.`,
          severity: win.riskState === 'critical' ? 'critical' : 'warning',
          alertId: alertDoc.alertId,
        });

        // Emit socket event for new alerts (watch or critical)
        import('../socket.js').then(({ emitToOrg }) => {
          if (isNewAlert) {
            emitToOrg(orgId, 'alert_created', alertDoc);
          } else {
            emitToOrg(orgId, 'alert_updated', alertDoc);
          }
          emitToOrg(orgId, 'notification_created', notif);
        });
      }).catch(err => console.error('Failed to create notification', err));
    } else {
      // If the alert already existed and didn't escalate, we just updated its probability/stage. 
      // Emit alert_updated so the Kanban board stays in sync!
      import('../socket.js').then(({ emitToOrg }) => {
        emitToOrg(orgId, 'alert_updated', alertDoc);
      }).catch(err => console.error('Failed to emit alert_updated', err));
    }
  }

  // 3. Insert real active flows for this window (manual actions only —
  // live flow views are served from the in-memory replay dataset)
  if (persist && win.flows && win.flows.length > 0) {
    const flowDocs = win.flows.map((f) => ({
      src: f.src,
      dst: f.dst,
      proto: f.proto,
      flags: f.proto === 'TCP' ? '0x018' : '—',
      bytes: f.bytes,
      packets: Math.max(10, Math.round(f.bytes / 120)),
      duration: 2.0,
      iatMean: 0.04,
      iatVar: 0.001,
      iatMax: 0.1,
      ttlVar: 1.2,
      window: 64240,
      retrans: win.riskState === 'critical' ? 14 : 0,
      score: f.score,
      orgId: orgObjectId,
      timestamp: now,
    }));
    await Flow.insertMany(flowDocs);
  }

  return {
    prediction,
    window: win,
    replayStatus: {
      dataset: dataset.dataset,
      targetEpisode: dataset.targetEpisode,
      currentWindow: win.windowIndex,
      phase: win.phase,
      stage: win.stage,
      probability: win.probability,
      confidence: win.confidence,
      riskState: win.riskState,
      isAttack: win.isAttack,
      leadTimeSeconds: win.riskState === 'critical' ? 20.0 : 0.0,
    },
  };
}

export async function stepReplay(orgId: string, delta = 1) {
  const dataset = getReplayDataset();
  const current = getCurrentWindowIndex(orgId);
  let next = current + delta;
  if (next > dataset.endIndex) {
    next = dataset.startIndex;
  }
  return applyWindowToDatabase(orgId, next);
}

export async function resetReplay(orgId: string) {
  const dataset = getReplayDataset();
  return applyWindowToDatabase(orgId, dataset.startIndex);
}

export async function jumpToAttack(orgId: string) {
  const dataset = getReplayDataset();
  return applyWindowToDatabase(orgId, dataset.attackOnsetInterval);
}

export function getReplayStatus(orgId: string) {
  const dataset = getReplayDataset();
  const currentIdx = getCurrentWindowIndex(orgId);
  const win = dataset.windows.find((w) => w.windowIndex === currentIdx) || dataset.windows[0];

  return {
    dataset: dataset.dataset,
    targetEpisode: dataset.targetEpisode,
    sourceFile: dataset.sourceFile,
    currentWindow: win.windowIndex,
    startIndex: dataset.startIndex,
    attackOnsetInterval: dataset.attackOnsetInterval,
    endIndex: dataset.endIndex,
    phase: win.phase,
    stage: win.stage,
    probability: win.probability,
    confidence: win.confidence,
    riskState: win.riskState,
    isAttack: win.isAttack,
    leadTimeSeconds: win.riskState === 'critical' ? 20.0 : 0.0,
    flowCount: win.flowCount,
    timestampStart: win.timestampStart,
    timestampEnd: win.timestampEnd,
  };
}
