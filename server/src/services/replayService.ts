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

export async function applyWindowToDatabase(orgId: string, windowIndex?: number) {
  const dataset = getReplayDataset();
  const idx = windowIndex !== undefined ? windowIndex : getCurrentWindowIndex(orgId);
  const clampedIdx = Math.max(dataset.startIndex, Math.min(dataset.endIndex, idx));
  orgCurrentWindow.set(orgId, clampedIdx);

  const win = dataset.windows.find((w) => w.windowIndex === clampedIdx) || dataset.windows[0];
  const orgObjectId = new mongoose.Types.ObjectId(orgId);
  const now = new Date();

  // 1. Create or update Prediction document
  const prediction = await Prediction.create({
    orgId: orgObjectId,
    segmentName: 'corp-core',
    windowStart: new Date(Date.now() - 20 * 1000),
    windowEnd: now,
    probability: win.probability,
    stage: win.stage,
    confidence: win.confidence,
    series: win.series,
    featureContributions: win.featureContributions,
    summary: win.summary,
    modelVersion: 'wm-v4.2.1-cicids2018',
  });

  // 2. Generate Alert if in watch or critical phase
  if (win.riskState === 'critical' || win.riskState === 'watch') {
    const alertId = `AV-${clampedIdx}`;
    
    // Check if it already exists to avoid duplicate emails on replay
    const existingAlert = await Alert.findOne({ alertId, orgId: orgObjectId });
    
    const alertDoc = await Alert.findOneAndUpdate(
      { alertId, orgId: orgObjectId },
      {
        alertId,
        host: '172.31.69.28',
        ip: '172.31.69.28',
        stage: win.stage,
        probability: win.probability,
        state: win.riskState,
        reason: win.reason,
        detectedAt: now,
        status: 'New',
        orgId: orgObjectId,
        notes: `Telemetry extracted from CIC-IDS-2018 (Window #${win.windowIndex}). Technique: ${win.techniqueId || 'T1046'}.`,
      },
      { upsert: true, new: true },
    );

    if (!existingAlert && win.riskState === 'critical') {
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
  }

  // 3. Insert real active flows for this window
  if (win.flows && win.flows.length > 0) {
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
