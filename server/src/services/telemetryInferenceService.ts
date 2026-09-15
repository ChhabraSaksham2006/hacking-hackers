/**
 * telemetryInferenceService.ts
 * =============================
 * Real-time Cyber World Model Telemetry Ingestion & Inference Provider.
 *
 * Designed for continuous streaming ingestion where incoming telemetry frames
 * populate a sliding temporal buffer of recent history (K windows x 54 dimensions).
 *
 * Current Provider: CSE-CIC-IDS2018 Thursday-01-03-2018 Infiltration episode.
 * Future Provider: Direct Kafka / Zeek / Suricata / eBPF socket streaming.
 */

import { getReplayDataset, type IReplayWindow, type IReplayDataset } from './replayService.js';
import { EventEmitter } from 'events';

export interface ITelemetryFrame {
  windowIndex: number;
  timestampStart: string;
  timestampEnd: string;
  features: Record<string, number>;
  flows: Array<{
    src: string;
    dst: string;
    proto: string;
    bytes: number;
    score: number;
  }>;
}

export interface ITelemetryInferenceOutput {
  windowIndex: number;
  timestamp: string;
  probability: number;
  stage: string;
  confidence: number;
  leadTimeSeconds: number;
  riskState: 'normal' | 'watch' | 'critical';
  reason: string;
  summary: string;
  mitre: {
    techniqueId: string | null;
    techniqueName: string | null;
    tactic: string;
  };
  features: Record<string, number>;
  featureContributions: Array<{
    feature: string;
    value: string;
    weight: number;
  }>;
  isLive: boolean;
}

export interface ITelemetryDataSource {
  getCurrentWindowIndex(): number;
  getWindowData(index: number): IReplayWindow;
  getBounds(): { min: number; max: number; default: number; attackOnset: number };
  advanceStep(delta?: number): number;
  resetTo(targetIndex?: number): number;
  jumpToAttack(): number;
  ingestFrame?(frame: ITelemetryFrame): void;
}

/**
 * Benchmark implementation of ITelemetryDataSource backed by CSE-CIC-IDS2018 replay slice.
 * When real-time streaming is plugged in, a StreamingTelemetryDataSource implementing
 * ITelemetryDataSource can replace or augment this provider.
 */
export class BenchmarkTelemetryDataSource implements ITelemetryDataSource {
  private currentIndex: number = 1796;
  private dataset: IReplayDataset;

  constructor() {
    this.dataset = getReplayDataset();
    this.currentIndex = this.dataset.defaultIndex || 1796;
  }

  public getCurrentWindowIndex(): number {
    return this.currentIndex;
  }

  public getBounds() {
    return {
      min: this.dataset.startIndex,
      max: this.dataset.endIndex,
      default: this.dataset.defaultIndex,
      attackOnset: this.dataset.attackOnsetInterval,
    };
  }

  public getWindowData(index: number): IReplayWindow {
    const clamped = Math.max(this.dataset.startIndex, Math.min(this.dataset.endIndex, index));
    const win = this.dataset.windows.find((w) => w.windowIndex === clamped);
    return win || this.dataset.windows[0]!;
  }

  public advanceStep(delta: number = 1): number {
    let next = this.currentIndex + delta;
    if (next > this.dataset.endIndex) {
      next = this.dataset.startIndex;
    }
    this.currentIndex = next;
    return this.currentIndex;
  }

  public resetTo(targetIndex?: number): number {
    this.currentIndex = targetIndex !== undefined ? targetIndex : this.dataset.startIndex;
    return this.currentIndex;
  }

  public jumpToAttack(): number {
    this.currentIndex = this.dataset.attackOnsetInterval;
    return this.currentIndex;
  }

  public ingestFrame(frame: ITelemetryFrame): void {
    // In future streaming integration, incoming socket frames will be pushed here
    this.currentIndex = frame.windowIndex;
  }
}

/**
 * Unified Telemetry & Inference Manager
 * Emits 'telemetry:update' whenever the live system prediction advances.
 */
export class TelemetryInferenceService extends EventEmitter {
  private dataSource: ITelemetryDataSource;
  private isContinuousStreaming: boolean = false;

  constructor(dataSource?: ITelemetryDataSource) {
    super();
    this.dataSource = dataSource || new BenchmarkTelemetryDataSource();
  }

  public setDataSource(newSource: ITelemetryDataSource) {
    this.dataSource = newSource;
    this.emit('telemetry:update', this.getLiveState());
  }

  public getCurrentWindowIndex(): number {
    return this.dataSource.getCurrentWindowIndex();
  }

  public getBounds() {
    return this.dataSource.getBounds();
  }

  public getLiveState(): ITelemetryInferenceOutput {
    return this.getInferenceForWindow(this.dataSource.getCurrentWindowIndex(), true);
  }

  public getInferenceForWindow(windowIndex: number, isLive: boolean = false): ITelemetryInferenceOutput {
    const win = this.dataSource.getWindowData(windowIndex);
    return {
      windowIndex: win.windowIndex,
      timestamp: win.timestampStart,
      probability: win.probability,
      stage: win.stage,
      confidence: win.confidence,
      leadTimeSeconds: win.riskState === 'critical' ? 20.0 : win.riskState === 'watch' ? 14.0 : 0.0,
      riskState: win.riskState,
      reason: win.reason,
      summary: win.summary,
      mitre: {
        techniqueId: win.techniqueId,
        techniqueName: win.techniqueName,
        tactic: win.stage,
      },
      features: win.features,
      featureContributions: win.featureContributions,
      isLive,
    };
  }

  public stepForward(delta: number = 1): ITelemetryInferenceOutput {
    const newIndex = this.dataSource.advanceStep(delta);
    const output = this.getInferenceForWindow(newIndex, true);
    this.emit('telemetry:update', output);
    return output;
  }

  public resetBaseline(targetWindow?: number): ITelemetryInferenceOutput {
    const newIndex = this.dataSource.resetTo(targetWindow);
    const output = this.getInferenceForWindow(newIndex, true);
    this.emit('telemetry:update', output);
    return output;
  }

  public jumpToAttack(): ITelemetryInferenceOutput {
    const newIndex = this.dataSource.jumpToAttack();
    const output = this.getInferenceForWindow(newIndex, true);
    this.emit('telemetry:update', output);
    return output;
  }

  /**
   * Future Real-time Streaming Ingestion API
   * Call this function when live packet capture / Zeek / eBPF pipes send real-time frames.
   */
  public ingestStreamingTelemetry(frame: ITelemetryFrame): ITelemetryInferenceOutput {
    if (this.dataSource.ingestFrame) {
      this.dataSource.ingestFrame(frame);
    }
    const output = this.getInferenceForWindow(frame.windowIndex, true);
    this.emit('telemetry:update', output);
    return output;
  }
}

export const telemetryService = new TelemetryInferenceService();
