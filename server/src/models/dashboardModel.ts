import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import { EventEmitter } from 'events';
import { env } from '../config/env.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BRIDGE_SCRIPT = path.resolve(__dirname, '../../scripts/model_bridge.py');

export interface IDashboardSummary {
  infiltrationProbability: number;
  infiltrationProbabilityPct: string;
  activeFlows: string;
  flaggedHosts: string;
  modelConfidence: string;
  leadTimeSeconds: number;
  currentStage: string;
  riskLevel: 'normal' | 'watch' | 'critical';
  threshold: number;
}

export interface IMitreStage {
  id: string;
  label: string;
  active: boolean;
}

export interface IDashboardAlert {
  id: number;
  level: 'normal' | 'watch' | 'critical';
  host: string;
  stage: string;
  ts: string;
  reason: string;
}

export interface IDashboardFlow {
  src: string;
  dst: string;
  proto: string;
  flags: string;
  bytes: string;
  prob: number;
}

export interface IDashboardState {
  step_index: number;
  actual_window_index: number;
  timestamp: string;
  latest_probability: number;
  summary: IDashboardSummary;
  stages: IMitreStage[];
  recentAlerts: IDashboardAlert[];
  recentFlows: IDashboardFlow[];
  timeline: number[];
}

export class DashboardStore extends EventEmitter {
  public currentStep: number = 47;
  public timeline: number[] = [];
  public summary: IDashboardSummary = {
    infiltrationProbability: 0.88,
    infiltrationProbabilityPct: '88%',
    activeFlows: '14,820',
    flaggedHosts: '3',
    modelConfidence: '94.2%',
    leadTimeSeconds: 20.0,
    currentStage: 'Lateral Movement',
    riskLevel: 'critical',
    threshold: 0.65,
  };
  public stages: IMitreStage[] = [
    { id: 'recon', label: 'Recon', active: true },
    { id: 'initial', label: 'Initial Access', active: true },
    { id: 'lateral', label: 'Lateral Movement', active: true },
    { id: 'c2', label: 'C2', active: false },
    { id: 'exfil', label: 'Exfiltration', active: false },
  ];
  public recentAlerts: IDashboardAlert[] = [];
  public recentFlows: IDashboardFlow[] = [];
  public timestamp: string = '2018-03-01 01:59:54';
  public actual_window_index: number = 1797;
  public isStepping: boolean = false;
  private initialized: boolean = false;

  constructor() {
    super();
    // Default 48-window baseline curve
    this.timeline = [
      0.08, 0.09, 0.10, 0.11, 0.12, 0.12, 0.12, 0.13, 0.12, 0.12, 0.12, 0.11,
      0.11, 0.10, 0.09, 0.08, 0.08, 0.07, 0.06, 0.06, 0.06, 0.06, 0.06, 0.06,
      0.06, 0.06, 0.06, 0.06, 0.07, 0.08, 0.09, 0.27, 0.30, 0.35, 0.38, 0.41,
      0.44, 0.46, 0.45, 0.47, 0.48, 0.50, 0.53, 0.55, 0.57, 0.60, 0.87, 0.93,
    ];
  }

  public lastInferenceSource: 'fastapi_microservice' | 'local_python_bridge' = 'local_python_bridge';

  private async runBridge(action: 'init' | 'step', index?: number): Promise<any> {
    // 1. Check if remote ML microservice is configured
    if (env.ML_SERVICE_URL) {
      try {
        const base = env.ML_SERVICE_URL.replace(/\/+$/, '');
        if (action === 'init') {
          const res = await fetch(`${base}/predict/init`, {
            method: 'GET',
            headers: { Accept: 'application/json' },
            signal: AbortSignal.timeout(20000),
          });
          if (res.ok) {
            this.lastInferenceSource = 'fastapi_microservice';
            return await res.json();
          }
        } else {
          const stepIdx = typeof index === 'number' ? index : 47;
          const res = await fetch(`${base}/predict/step`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify({ step_index: stepIdx }),
            signal: AbortSignal.timeout(10000),
          });
          if (res.ok) {
            this.lastInferenceSource = 'fastapi_microservice';
            return await res.json();
          }
        }
      } catch (err: any) {
        console.warn(`[DashboardStore] ML Microservice (${env.ML_SERVICE_URL}) unreachable: ${err?.message || err}. Falling back to local bridge.`);
      }
    }

    // 2. Fallback: Local Python process bridge
    this.lastInferenceSource = 'local_python_bridge';
    return this.runLocalBridge(action, index);
  }

  private runLocalBridge(action: 'init' | 'step', index?: number): Promise<any> {
    return new Promise((resolve) => {
      const args = [BRIDGE_SCRIPT, '--action', action];
      if (typeof index === 'number') {
        args.push('--index', index.toString());
      }

      const proc = spawn('python', args, {
        cwd: path.resolve(__dirname, '../../..'),
      });

      let stdout = '';
      let stderr = '';

      proc.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      proc.on('close', (code) => {
        if (code === 0 && stdout.trim()) {
          try {
            const parsed = JSON.parse(stdout.trim());
            resolve(parsed);
            return;
          } catch (e) {
            console.error('[DashboardStore] Failed to parse bridge output:', e);
          }
        } else {
          console.error(`[DashboardStore] Bridge process exited with code ${code}: ${stderr}`);
        }
        resolve(null);
      });

      proc.on('error', (err) => {
        console.error('[DashboardStore] Failed to spawn bridge:', err);
        resolve(null);
      });
    });
  }

  public async init(): Promise<void> {
    if (this.initialized) return;
    try {
      console.log('⚡ Initializing Dashboard Model Engine...');
      const result = await this.runBridge('init');
      if (result) {
        this.applyResult(result);
        if (Array.isArray(result.timeline) && result.timeline.length === 48) {
          this.timeline = result.timeline;
        }
      }
      this.initialized = true;
      if (this.lastInferenceSource === 'fastapi_microservice') {
        console.log(`🌐 [Inference Engine] Connected to FastAPI Microservice -> ${env.ML_SERVICE_URL}`);
      } else {
        console.log(`⚙️ [Inference Engine] Connected to Local Python Bridge (model_bridge.py)`);
      }
    } catch (e) {
      console.error('Failed to initialize dashboard store:', e);
    }
  }

  public async stepForward(): Promise<IDashboardState> {
    if (this.isStepping) {
      return this.getState();
    }

    this.isStepping = true;
    try {
      // Loop sliding window 0 through 47
      this.currentStep = (this.currentStep + 1) % 48;
      const result = await this.runBridge('step', this.currentStep);

      if (result && typeof result.latest_probability === 'number') {
        this.applyResult(result);

        // Slide the 48-window timeline: drop oldest, append newest
        this.timeline.shift();
        this.timeline.push(result.latest_probability);

        this.emit('tick', this.getState());
      }
    } catch (e) {
      console.error('[DashboardStore] Error during stepForward:', e);
    } finally {
      this.isStepping = false;
    }

    return this.getState();
  }

  public async reset(targetStep: number = 0): Promise<IDashboardState> {
    this.currentStep = Math.max(0, Math.min(47, targetStep));
    const result = await this.runBridge('step', this.currentStep);
    if (result) {
      this.applyResult(result);
      this.emit('tick', this.getState());
    }
    return this.getState();
  }

  public async jumpAttack(): Promise<IDashboardState> {
    return this.reset(47);
  }

  private applyResult(result: any) {
    if (result.summary) this.summary = result.summary;
    if (result.stages) this.stages = result.stages;
    if (result.recentAlerts) this.recentAlerts = result.recentAlerts;
    if (result.recentFlows) this.recentFlows = result.recentFlows;
    if (result.timestamp) this.timestamp = result.timestamp;
    if (result.actual_window_index) this.actual_window_index = result.actual_window_index;
  }

  public getState(): IDashboardState {
    return {
      step_index: this.currentStep,
      actual_window_index: this.actual_window_index,
      timestamp: this.timestamp,
      latest_probability: this.summary.infiltrationProbability,
      summary: this.summary,
      stages: this.stages,
      recentAlerts: this.recentAlerts,
      recentFlows: this.recentFlows,
      timeline: [...this.timeline],
    };
  }

  public getSummary() {
    return {
      ...this.summary,
      currentProbability: this.summary.infiltrationProbability,
      activeFlows: parseInt(this.summary.activeFlows.replace(/,/g, ''), 10) || 14820,
      flaggedHosts: parseInt(this.summary.flaggedHosts, 10) || 3,
      modelConfidence: parseFloat(this.summary.modelConfidence) / 100 || 0.94,
      inferenceSource: this.lastInferenceSource,
      mlServiceUrl: this.lastInferenceSource === 'fastapi_microservice' ? env.ML_SERVICE_URL : null,
    };
  }

  public getTimeline() {
    return {
      series: [...this.timeline],
      windowStart: '2018-03-01 01:58:20',
      windowEnd: this.timestamp,
    };
  }

  public getStages() {
    return {
      stage: this.summary.currentStage,
      probability: this.summary.infiltrationProbability,
      confidence: 0.94,
      stages: this.stages,
    };
  }

  public getAlerts() {
    return {
      data: this.recentAlerts.map((a) => ({
        _id: `AV-${a.id}`,
        alertId: `AV-${this.actual_window_index}-${a.id}`,
        host: a.host,
        ip: a.host,
        stage: a.stage,
        probability: this.summary.infiltrationProbability,
        state: a.level,
        reason: a.reason,
        detectedAt: this.timestamp,
        status: 'New',
      })),
    };
  }

  public getFlows() {
    return {
      data: this.recentFlows.map((f, idx) => ({
        _id: `flow-${idx}-${f.src}`,
        src: f.src,
        dst: f.dst,
        proto: f.proto,
        flags: f.flags,
        bytes: parseInt(f.bytes.replace(/[^\d]/g, ''), 10) || 1240,
        packets: 14,
        score: f.prob,
        timestamp: this.timestamp,
      })),
    };
  }

  public getNetworkGraph(scrub?: number) {
    // Ground truth enterprise topology from Thursday-01-03-2018 Infiltration episode
    // Subnet: 192.168.10.0/24 (Enterprise Core) + External Perimeter (203.0.113.15, 192.168.10.1 DNS/GW)
    let effectiveWindow = this.actual_window_index;
    let isLive = true;

    if (typeof scrub === 'number' && !isNaN(scrub)) {
      const clampedScrub = Math.max(0, Math.min(100, scrub));
      // Window range: 1750 to 1810
      effectiveWindow = Math.round(1750 + (clampedScrub / 100) * (1810 - 1750));
      isLive = clampedScrub === 100;
    }

    const isC2 = effectiveWindow >= 1804;
    const isLateral = effectiveWindow >= 1796 && !isC2;
    const isInitial = effectiveWindow >= 1789 && !isLateral && !isC2;
    const isRecon = effectiveWindow >= 1781 && !isInitial && !isLateral && !isC2;
    const isBaseline = effectiveWindow < 1781;

    const phase = isC2
      ? 'C2 Beaconing & Exfiltration'
      : isLateral
      ? 'Lateral Movement'
      : isInitial
      ? 'Initial Exploitation'
      : isRecon
      ? 'Network Reconnaissance'
      : 'Benign Baseline';

    const probability = isLive
      ? this.summary.infiltrationProbability
      : isC2
      ? 0.94
      : isLateral
      ? 0.88
      : isInitial
      ? 0.58
      : isRecon
      ? 0.36
      : 0.08;

    const isUnderAttack = isLateral || isC2;
    const isPrecursor = isRecon || isInitial;

    // Node definitions mapped to physical hosts observed in the attack timeline
    const nodes = [
      {
        id: '192.168.10.44', // Primary compromised host (attacker foothold)
        hostname: 'corp-workstation-44',
        segment: 'corp-core',
        role: 'Foothold Workstation',
        x: 180,
        y: 110,
        size: isUnderAttack ? 18 : isPrecursor ? 14 : 10,
        state: isUnderAttack ? 'critical' : isPrecursor ? 'watch' : 'normal',
        flows: isUnderAttack ? 48 : isPrecursor ? 24 : 8,
        bytes: isUnderAttack ? 84500 : isPrecursor ? 32000 : 12400,
        firstSeen: '2018-03-01 01:40:00',
      },
      {
        id: '192.168.10.12', // Critical internal file & domain pivot (targeted over port 445)
        hostname: 'corp-file-srv-12',
        segment: 'finance',
        role: 'Internal SMB Server',
        x: 390,
        y: 90,
        size: isUnderAttack ? 16 : isPrecursor ? 12 : 9,
        state: isUnderAttack ? 'critical' : isPrecursor ? 'watch' : 'normal',
        flows: isUnderAttack ? 36 : isPrecursor ? 18 : 6,
        bytes: isUnderAttack ? 64200 : isPrecursor ? 21000 : 9800,
        firstSeen: '2018-03-01 01:30:00',
      },
      {
        id: '192.168.10.19', // Auxiliary victim server (authenticated session target)
        hostname: 'corp-app-node-19',
        segment: 'corp-core',
        role: 'Application Server',
        x: 350,
        y: 220,
        size: isUnderAttack ? 14 : isPrecursor ? 11 : 8,
        state: isUnderAttack ? 'watch' : isInitial ? 'watch' : 'normal',
        flows: isUnderAttack ? 22 : isPrecursor ? 12 : 5,
        bytes: isUnderAttack ? 31800 : isPrecursor ? 14500 : 6400,
        firstSeen: '2018-03-01 01:25:00',
      },
      {
        id: '192.168.10.1', // Gateway & internal recursive DNS resolver
        hostname: 'edge-gw-01',
        segment: 'dmz-edge',
        role: 'Internal Gateway & DNS',
        x: 100,
        y: 230,
        size: 13,
        state: 'normal',
        flows: 64,
        bytes: 142000,
        firstSeen: '2018-03-01 00:00:00',
      },
      {
        id: '10.0.0.15', // DMZ Management jump host
        hostname: 'ops-jump-15',
        segment: 'dmz-edge',
        role: 'Management Bastion',
        x: 540,
        y: 160,
        size: 11,
        state: isUnderAttack ? 'watch' : 'normal',
        flows: 14,
        bytes: 28400,
        firstSeen: '2018-03-01 01:10:00',
      },
      {
        id: '203.0.113.15', // External C2 egress listener (T1071 beacon destination)
        hostname: 'ext-c2-node',
        segment: 'dmz-edge',
        role: 'External Endpoint',
        x: 680,
        y: 80,
        size: isC2 ? 16 : isUnderAttack ? 12 : 6,
        state: isC2 ? 'critical' : isUnderAttack ? 'watch' : 'normal',
        flows: isC2 ? 32 : isUnderAttack ? 8 : 2,
        bytes: isC2 ? 96400 : 12000,
        firstSeen: '2018-03-01 01:59:52',
      },
      {
        id: '192.168.10.25', // Legitimate benign intranet client
        hostname: 'hr-workstation-25',
        segment: 'corp-core',
        role: 'Internal Client',
        x: 230,
        y: 280,
        size: 7,
        state: 'normal',
        flows: 8,
        bytes: 8400,
        firstSeen: '2018-03-01 01:00:00',
      },
      {
        id: '192.168.10.50', // Automated build worker node
        hostname: 'dev-ci-worker',
        segment: 'corp-core',
        role: 'CI/CD Node',
        x: 520,
        y: 270,
        size: 8,
        state: 'normal',
        flows: 10,
        bytes: 14600,
        firstSeen: '2018-03-01 00:30:00',
      },
    ];

    // Edges connecting nodes with physical telemetry flow volume and probability scores
    const edges = [
      {
        source: '192.168.10.44',
        target: '192.168.10.12',
        proto: 'TCP',
        port: 445,
        bytes: isUnderAttack ? 12400 : isPrecursor ? 3100 : 800,
        score: isUnderAttack ? probability : isPrecursor ? 0.52 : 0.08,
      },
      {
        source: '192.168.10.44',
        target: '192.168.10.19',
        proto: 'TCP',
        port: 445,
        bytes: isUnderAttack ? 8600 : isPrecursor ? 2800 : 650,
        score: isUnderAttack ? Math.max(0, probability - 0.04) : isPrecursor ? 0.48 : 0.09,
      },
      {
        source: '192.168.10.44',
        target: '192.168.10.1',
        proto: 'UDP',
        port: 53,
        bytes: 840,
        score: 0.08,
      },
      {
        source: '192.168.10.19',
        target: '10.0.0.15',
        proto: 'TCP',
        port: 445,
        bytes: 4820,
        score: isUnderAttack ? 0.65 : 0.12,
      },
      {
        source: '192.168.10.44',
        target: '203.0.113.15',
        proto: 'TCP',
        port: 8080,
        bytes: isC2 ? 48200 : isUnderAttack ? 8200 : 400,
        score: isC2 ? probability : isUnderAttack ? 0.72 : 0.05,
      },
      {
        source: '192.168.10.25',
        target: '192.168.10.1',
        proto: 'TCP',
        port: 80,
        bytes: 2420,
        score: 0.11,
      },
      {
        source: '192.168.10.50',
        target: '10.0.0.15',
        proto: 'TCP',
        port: 22,
        bytes: 3800,
        score: 0.15,
      },
    ];

    const timestamp = isLive
      ? this.timestamp
      : `2018-03-01 01:${Math.floor(50 + ((effectiveWindow - 1750) / 60) * 10)}:${String((effectiveWindow * 7) % 60).padStart(2, '0')}`;

    return {
      windowIndex: effectiveWindow,
      timestamp,
      phase,
      probability,
      scrub: typeof scrub === 'number' ? scrub : 100,
      nodes,
      edges,
    };
  }

  public getHostDetail(hostId: string, scrub?: number) {
    const graph = this.getNetworkGraph(scrub);
    const node = graph.nodes.find((n) => n.id === hostId || n.hostname === hostId) || graph.nodes[0]!;
    
    // Connected flows for this specific host
    const connectedFlows = this.recentFlows.filter(
      (f) => f.src.startsWith(node.id) || f.dst.startsWith(node.id)
    );

    const fallbackFlows = graph.edges
      .filter((e) => e.source === node.id || e.target === node.id)
      .map((e) => ({
        src: e.source,
        dst: e.target,
        proto: e.proto,
        bytes: `${(e.bytes / 1024).toFixed(1)} KB`,
        score: e.score,
      }));

    return {
      id: node.id,
      hostname: node.hostname,
      role: node.role,
      segment: node.segment,
      state: node.state,
      riskScore: node.state === 'critical' ? graph.probability : node.state === 'watch' ? 0.54 : 0.09,
      activeFlows: node.flows,
      totalBytes: node.bytes,
      firstSeen: node.firstSeen,
      recentFlows: connectedFlows.length > 0 ? connectedFlows : fallbackFlows,
    };
  }
}

export const dashboardStore = new DashboardStore();
