/**
 * ragService.ts
 * =============
 * Retrieval-Augmented Generation (RAG) Service for Aegis Vantage Telemetry Copilot.
 *
 * Priority Chain:
 * 1. Groq API (openai/gpt-oss-20b primary @ ~1000 tok/s, openai/gpt-oss-120b secondary)
 * 2. OpenRouter API (nvidia/nemotron-3.5-lightning:free)
 * 3. Built-in Cyber Causality Engine (Deterministic zero-key offline fallback)
 *
 * Design constraints:
 * - Compact prompt (~400-900 tokens) to strictly adhere to free-tier 8K TPM limits.
 * - Deep grounding in temporal DL world model state, MITRE ATT&CK KB, and SHAP explainability.
 */

import { env } from '../config/env.js';
import { dashboardStore } from '../models/dashboardModel.js';
import { getReplayDataset } from './replayService.js';

// ── 1. Domain MITRE ATT&CK Knowledge Base ──────────────────────

export interface IMitreTechniqueKB {
  id: string;
  name: string;
  tactic: string;
  description: string;
  indicators: string[];
  mitigations: Array<{ id: string; name: string; action: string }>;
  detectionRules: string;
}

export const MITRE_KNOWLEDGE_BASE: Record<string, IMitreTechniqueKB> = {
  'T1021.002': {
    id: 'T1021.002',
    name: 'SMB/Windows Admin Shares',
    tactic: 'Lateral Movement',
    description:
      'Adversaries use valid accounts to interact with remote network shares over Server Message Block (SMB, TCP port 445). After compromising an initial foothold, the adversary pivots across internal corporate workstations and file servers to stage tools and execute remote service commands.',
    indicators: [
      'Rapid burst of SMB session setups across distinct internal IP addresses',
      'Port 445 traffic spike with high forward-to-backward packet asymmetry',
      'Elevated auth_port_ratio (> 25%) and increased destination port concentration',
      'Anomalous IPC$ or C$ access requests from non-admin workstations',
    ],
    mitigations: [
      { id: 'M1037', name: 'Filter Network Traffic', action: 'Block ingress and transit TCP port 445 between disparate user workstation subnets and isolate the compromised host via microsegmentation.' },
      { id: 'M1035', name: 'Limit Access to Resource Over Network', action: 'Enable Microsoft LAPS to eliminate shared local administrator passwords across workstation fleets.' },
      { id: 'M1042', name: 'Disable or Remove Feature or Program', action: 'Disable SMBv1 globally, enforce SMB Signing, and restrict anonymous access to named pipes.' },
    ],
    detectionRules:
      'World Model SparseRSSM delta: delta_total_ip_bytes > 40KB/window with auth_port_ratio > 0.20 and distinct SMB target count >= 2 within 60s.',
  },
  'T1046': {
    id: 'T1046',
    name: 'Network Service Discovery',
    tactic: 'Discovery / Reconnaissance',
    description:
      'Adversaries attempt to get a listing of services running on hosts throughout the target enterprise network using active port sweeps, SYN probes, or banner grabbing.',
    indicators: [
      'Rapid rise in unique_dst_ports and destination port Shannon entropy (> 3.5 bits)',
      'High SYN/ACK ratio disparity with abnormal RST teardown frequency',
      'Short-lived connections (< 0.2s lifetime) across consecutive IP addresses',
    ],
    mitigations: [
      { id: 'M1030', name: 'Network Segmentation', action: 'Segment sensitive hosts into isolated VLANs with strict ingress firewall ACLs.' },
      { id: 'M1031', name: 'Network Intrusion Prevention', action: 'Deploy inline IDS/IPS rate-limiting rules to detect and drop progressive TCP SYN sweeps.' },
    ],
    detectionRules:
      'Entropy anomaly: dst_port_entropy divergence > 2.0 std above 48-window rolling baseline alongside syn_ratio > 0.35.',
  },
  'T1071.001': {
    id: 'T1071.001',
    name: 'Web Protocols (Command & Control)',
    tactic: 'Command and Control',
    description:
      'Adversaries communicate with external infrastructure using application layer protocols (HTTP/HTTPS/custom TCP over port 8080 or 443) to blend in with benign traffic.',
    indicators: [
      'Low inter-arrival jitter (flow_iat_std < 0.05s) indicating automated beacon timing',
      'Sustained active_connection_lifetime_mean (> 5.0s) with periodic small payload exchanges',
      'Egress traffic to non-reputable external IP (e.g. 203.0.113.15)',
    ],
    mitigations: [
      { id: 'M1031', name: 'Network Intrusion Prevention', action: 'Terminate suspicious external TCP sessions and sinkhole destination IP 203.0.113.15 at the border firewall.' },
      { id: 'M1020', name: 'SSL/TLS Inspection', action: 'Inspect TLS certificate validity and block unapproved dynamic DNS or high-entropy hostnames.' },
    ],
    detectionRules:
      'C2 Beaconing Detector: Outbound TCP session lifetime > 3.0s with periodic pulse rhythm and byte rate > 50KB/s.',
  },
  'T1190': {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    description:
      'Adversaries exploit vulnerabilities in an Internet-facing computer or program using software flaws, buffer overflows, or authentication bypass to gain initial remote execution.',
    indicators: [
      'Inbound payload size anomalies with unexpected HTTP method verb combinations',
      'Child process spawn events originating from web server listener binaries',
      'Immediate subsequent internal socket connection attempts originating from the DMZ host',
    ],
    mitigations: [
      { id: 'M1051', name: 'Update Software', action: 'Apply emergency security patches to web application daemons and public edge appliances.' },
      { id: 'M1050', name: 'Exploit Protection', action: 'Deploy Web Application Firewall (WAF) virtual patching rules for targeted exploit signatures.' },
    ],
    detectionRules:
      'Infiltration onset detector: sudden spike in inbound payload bytes followed by outbound peer socket initialization from corp-workstation-44.',
  },
  'T1110': {
    id: 'T1110',
    name: 'Brute Force / Password Spraying',
    tactic: 'Credential Access',
    description:
      'Adversaries use password spraying or brute force authentication to gain access to accounts by systematically attempting passwords against domain services.',
    indicators: [
      'Repeated Kerberos pre-authentication failures (Event ID 4771) or SMB auth errors (Status 0xC000006D)',
      'High ratio of reset/teardown connections on authentication ports 88/445/389',
    ],
    mitigations: [
      { id: 'M1036', name: 'Account Use Policies', action: 'Enforce account lockout thresholds and mandatory multi-factor authentication (MFA).' },
    ],
    detectionRules:
      'Authentication failure burst >= 10 attempts/min from a single internal source IP.',
  },
  'T1041': {
    id: 'T1041',
    name: 'Exfiltration Over C2 Channel',
    tactic: 'Exfiltration',
    description:
      'Adversaries steal data by transferring it over an existing command and control channel to an external endpoint.',
    indicators: [
      'Pronounced upward inflection in fwd_byte_ratio and delta_total_ip_bytes',
      'High outbound bandwidth transfer to untrusted external IP during non-business hours',
    ],
    mitigations: [
      { id: 'M1057', name: 'Data Loss Prevention', action: 'Inspect outbound traffic for enterprise data markers and enforce volume throttling on DMZ egress gateways.' },
    ],
    detectionRules:
      'Cumulative egress byte volume to 203.0.113.15 exceeding 80KB in single sliding window.',
  },
};

// ── 2. Retrieval Context Interfaces ─────────────────────────────

export interface IRetrievedContext {
  windowIndex: number;
  timestamp: string;
  probability: number;
  stage: string;
  riskLevel: 'normal' | 'watch' | 'critical';
  confidence: number;
  leadTimeSeconds: number;
  activeFlowCount: number;
  flaggedHostsCount: number;
  topFeatures: Array<{ feature: string; value: string; weight: number }>;
  flaggedHosts: Array<{
    id: string;
    hostname: string;
    role: string;
    segment: string;
    state: string;
    activeFlows: number;
    bytes: number;
  }>;
  suspiciousFlows: Array<{
    src: string;
    dst: string;
    proto: string;
    bytes: number;
    score: number;
  }>;
  recentAlerts: Array<{
    alertId: string;
    host: string;
    stage: string;
    state: string;
    reason: string;
  }>;
  relevantMitre: IMitreTechniqueKB[];
  summary: string;
}

// ── 3. Multi-source Retrieval Function ──────────────────────────

export function retrieveContext(query: string, windowIndex?: number): IRetrievedContext {
  const dataset = getReplayDataset();
  const liveState = dashboardStore.getState();

  let targetIndex: number;
  if (typeof windowIndex === 'number' && !isNaN(windowIndex)) {
    targetIndex = Math.max(dataset.startIndex, Math.min(dataset.endIndex, windowIndex));
  } else {
    targetIndex = liveState.actual_window_index;
  }

  const win = dataset.windows.find((w) => w.windowIndex === targetIndex) || dataset.windows[0]!;
  const isCurrentLive = targetIndex === liveState.actual_window_index;

  const currentProb = isCurrentLive ? liveState.summary.infiltrationProbability : win.probability;
  const currentStage = isCurrentLive ? liveState.summary.currentStage : win.stage;
  const currentRisk = isCurrentLive ? liveState.summary.riskLevel : win.riskState;
  const currentLeadTime = currentRisk === 'critical' ? 20.0 : currentRisk === 'watch' ? 14.0 : 0.0;

  // Retrieve Graph Nodes / Flagged Hosts
  const graph = dashboardStore.getNetworkGraph(undefined, isCurrentLive);
  const flaggedHosts = graph.nodes
    .filter((n) => n.state === 'critical' || n.state === 'watch')
    .map((n) => ({
      id: n.id,
      hostname: n.hostname,
      role: n.role,
      segment: n.segment,
      state: n.state,
      activeFlows: n.flows,
      bytes: n.bytes,
    }));

  // Suspicious Flows
  const flows = (win.flows || []).filter((f) => f.score >= 0.5 || f.dst.includes('445') || f.src === '192.168.10.44');
  const topFlows = (flows.length > 0 ? flows : win.flows || []).slice(0, 5);

  // Top Feature Contributions
  const topFeatures = (win.featureContributions || []).slice(0, 5).map((fc) => ({
    feature: fc.feature,
    value: fc.value,
    weight: fc.weight,
  }));

  // Alerts
  const recentAlerts = liveState.recentAlerts.map((a) => ({
    alertId: `AV-${targetIndex}-${a.id}`,
    host: a.host,
    stage: a.stage,
    state: a.level,
    reason: a.reason,
  }));

  // Match MITRE ATT&CK techniques
  const lowerQuery = query.toLowerCase();
  const relevantMitre: IMitreTechniqueKB[] = [];

  // Match active window's technique first
  if (win.techniqueId && MITRE_KNOWLEDGE_BASE[win.techniqueId]) {
    relevantMitre.push(MITRE_KNOWLEDGE_BASE[win.techniqueId]!);
  }

  // Match any mentioned techniques or keywords
  for (const [techId, tech] of Object.entries(MITRE_KNOWLEDGE_BASE)) {
    if (relevantMitre.some((m) => m.id === techId)) continue;

    const matchesId = lowerQuery.includes(techId.toLowerCase());
    const matchesName = lowerQuery.includes(tech.name.toLowerCase());
    const matchesTactic = lowerQuery.includes(tech.tactic.toLowerCase());
    const matchesStage = currentStage.toLowerCase().includes(tech.tactic.toLowerCase());

    if (matchesId || matchesName || matchesTactic || (matchesStage && relevantMitre.length < 2)) {
      relevantMitre.push(tech);
    }
  }

  if (relevantMitre.length === 0) {
    relevantMitre.push(MITRE_KNOWLEDGE_BASE['T1021.002']!);
  }

  return {
    windowIndex: targetIndex,
    timestamp: isCurrentLive ? liveState.timestamp : win.timestampStart,
    probability: currentProb,
    stage: currentStage,
    riskLevel: currentRisk,
    confidence: isCurrentLive ? parseFloat(liveState.summary.modelConfidence) / 100 : win.confidence,
    leadTimeSeconds: currentLeadTime,
    activeFlowCount: win.flowCount,
    flaggedHostsCount: flaggedHosts.length,
    topFeatures,
    flaggedHosts,
    suspiciousFlows: topFlows,
    recentAlerts,
    relevantMitre,
    summary: win.summary || liveState.summary.currentStage,
  };
}

// ── 4. Compact Prompt Formatter (~400-800 tokens for 8K TPM) ────

function buildCompactSystemPrompt(ctx: IRetrievedContext): string {
  const hostSummary = ctx.flaggedHosts
    .map((h) => `${h.id}(${h.hostname}, ${h.state})`)
    .join(', ') || '192.168.10.44';

  const featSummary = ctx.topFeatures
    .slice(0, 3)
    .map((f) => `${f.feature}=${f.value}(+${f.weight.toFixed(2)})`)
    .join(', ');

  const flowSummary = ctx.suspiciousFlows
    .slice(0, 3)
    .map((f) => `${f.src}->${f.dst} [${f.proto}, score=${f.score}]`)
    .join('; ');

  const mitre = ctx.relevantMitre[0] || MITRE_KNOWLEDGE_BASE['T1021.002']!;
  const mitigations = mitre.mitigations.map((m) => `${m.id}: ${m.name}`).join(', ');

  return `You are Aegis Vantage AI Copilot, an expert cyber telemetry analyst.
Ground-truth DL state:
- Monitored Window: #${ctx.windowIndex} (${ctx.timestamp})
- Infiltration Prob: ${(ctx.probability * 100).toFixed(1)}% | Stage: ${ctx.stage} | Risk: ${ctx.riskLevel.toUpperCase()}
- Model Confidence: ${(ctx.confidence * 100).toFixed(1)}% | Lead Time: ${ctx.leadTimeSeconds.toFixed(1)}s
- Flagged Hosts: ${hostSummary}
- Top SHAP Drivers: ${featSummary}
- Active Suspicious Flows: ${flowSummary}
- MITRE Technique: ${mitre.id} (${mitre.name}, ${mitre.tactic}) | Mitigations: ${mitigations}

Instructions:
1. Provide a sharp, concise forensic answer in clean Markdown.
2. Directly answer the user's specific query using only the telemetry facts above.
3. Keep the response under 350 words.
4. Conclude with a single JSON block strictly on a new line:
\`\`\`json
{"references": ["ref1", "ref2", "ref3"]}
\`\`\`
where references are 2 to 4 key entities (e.g. IP addresses, MITRE technique ID, alert ID).`;
}

// ── 5. Provider 1: Groq API (openai/gpt-oss-20b & 120b) ─────────

async function generateWithGroq(
  query: string,
  ctx: IRetrievedContext,
  apiKey: string
): Promise<{ answer: string; references: string[]; provider: string } | null> {
  const models = ['openai/gpt-oss-20b', 'openai/gpt-oss-120b'];
  const systemPrompt = buildCompactSystemPrompt(ctx);

  for (const model of models) {
    try {
      const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model,
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: query },
          ],
          temperature: 0.2,
          max_tokens: 700,
        }),
        signal: AbortSignal.timeout(9000),
      });

      if (!res.ok) {
        const errorText = await res.text();
        console.warn(`[ragService] Groq model ${model} failed (${res.status}): ${errorText.slice(0, 200)}`);
        continue; // try next model
      }

      const data = (await res.json()) as any;
      const rawText = data?.choices?.[0]?.message?.content;
      if (!rawText) continue;

      const { answer, references } = extractReferences(rawText, ctx);
      return { answer, references, provider: `groq:${model}` };
    } catch (err) {
      console.warn(`[ragService] Groq request error on model ${model}:`, err);
    }
  }

  return null;
}

// ── 6. Provider 2: OpenRouter API (nvidia/nemotron-3.5-lightning:free) ──

async function generateWithOpenRouter(
  query: string,
  ctx: IRetrievedContext,
  apiKey: string
): Promise<{ answer: string; references: string[]; provider: string } | null> {
  const model = 'nvidia/nemotron-3.5-lightning:free';
  const systemPrompt = buildCompactSystemPrompt(ctx);

  try {
    const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
        'HTTP-Referer': 'https://aegisvantage.com',
        'X-Title': 'Aegis Vantage Telemetry Copilot',
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: query },
        ],
        temperature: 0.2,
        max_tokens: 700,
      }),
      signal: AbortSignal.timeout(16000),
    });

    if (!res.ok) {
      const errorText = await res.text();
      console.warn(`[ragService] OpenRouter ${model} failed (${res.status}): ${errorText.slice(0, 200)}`);
      return null;
    }

    const data = (await res.json()) as any;
    const rawText = data?.choices?.[0]?.message?.content;
    if (!rawText) return null;

    const { answer, references } = extractReferences(rawText, ctx);
    return { answer, references, provider: `openrouter:${model}` };
  } catch (err) {
    console.warn('[ragService] OpenRouter request error:', err);
    return null;
  }
}

// ── Helper: Extract JSON References ────────────────────────────

function extractReferences(
  rawText: string,
  ctx: IRetrievedContext
): { answer: string; references: string[] } {
  let answer = rawText;
  let references: string[] = [`Window #${ctx.windowIndex}`];

  const jsonMatch = rawText.match(/```json\s*(\{[\s\S]*?\})\s*```/);
  if (jsonMatch && jsonMatch[1]) {
    try {
      const parsed = JSON.parse(jsonMatch[1]);
      if (Array.isArray(parsed.references)) {
        references = parsed.references;
      }
      answer = rawText.replace(jsonMatch[0], '').trim();
    } catch {
      // Ignore parse error
    }
  }

  if (references.length === 0 || (references.length === 1 && references[0] === `Window #${ctx.windowIndex}`)) {
    const mitre = ctx.relevantMitre[0]?.id || 'T1021.002';
    const host = ctx.flaggedHosts[0]?.id || '192.168.10.44';
    references = [`Window #${ctx.windowIndex}`, host, mitre, 'Port 445'];
  }

  return { answer, references };
}

// ── 7. Provider 3: Built-in Cyber Causality Engine (Offline Fallback) ─

export function generateWithBuiltinCyberEngine(query: string, ctx: IRetrievedContext): {
  answer: string;
  references: string[];
} {
  const q = query.toLowerCase().trim();
  const refs: Set<string> = new Set();

  refs.add(`Window #${ctx.windowIndex}`);
  if (ctx.relevantMitre[0]) {
    refs.add(ctx.relevantMitre[0].id);
  }

  // Host-specific queries
  if (q.includes('44') || q.includes('foothold') || q.includes('workstation-44')) {
    refs.add('192.168.10.44');
    refs.add('corp-workstation-44');
    refs.add('T1021.002');
    refs.add('Port 445');

    return {
      answer: `### Host Diagnostic: \`192.168.10.44\` (corp-workstation-44)

**Status:** **CRITICAL FOOTHOLD** | **Segment:** \`corp-core\` | **Threat Attribution:** ${(ctx.probability * 100).toFixed(1)}% Infiltration Risk

#### Forensic Findings:
1. **Compromised Origin:** \`192.168.10.44\` serves as the primary pivot node established during the initial exploitation phase.
2. **Lateral SMB Propagation:** The host is actively issuing unauthenticated and privileged SMB session requests over **TCP Port 445** directed at internal resources:
   - **Target 1:** \`192.168.10.12\` (*corp-file-srv-12*, Finance SMB share)
   - **Target 2:** \`192.168.10.19\` (*corp-app-node-19*, Core App Server)
3. **C2 Beaconing Egress:** Telemetry records outbound TCP flows terminating at external infrastructure \`203.0.113.15:8080\` with periodic inter-arrival timing (${(ctx.topFeatures.find((f) => f.feature === 'flow_iat_mean')?.value || '0.04s')}).

#### Recommended Containment Playbook:
- [ ] **Network Isolation:** Apply firewall rule to drop all ingress/egress for \`192.168.10.44\` at switch port level.
- [ ] **Session Revocation:** Terminate all active Kerberos and SMB sessions originated from this host.
- [ ] **Memory Acquisition:** Capture RAM volatile artifacts before host reboot to preserve injected DLL modules.`,
      references: Array.from(refs),
    };
  }

  if (q.includes('12') || q.includes('file-srv') || q.includes('finance') || q.includes('smb')) {
    refs.add('192.168.10.12');
    refs.add('corp-file-srv-12');
    refs.add('T1021.002');
    refs.add('Port 445');

    return {
      answer: `### Host Diagnostic: \`192.168.10.12\` (corp-file-srv-12)

**Status:** **TARGETED ASSET (CRITICAL)** | **Segment:** \`finance\` | **Threat State:** Under Active Pivot

#### Forensic Findings:
1. **Targeted Service:** Inbound TCP port 445 (Microsoft SMB) is experiencing a session creation surge originating from compromised workstation \`192.168.10.44\`.
2. **Behavioral Indicators:**
   - Auth port affinity ratio is currently elevated at **${ctx.topFeatures.find((f) => f.feature === 'auth_port_ratio')?.value || '34.2%'}**.
   - Directional byte disparity indicates incoming tool staging and file enumeration commands.
3. **MITRE ATT&CK Mapping:** **T1021.002 (SMB/Windows Admin Shares)**.

#### Immediate Action Required:
- Disconnect \`192.168.10.12\` from the \`corp-core\` transit VLAN while maintaining domain controller access.
- Restrict SMB named pipes (\`IPC$\`, \`ADMIN$\`, \`C$\`) via Group Policy Object (GPO) to authorized administrative bastion IPs only.`,
      references: Array.from(refs),
    };
  }

  if (q.includes('203.0.113.15') || q.includes('c2') || q.includes('beacon') || q.includes('exfil')) {
    refs.add('203.0.113.15');
    refs.add('T1071.001');
    refs.add('T1041');
    refs.add('Port 8080');

    return {
      answer: `### Egress Analysis: External C2 Endpoint \`203.0.113.15\`

**Classification:** **COMMAND & CONTROL LISTENER / EXFILTRATION DESTINATION**
**Threat Protocol:** \`TCP/8080\` | **Technique:** **T1071.001 (Web Protocols)**

#### Traffic Telemetry:
- **Egress Source:** \`192.168.10.44\` (*corp-workstation-44*)
- **Flow Pattern:** High session lifetime persistence with periodic heartbeat transmissions every ~3.2s.
- **Risk Assessment:** Egress volume indicates command-and-control synchronization and staging of exfiltrated enterprise telemetry.

#### Remediation Protocol:
1. **Perimeter Sinkhole:** Push egress ACL block for CIDR \`203.0.113.0/24\` to border Palo Alto / Fortinet firewalls.
2. **DNS Cache Inspection:** Correlate external IP to historical DNS query logs to identify the adversary's dynamic domain names.`,
      references: Array.from(refs),
    };
  }

  // Explainability / SHAP / Feature queries
  if (q.includes('shap') || q.includes('feature') || q.includes('why flagged') || q.includes('reason') || q.includes('entropy') || q.includes('driver')) {
    const featRows = ctx.topFeatures
      .map((f) => `- **\`${f.feature}\`**: Value \`${f.value}\` | Attribution Weight: \`+${f.weight.toFixed(2)}\``)
      .join('\n');

    refs.add('SHAP Attributions');
    refs.add('SparseRSSM');
    if (ctx.topFeatures[0]) refs.add(ctx.topFeatures[0].feature);

    return {
      answer: `### Explainability Breakdown: Model Attribution Analysis

**Monitored Window:** \`#${ctx.windowIndex}\` | **Infiltration Probability:** \`${(ctx.probability * 100).toFixed(1)}%\` | **Confidence:** \`${(ctx.confidence * 100).toFixed(1)}%\`

The **SparseRSSM + TFCNet Ensemble** flagged this temporal slice based on acute divergence in multi-dimensional flow metrics:

${featRows}

#### Causal Threat Interpretation:
- **Destination Port Entropy:** Elevated port entropy accompanied by abnormal auth port affinity indicates rapid reconnaissance transitioning into targeted service exploitation.
- **Temporal Gradient Acceleration (\`delta_total_ip_bytes\`):** A high rate of byte volume expansion signals file transfer and payload staging across internal hosts.
- **TCP Handshake Dynamics:** High SYN-to-ACK ratios with non-zero RST teardowns reflect uncompleted probing against closed ports, characteristic of automated lateral spread.`,
      references: Array.from(refs),
    };
  }

  // Remediation / Containment / Playbook queries
  if (q.includes('remediat') || q.includes('mitigat') || q.includes('playbook') || q.includes('contain') || q.includes('isolate') || q.includes('how to')) {
    const mitre = ctx.relevantMitre[0] || MITRE_KNOWLEDGE_BASE['T1021.002']!;
    refs.add(mitre.id);
    refs.add('Mitigation Playbook');

    const mitList = mitre.mitigations
      .map((m) => `1. **${m.id} (${m.name}):**\n   ${m.action}`)
      .join('\n\n');

    return {
      answer: `### Incident Containment & Remediation Playbook

**Target Threat:** \`${mitre.id}: ${mitre.name}\` (\`${mitre.tactic}\`)
**Urgency:** **HIGH** | **Action Window:** Under ${ctx.leadTimeSeconds.toFixed(0)} seconds

#### Immediate Action Checklist:
${mitList}

#### Automated Orchestration Steps:
\`\`\`bash
# 1. Null-route attacker foothold host on core switch
switch(config)# ip route 192.168.10.44 255.255.255.255 Null0

# 2. Block outbound C2 beaconing
iptables -A FORWARD -d 203.0.113.15 -j DROP

# 3. Restrict SMB transit between workstation subnets
iptables -A FORWARD -p tcp --dport 445 -s 192.168.10.0/24 -d 192.168.10.0/24 -j DROP
\`\`\``,
      references: Array.from(refs),
    };
  }

  // Risk / Probability / Lead Time queries
  if (q.includes('risk') || q.includes('probability') || q.includes('lead time') || q.includes('breach') || q.includes('how bad')) {
    refs.add(`Risk: ${ctx.riskLevel.toUpperCase()}`);
    refs.add(`${ctx.leadTimeSeconds.toFixed(0)}s Lead Time`);

    return {
      answer: `### Real-Time Threat Posture & Early Warning

- **Current Stage:** \`${ctx.stage}\`
- **Infiltration Probability:** \`${(ctx.probability * 100).toFixed(1)}%\`
- **Threat Risk Level:** **${ctx.riskLevel.toUpperCase()}**
- **Forecasted Early Lead Time:** **${ctx.leadTimeSeconds.toFixed(1)} seconds** prior to catastrophic domain compromise
- **Model Confidence:** \`${(ctx.confidence * 100).toFixed(1)}%\`

#### Operational Assessment:
The world model forecasts that adversary activity has breached perimeter boundary defenses and is executing **${ctx.stage}** actions. Without immediate containment, credential harvesting and exfiltration over \`203.0.113.15\` will finalize within the next observation intervals.`,
      references: Array.from(refs),
    };
  }

  // Default General Overview
  const topHostNames = ctx.flaggedHosts.map((h) => `\`${h.id}\` (${h.hostname})`).join(', ') || '`192.168.10.44`';
  refs.add(ctx.stage);
  if (ctx.flaggedHosts[0]) refs.add(ctx.flaggedHosts[0].id);

  return {
    answer: `### Aegis Vantage Telemetry Summary (Window #${ctx.windowIndex})

**Active State:** \`${ctx.stage}\` | **Probability:** \`${(ctx.probability * 100).toFixed(1)}%\` | **Status:** **${ctx.riskLevel.toUpperCase()}**

#### Current Situation:
- **Monitored Episode:** CSE-CIC-IDS2018 Infiltration Replay (Thursday series)
- **Flagged Assets:** ${topHostNames}
- **Primary Attack Vector:** Lateral movement over SMB (TCP 445) and external C2 egress to \`203.0.113.15\`.
- **Top Metric Anomalies:**
${ctx.topFeatures.slice(0, 3).map((f) => `  - \`${f.feature}\`: ${f.value} (+${f.weight.toFixed(2)})`).join('\n')}

*Ask me about any specific host (\`192.168.10.44\`, \`192.168.10.12\`), explainability features (SHAP), MITRE mitigations, or containment commands.*`,
    references: Array.from(refs),
  };
}

// ── 8. Dynamic Suggested Queries Generator ─────────────────────

export function getSuggestedQueries(windowIndex?: number): string[] {
  const ctx = retrieveContext('', windowIndex);

  if (ctx.riskLevel === 'critical') {
    return [
      `Why is ${ctx.flaggedHosts[0]?.id || '192.168.10.44'} flagged for lateral movement?`,
      'What is the recommended isolation playbook for port 445?',
      'Explain top SHAP drivers for current threat probability',
      'What is the forecasted breach lead time?',
    ];
  } else if (ctx.riskLevel === 'watch') {
    return [
      'What reconnaissance activity is detected?',
      'Which destination ports have highest entropy?',
      'What are the mitigation steps for T1046 Network Discovery?',
      'Show active suspicious flows in this window',
    ];
  } else {
    return [
      'What is the normal baseline status of the enterprise network?',
      'How does the SparseRSSM model predict threat onset?',
      'Explain destination port entropy and SYN ratio indicators',
      'What are the configured MITRE detection rules?',
    ];
  }
}

// ── 9. Public Unified Query Handler ────────────────────────────

export interface IAnswerResponse {
  answer: string;
  references: string[];
  suggestedQueries: string[];
  context: {
    windowIndex: number;
    timestamp: string;
    stage: string;
    probability: number;
    riskLevel: string;
    confidence: number;
    leadTimeSeconds: number;
    provider: string;
  };
}

export async function answerTelemetryQuery(
  query: string,
  options?: { windowIndex?: number; contextHint?: string }
): Promise<IAnswerResponse> {
  const ctx = retrieveContext(query, options?.windowIndex);
  let result: { answer: string; references: string[]; provider: string } | null = null;

  const groqKey = (
    (process.env.GROQ_API_KEY !== undefined ? process.env.GROQ_API_KEY : undefined) ??
    (process.env.GR0Q_API_KEY !== undefined ? process.env.GR0Q_API_KEY : undefined) ??
    (process.env.GROK_API_KEY !== undefined ? process.env.GROK_API_KEY : undefined) ??
    env.GROQ_API_KEY ?? ''
  ).trim();

  const openRouterKey = (
    (process.env.OPENROUTER_API_KEY !== undefined ? process.env.OPENROUTER_API_KEY : undefined) ??
    env.OPENROUTER_API_KEY ?? ''
  ).trim();

  // 1. First: Groq API (openai/gpt-oss-20b first, then openai/gpt-oss-120b)
  if (groqKey.length > 0) {
    result = await generateWithGroq(query, ctx, groqKey);
  }

  // 2. Second: OpenRouter (nvidia/nemotron-3.5-lightning:free)
  if (!result && openRouterKey.length > 0) {
    result = await generateWithOpenRouter(query, ctx, openRouterKey);
  }

  // 3. Third: Built-in Cyber Causality Engine (Offline Fallback)
  if (!result) {
    const fallback = generateWithBuiltinCyberEngine(query, ctx);
    result = {
      ...fallback,
      provider: 'cyber_causality_engine',
    };
  }

  const suggestedQueries = getSuggestedQueries(options?.windowIndex);

  return {
    answer: result.answer,
    references: result.references,
    suggestedQueries,
    context: {
      windowIndex: ctx.windowIndex,
      timestamp: ctx.timestamp,
      stage: ctx.stage,
      probability: ctx.probability,
      riskLevel: ctx.riskLevel,
      confidence: ctx.confidence,
      leadTimeSeconds: ctx.leadTimeSeconds,
      provider: result.provider,
    },
  };
}
