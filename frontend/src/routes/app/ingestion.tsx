import { useState, useEffect } from "react";
import { createFileRoute } from "@tanstack/react-router";
import {
  Check,
  Copy,
  Terminal,
  Network,
  Activity,
  Shield,
  RefreshCw,
  Radio,
  Server,
  Zap,
  Eye,
  EyeOff,
  Lock,
  Layers,
  ArrowRight,
  Cpu,
  Database,
  UploadCloud,
  Loader2,
  AlertCircle,
  FileCode,
} from "lucide-react";
import {
  ActionButton,
  FlatPanel,
  PageTitle,
  RiskBadge,
} from "@/components/app/panels";
import { pageHead } from "@/lib/head";
import { cn } from "@/lib/utils";
import {
  fetchSensorsConfig,
  saveSensorSetup,
  regenerateSensorKey,
  type SensorsConfigResponse,
} from "@/api/sensorsApi";
import { OnboardingModal } from "@/components/app/OnboardingModal";

export const Route = createFileRoute("/app/ingestion")({
  head: pageHead(
    "Telemetry Ingestion — Flow दृष्टि",
    "Configure edge sensor mirror ports, manage Kafka stream ingestion, and upload PCAP forensic captures.",
  ),
  component: IngestionPage,
});

const steps = [
  { name: "Raw Packet Ingress", status: "done" },
  { name: "54-D Feature Extraction", status: "done" },
  { name: "Kafka Partition Queuing", status: "done" },
  { name: "SparseRSSM Inference", status: "running" },
  { name: "SOC Alert Dispatch", status: "pending" },
] as const;

const pcapHistory = [
  { file: "cicids-2018-thursday-infiltration.pcap", set: "CSE-CIC-IDS2018", size: "4.2 GB", at: "Live Replay", ok: true },
  { file: "ctu13-botnet-capture.pcap", set: "CTU-13 Benchmark", size: "1.1 GB", at: "2026-09-20 14:10Z", ok: true },
  { file: "corp-core-span-dump.pcap", set: "SPAN Mirror Dump", size: "640 MB", at: "2026-09-18 09:30Z", ok: true },
  { file: "dmz-perimeter-trace.pcap", set: "Internal Audit", size: "185 MB", at: "2026-09-15 17:41Z", ok: true },
];

function IngestionPage() {
  const [activeTab, setActiveTab] = useState<"live" | "pcap">("live");
  const [config, setConfig] = useState<SensorsConfigResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [isOnboardingOpen, setIsOnboardingOpen] = useState(false);
  const [showKey, setShowKey] = useState(false);
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);
  const [deployType, setDeployType] = useState<"docker" | "python" | "span">("docker");
  const [sensorId, setSensorId] = useState("edge-probe-01");
  const [interfaceName, setInterfaceName] = useState("eth0");
  const [dragging, setDragging] = useState(false);

  // Poll sensor config and live status
  useEffect(() => {
    let isMounted = true;
    const load = async () => {
      try {
        const data = await fetchSensorsConfig();
        if (isMounted) {
          setConfig(data);
        }
      } catch (err) {
        console.error("Failed to load sensors config:", err);
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    load();
    // Skip polling while the tab is hidden to save bandwidth
    const interval = setInterval(() => {
      if (!document.hidden) load();
    }, 3000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const handleCopy = (text: string, type: "key" | "cmd") => {
    navigator.clipboard.writeText(text);
    if (type === "key") {
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    } else {
      setCopiedCmd(true);
      setTimeout(() => setCopiedCmd(false), 2000);
    }
  };

  const handleRegenerateKey = async () => {
    if (!confirm("Are you sure? Rotating the secret key will disconnect currently active edge sensors.")) {
      return;
    }
    try {
      const res = await regenerateSensorKey();
      if (config) {
        setConfig({ ...config, sensorApiKey: res.sensorApiKey });
      }
    } catch (err) {
      console.error("Failed to rotate key:", err);
    }
  };

  const upstreamUrl =
    config?.upstreamUrl ||
    (typeof window !== "undefined"
      ? `${window.location.origin}/api/sensors/telemetry`
      : "http://localhost:5000/api/sensors/telemetry");

  const apiKey = config?.sensorApiKey || "av_sec_sample_key";

  const dockerCmd = `docker run -d --restart=always \\
  --name aegis-edge-sensor \\
  --net=host \\
  --cap-add=NET_ADMIN \\
  -e AEGIS_API_KEY="${apiKey}" \\
  -e AEGIS_UPSTREAM_URL="${upstreamUrl}" \\
  -e AEGIS_SENSOR_ID="${sensorId}" \\
  -e AEGIS_INTERFACE="${interfaceName}" \\
  ghcr.io/aegis-vantage/edge-sensor:latest`;

  const pythonCmd = `python edge_sensor/run_sensor.py \\
  --mode tap \\
  --interface ${interfaceName} \\
  --upstream ${upstreamUrl} \\
  --api-key ${apiKey} \\
  --sensor-id ${sensorId}`;

  return (
    <>
      <PageTitle
        title="Telemetry Ingestion & Edge Sensors"
        note="Connect passive network SPAN mirror ports, stream high-throughput telemetry through Kafka, or ingest forensic PCAPs."
        actions={
          <ActionButton
            onClick={() => setIsOnboardingOpen(true)}
            className="flex items-center gap-1.5"
          >
            <Zap className="size-3.5" />
            Guided Sensor Setup
          </ActionButton>
        }
      />

      {/* Guided Onboarding Modal */}
      <OnboardingModal
        isOpen={isOnboardingOpen}
        onClose={() => setIsOnboardingOpen(false)}
        onConnected={() => setIsOnboardingOpen(false)}
      />

      {/* Telemetry Status Summary Cards */}
      <div className="mb-6 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Stream Status Card */}
        <div className="rounded-xl border border-fog-deep/60 bg-void-800/80 p-4">
          <div className="flex items-center justify-between text-xs text-fog mb-1.5">
            <span className="font-semibold uppercase tracking-wider">Stream State</span>
            {config?.isLive ? (
              <span className="flex size-2 rounded-full bg-teal animate-pulse" />
            ) : (
              <span className="size-2 rounded-full bg-amber" />
            )}
          </div>
          <div className="flex items-baseline gap-2">
            <p className={cn("text-lg font-bold font-display", config?.isLive ? "text-teal" : "text-amber")}>
              {config?.isLive ? "Live Telemetry" : "Demo Benchmark"}
            </p>
          </div>
          <p className="text-[11px] text-fog mt-1">
            {config?.isLive
              ? "Receiving real 2.0s packets from infrastructure"
              : "Replaying CIC-IDS-2018 infiltration benchmark"}
          </p>
        </div>

        {/* Active Sensors Card */}
        <div className="rounded-xl border border-fog-deep/60 bg-void-800/80 p-4">
          <div className="flex items-center justify-between text-xs text-fog mb-1.5">
            <span className="font-semibold uppercase tracking-wider">Connected Sensors</span>
            <Activity className="size-3.5 text-fog" />
          </div>
          <div className="flex items-baseline gap-2">
            <p className="text-lg font-bold font-display text-paper">
              {config?.activeSensorsCount ?? 0}
            </p>
            <span className="text-xs text-fog">active probe(s)</span>
          </div>
          <p className="text-[11px] text-fog mt-1">
            {config?.activeSensorsCount ? "Sensors sending 54-D telemetry" : "Awaiting first sensor connection"}
          </p>
        </div>

        {/* Message Broker Card */}
        <div className="rounded-xl border border-fog-deep/60 bg-void-800/80 p-4">
          <div className="flex items-center justify-between text-xs text-fog mb-1.5">
            <span className="font-semibold uppercase tracking-wider">Message Broker</span>
            <Database className="size-3.5 text-fog" />
          </div>
          <div className="flex items-baseline gap-2">
            <p className="text-lg font-bold font-display text-paper">
              {config?.kafkaActive ? "Apache Kafka" : "Memory Stream"}
            </p>
          </div>
          <p className="text-[11px] text-fog mt-1">
            {config?.kafkaActive ? "Partitioned on aegis.telemetry.raw" : "High-throughput fallback active"}
          </p>
        </div>

        {/* Monitored Subnets Card */}
        <div className="rounded-xl border border-fog-deep/60 bg-void-800/80 p-4">
          <div className="flex items-center justify-between text-xs text-fog mb-1.5">
            <span className="font-semibold uppercase tracking-wider">Monitored Scope</span>
            <Network className="size-3.5 text-fog" />
          </div>
          <div className="flex items-baseline gap-2">
            <p className="text-xs font-mono font-semibold text-paper truncate">
              {config?.monitoredSubnets?.join(", ") || "192.168.10.0/24"}
            </p>
          </div>
          <p className="text-[11px] text-fog mt-1">
            Subnet boundaries for lateral risk triage
          </p>
        </div>
      </div>

      {/* Mode Navigation Tabs */}
      <div className="mb-6 flex border-b border-fog-deep/60">
        <button
          onClick={() => setActiveTab("live")}
          className={cn(
            "flex items-center gap-2 border-b-2 px-4 py-2.5 text-xs font-semibold transition-colors",
            activeTab === "live"
              ? "border-teal text-teal"
              : "border-transparent text-fog hover:text-paper",
          )}
        >
          <Zap className="size-4" />
          Live Edge Sensor & SPAN Ports (Recommended)
        </button>
        <button
          onClick={() => setActiveTab("pcap")}
          className={cn(
            "flex items-center gap-2 border-b-2 px-4 py-2.5 text-xs font-semibold transition-colors",
            activeTab === "pcap"
              ? "border-teal text-teal"
              : "border-transparent text-fog hover:text-paper",
          )}
        >
          <FileCode className="size-4" />
          Forensic PCAP File Upload
        </button>
      </div>

      {/* TAB 1: LIVE EDGE SENSORS & PORT MIRRORING */}
      {activeTab === "live" && (
        <div className="space-y-6 animate-fade-in">
          
          {/* Explainability Pipeline Card */}
          <div className="rounded-xl border border-teal/30 bg-teal/5 p-4 sm:p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <div className="rounded-lg bg-teal/20 p-2 text-teal border border-teal/40">
                  <Shield className="size-5" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-paper">
                    How Edge Telemetry Ingestion Works
                  </h3>
                  <p className="text-xs text-fog">
                    Passive, out-of-band packet inspection with zero application payload exposure
                  </p>
                </div>
              </div>
              <button
                onClick={() => setIsOnboardingOpen(true)}
                className="rounded-md border border-teal/40 bg-teal/20 px-3 py-1.5 text-xs font-medium text-teal hover:bg-teal/30 transition-colors self-start sm:self-auto"
              >
                Open Setup Wizard →
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 text-xs">
              <div className="rounded-lg border border-fog-deep/60 bg-void-900/60 p-3 space-y-1">
                <div className="flex items-center gap-1.5 font-semibold text-paper">
                  <Lock className="size-3.5 text-teal" /> 1. Zero Payload Exposure
                </div>
                <p className="text-[11px] text-fog leading-relaxed">
                  The sensor calculates 54 statistical metrics (byte entropy, packet jitter, SYN ratios). Raw payloads are never stored or transmitted to the cloud.
                </p>
              </div>

              <div className="rounded-lg border border-fog-deep/60 bg-void-900/60 p-3 space-y-1">
                <div className="flex items-center gap-1.5 font-semibold text-paper">
                  <Zap className="size-3.5 text-amber" /> 2. Zero In-Line Latency
                </div>
                <p className="text-[11px] text-fog leading-relaxed">
                  Attaches passively to switch SPAN ports, virtual TAPs, or mirror interfaces. Cannot drop or delay production corporate network traffic.
                </p>
              </div>

              <div className="rounded-lg border border-fog-deep/60 bg-void-900/60 p-3 space-y-1">
                <div className="flex items-center gap-1.5 font-semibold text-paper">
                  <Database className="size-3.5 text-teal" /> 3. Kafka Ingestion Stream
                </div>
                <p className="text-[11px] text-fog leading-relaxed">
                  Once connected, telemetry routes through topic <code className="mono text-teal-light">aegis.telemetry.raw</code> partitioned by your tenant ID for sub-second threat alerts.
                </p>
              </div>
            </div>
          </div>

          {/* Sensor Secret Key & Dynamic Command Customizer */}
          <FlatPanel title="Edge Sensor Authentication & Deployment Commands">
            <div className="space-y-4">
              
              {/* API Key Box */}
              <div className="rounded-lg border border-fog-deep/60 bg-void-950 p-3.5 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-paper flex items-center gap-1.5">
                    <Lock className="size-3 text-teal" /> Organization Sensor API Secret Key
                  </span>
                  <button
                    onClick={handleRegenerateKey}
                    className="text-[11px] text-amber hover:underline flex items-center gap-1"
                  >
                    <RefreshCw className="size-3" /> Rotate Key
                  </button>
                </div>
                <div className="flex items-center gap-2">
                  <div className="relative flex-1">
                    <input
                      type={showKey ? "text" : "password"}
                      readOnly
                      value={apiKey}
                      className="w-full rounded border border-fog-deep bg-void-900 px-3 py-1.5 text-xs text-paper mono pr-8"
                    />
                    <button
                      type="button"
                      onClick={() => setShowKey(!showKey)}
                      className="absolute right-2 top-2 text-fog hover:text-paper"
                    >
                      {showKey ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                    </button>
                  </div>
                  <ActionButton
                    variant="ghost"
                    onClick={() => handleCopy(apiKey, "key")}
                    className="shrink-0 text-xs px-3"
                  >
                    {copiedKey ? <Check className="size-3.5 text-teal" /> : <Copy className="size-3.5" />}
                    {copiedKey ? "Copied" : "Copy"}
                  </ActionButton>
                </div>
              </div>

              {/* Dynamic Inputs */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-fog mb-1">
                    Sensor Identifier Tag
                  </label>
                  <input
                    type="text"
                    value={sensorId}
                    onChange={(e) => setSensorId(e.target.value)}
                    placeholder="e.g. edge-probe-core-01"
                    className="w-full rounded border border-fog-deep bg-void-800 px-3 py-1.5 text-xs text-paper mono focus:border-teal focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-fog mb-1">
                    Host Sniffing Interface / SPAN Port
                  </label>
                  <input
                    type="text"
                    value={interfaceName}
                    onChange={(e) => setInterfaceName(e.target.value)}
                    placeholder="e.g. eth0, ens192, any"
                    className="w-full rounded border border-fog-deep bg-void-800 px-3 py-1.5 text-xs text-paper mono focus:border-teal focus:outline-none"
                  />
                </div>
              </div>

              {/* Method Selector Tabs */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-fog">
                    Deployment Method
                  </span>
                  <div className="flex rounded-lg border border-fog-deep/60 bg-void-950 p-0.5 text-xs">
                    <button
                      onClick={() => setDeployType("docker")}
                      className={cn(
                        "px-3 py-1 rounded transition-colors",
                        deployType === "docker" ? "bg-teal text-void-950 font-semibold" : "text-fog hover:text-paper"
                      )}
                    >
                      Docker Container
                    </button>
                    <button
                      onClick={() => setDeployType("python")}
                      className={cn(
                        "px-3 py-1 rounded transition-colors",
                        deployType === "python" ? "bg-teal text-void-950 font-semibold" : "text-fog hover:text-paper"
                      )}
                    >
                      Python CLI
                    </button>
                    <button
                      onClick={() => setDeployType("span")}
                      className={cn(
                        "px-3 py-1 rounded transition-colors",
                        deployType === "span" ? "bg-teal text-void-950 font-semibold" : "text-fog hover:text-paper"
                      )}
                    >
                      Switch SPAN Guide
                    </button>
                  </div>
                </div>

                {deployType === "docker" && (
                  <div className="relative rounded-lg border border-fog-deep bg-void-950 p-3 font-mono text-xs text-teal-light overflow-x-auto">
                    <pre className="whitespace-pre-wrap leading-relaxed">{dockerCmd}</pre>
                    <button
                      onClick={() => handleCopy(dockerCmd, "cmd")}
                      className="absolute top-2 right-2 rounded bg-void-800 px-2 py-1 text-fog hover:text-paper text-[11px] flex items-center gap-1 border border-fog-deep/60"
                    >
                      {copiedCmd ? <Check className="size-3 text-teal" /> : <Copy className="size-3" />}
                      {copiedCmd ? "Copied" : "Copy Command"}
                    </button>
                  </div>
                )}

                {deployType === "python" && (
                  <div className="relative rounded-lg border border-fog-deep bg-void-950 p-3 font-mono text-xs text-teal-light overflow-x-auto">
                    <pre className="whitespace-pre-wrap leading-relaxed">{pythonCmd}</pre>
                    <button
                      onClick={() => handleCopy(pythonCmd, "cmd")}
                      className="absolute top-2 right-2 rounded bg-void-800 px-2 py-1 text-fog hover:text-paper text-[11px] flex items-center gap-1 border border-fog-deep/60"
                    >
                      {copiedCmd ? <Check className="size-3 text-teal" /> : <Copy className="size-3" />}
                      {copiedCmd ? "Copied" : "Copy Command"}
                    </button>
                  </div>
                )}

                {deployType === "span" && (
                  <div className="rounded-lg border border-fog-deep bg-void-950 p-3 text-xs space-y-2 text-fog">
                    <p className="font-semibold text-paper">Cisco Catalyst / Nexus SPAN Configuration:</p>
                    <pre className="bg-void-900 border border-fog-deep/40 rounded p-2 text-paper font-mono text-[11px]">
{`switch(config)# monitor session 1 source interface GigabitEthernet0/1 both
switch(config)# monitor session 1 destination interface GigabitEthernet0/2`}
                    </pre>
                    <p className="text-[11px]">
                      Connect the sensor machine's physical network adapter to port <code className="mono text-paper">Gi0/2</code> and specify its interface name above.
                    </p>
                  </div>
                )}
              </div>
            </div>
          </FlatPanel>

          {/* Active Sensor Fleet Table */}
          <FlatPanel
            title="Connected Edge Sensor Probes"
            control={
              config?.isLive ? (
                <span className="text-[11px] text-teal font-mono flex items-center gap-1">
                  <span className="size-1.5 rounded-full bg-teal animate-ping" /> Real-Time Telemetry Stream
                </span>
              ) : (
                <span className="text-[11px] text-amber font-mono">
                  Awaiting Telemetry
                </span>
              )
            }
            bodyClassName="p-0 overflow-x-auto"
          >
            {config?.activeSensors && config.activeSensors.length > 0 ? (
              <table className="w-full min-w-[650px] text-left text-xs">
                <thead className="text-fog border-b border-fog-deep/60 bg-void-950/40">
                  <tr>
                    <th className="px-5 py-3 font-medium">Sensor ID</th>
                    <th className="px-5 py-3 font-medium">Predicted Stage</th>
                    <th className="px-5 py-3 font-medium">Risk Tier</th>
                    <th className="px-5 py-3 font-medium text-right">Probability</th>
                    <th className="px-5 py-3 font-medium text-right">Active Flows</th>
                    <th className="px-5 py-3 font-medium text-right">Packets/Window</th>
                    <th className="px-5 py-3 font-medium text-right">Last Received</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-fog-deep/40">
                  {config.activeSensors.map((s) => (
                    <tr key={s.sensorId} className="hover:bg-paper/4">
                      <td className="px-5 py-3 font-mono font-semibold text-paper flex items-center gap-2">
                        <span className="size-2 rounded-full bg-teal animate-pulse" />
                        {s.sensorId}
                      </td>
                      <td className="px-5 py-3 text-paper">{s.stage || "Normal Baseline"}</td>
                      <td className="px-5 py-3">
                        <RiskBadge state={s.risk_level === "critical" ? "critical" : s.risk_level === "watch" ? "watch" : "normal"} />
                      </td>
                      <td className="px-5 py-3 font-mono text-right text-paper">
                        {(s.probability * 100).toFixed(1)}%
                      </td>
                      <td className="px-5 py-3 font-mono text-right text-fog">
                        {s.activeFlows}
                      </td>
                      <td className="px-5 py-3 font-mono text-right text-fog">
                        {s.packets}
                      </td>
                      <td className="px-5 py-3 font-mono text-right text-fog">
                        {Math.max(0, Math.round((Date.now() - s.receivedAt) / 1000))}s ago
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="py-8 text-center space-y-3">
                <div className="mx-auto flex size-12 items-center justify-center rounded-full bg-amber/15 text-amber border border-amber/30">
                  <Activity className="size-6 animate-pulse" />
                </div>
                <div>
                  <p className="text-sm font-semibold text-paper">No Live Sensors Connected Yet</p>
                  <p className="text-xs text-fog mt-0.5 max-w-md mx-auto">
                    Your dashboard is currently running in benchmark simulation mode. Once you start an edge sensor with your secret key, it will appear here instantly.
                  </p>
                </div>
                <ActionButton onClick={() => setIsOnboardingOpen(true)}>
                  Launch Setup Wizard
                </ActionButton>
              </div>
            )}
          </FlatPanel>
        </div>
      )}

      {/* TAB 2: FORENSIC PCAP UPLOAD */}
      {activeTab === "pcap" && (
        <div className="space-y-6 animate-fade-in">
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragging(false);
            }}
            className={cn(
              "flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed bg-void-800/80 px-8 py-12 transition-colors text-center",
              dragging ? "border-teal bg-teal/5" : "border-fog-deep",
            )}
          >
            <div className="rounded-full bg-teal/15 p-3 text-teal border border-teal/30 mb-1">
              <UploadCloud className="size-6" />
            </div>
            <p className="text-sm font-semibold text-paper">
              Drag & Drop Binary PCAP Capture or NetFlow CSV
            </p>
            <p className="text-xs text-fog max-w-md">
              Supports standard <code className="mono text-paper">.pcap</code>, <code className="mono text-paper">.pcapng</code>, or IPFIX exports up to 20 GB. The file will be parsed into 2.0s temporal observation windows.
            </p>
            <div className="pt-2 flex items-center gap-2">
              <ActionButton>Choose File to Upload</ActionButton>
            </div>
            <p className="text-[11px] text-fog mt-2">
              Or replay directly from the edge sensor CLI:{" "}
              <code className="mono text-teal-light">python edge_sensor/run_sensor.py --mode pcap --file capture.pcap</code>
            </p>
          </div>

          <FlatPanel title="Capture Processing Pipeline">
            <ol className="grid gap-4 grid-cols-2 sm:grid-cols-3 lg:grid-cols-5">
              {steps.map((s, i) => (
                <li key={s.name} className="flex items-start gap-3">
                  <span className="mono w-5 shrink-0 text-fog">{i + 1}</span>
                  <div>
                    <p
                      className={cn(
                        "text-[13px] font-medium",
                        s.status === "pending" ? "text-fog" : "text-paper",
                      )}
                    >
                      {s.name}
                    </p>
                    <p className="mt-1 flex items-center gap-1.5 text-[12px] text-fog">
                      {s.status === "done" && (
                        <>
                          <Check className="size-3.5 text-teal" /> done
                        </>
                      )}
                      {s.status === "running" && (
                        <>
                          <Loader2 className="size-3.5 animate-spin text-amber" />{" "}
                          running
                        </>
                      )}
                      {s.status === "pending" && "pending"}
                    </p>
                  </div>
                </li>
              ))}
            </ol>
          </FlatPanel>

          <FlatPanel title="Ingestion History" bodyClassName="p-0 overflow-x-auto">
            <table className="w-full min-w-[580px] text-left text-xs">
              <thead className="text-fog border-b border-fog-deep/60 bg-void-950/40">
                <tr>
                  <th className="px-5 py-3 font-medium">Capture File</th>
                  <th className="px-5 py-3 font-medium">Dataset Origin</th>
                  <th className="px-5 py-3 text-right font-medium">Size</th>
                  <th className="px-5 py-3 font-medium">Ingestion Time</th>
                  <th className="px-5 py-3 font-medium">Status</th>
                  <th className="px-5 py-3 text-right font-medium">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-fog-deep/40">
                {pcapHistory.map((h) => (
                  <tr key={h.file} className="hover:bg-paper/4">
                    <td className="mono px-5 py-3 text-paper font-semibold">{h.file}</td>
                    <td className="px-5 py-3 text-fog">{h.set}</td>
                    <td className="mono px-5 py-3 text-right text-fog">{h.size}</td>
                    <td className="mono px-5 py-3 text-fog">{h.at}</td>
                    <td className="px-5 py-3">
                      <RiskBadge
                        state={h.ok ? "normal" : "critical"}
                        label={h.ok ? "Analyzed" : "Failed"}
                      />
                    </td>
                    <td className="px-5 py-3 text-right">
                      <button className="text-teal hover:underline font-medium">
                        View Threat State →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </FlatPanel>
        </div>
      )}
    </>
  );
}
