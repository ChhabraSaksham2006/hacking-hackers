import React, { useState, useEffect } from "react";
import {
  Check,
  Copy,
  Terminal,
  Network,
  Activity,
  Shield,
  X,
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
  Info,
  AlertCircle,
} from "lucide-react";
import {
  fetchSensorsConfig,
  saveSensorSetup,
  regenerateSensorKey,
  type SensorsConfigResponse,
} from "@/api/sensorsApi";
import { ActionButton } from "@/components/app/panels";

interface OnboardingModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConnected?: () => void;
}

export function OnboardingModal({ isOpen, onClose, onConnected }: OnboardingModalProps) {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [deployMethod, setDeployMethod] = useState<"docker" | "python" | "span">("docker");
  const [config, setConfig] = useState<SensorsConfigResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [subnetsInput, setSubnetsInput] = useState<string>("192.168.10.0/24");
  const [environmentType, setEnvironmentType] = useState<string>("enterprise");
  const [sensorIdInput, setSensorIdInput] = useState<string>("edge-probe-core-01");
  const [interfaceInput, setInterfaceInput] = useState<string>("eth0");
  const [showKey, setShowKey] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<boolean>(false);
  const [copiedCmd, setCopiedCmd] = useState<boolean>(false);
  const [isSaving, setIsSaving] = useState<boolean>(false);

  // Poll sensor connection status when on step 3 or when open
  useEffect(() => {
    if (!isOpen) return;

    let isMounted = true;
    const loadConfig = async () => {
      try {
        const data = await fetchSensorsConfig();
        if (isMounted) {
          setConfig(data);
          if (data.monitoredSubnets && data.monitoredSubnets.length > 0) {
            setSubnetsInput(data.monitoredSubnets.join(", "));
          }
          if (data.environmentType) {
            setEnvironmentType(data.environmentType);
          }
          if (data.isLive && onConnected) {
            onConnected();
          }
        }
      } catch (err) {
        console.error("Failed to load sensor config:", err);
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    loadConfig();

    // Skip polling while the tab is hidden to save bandwidth
    const interval = setInterval(() => {
      if (!document.hidden) loadConfig();
    }, 3000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [isOpen, onConnected]);

  if (!isOpen) return null;

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

  const handleSaveStep1 = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    try {
      const subnets = subnetsInput
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);

      await saveSensorSetup({
        monitoredSubnets: subnets,
        environmentType,
        sensorSetupCompleted: true,
      });

      setStep(2);
    } catch (err) {
      console.error("Failed to save onboarding setup:", err);
    } finally {
      setIsSaving(false);
    }
  };

  const handleRegenerateKey = async () => {
    if (!confirm("Are you sure? Any running sensors using the old key will be disconnected.")) {
      return;
    }
    try {
      const res = await regenerateSensorKey();
      if (config) {
        setConfig({ ...config, sensorApiKey: res.sensorApiKey });
      }
    } catch (err) {
      console.error("Failed to regenerate key:", err);
    }
  };

  const upstreamUrl =
    config?.upstreamUrl ||
    (typeof window !== "undefined"
      ? `${window.location.origin}/api/sensors/telemetry`
      : "http://localhost:5000/api/sensors/telemetry");

  const apiKey = config?.sensorApiKey || "av_sec_sample_key";

  // Dynamic commands based on user inputs
  const dockerCmd = `docker run -d --restart=always \\
  --name aegis-edge-sensor \\
  --net=host \\
  --cap-add=NET_ADMIN \\
  -e AEGIS_API_KEY="${apiKey}" \\
  -e AEGIS_UPSTREAM_URL="${upstreamUrl}" \\
  -e AEGIS_SENSOR_ID="${sensorIdInput || "edge-probe-core-01"}" \\
  -e AEGIS_INTERFACE="${interfaceInput || "eth0"}" \\
  ghcr.io/aegis-vantage/edge-sensor:latest`;

  const pythonCmd = `python edge_sensor/run_sensor.py \\
  --mode tap \\
  --interface ${interfaceInput || "eth0"} \\
  --upstream ${upstreamUrl} \\
  --api-key ${apiKey} \\
  --sensor-id ${sensorIdInput || "edge-probe-core-01"}`;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-void-950/85 p-2 sm:p-4 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-3xl rounded-xl border border-fog-deep bg-void-900 shadow-2xl overflow-hidden flex flex-col max-h-[94vh] sm:max-h-[90vh]">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-fog-deep/60 px-4 sm:px-6 py-3 sm:py-4 bg-void-800/40">
          <div className="flex items-center gap-2.5 sm:gap-3">
            <div className="flex size-8 sm:size-9 items-center justify-center rounded-lg bg-teal/15 text-teal border border-teal/30 shrink-0">
              <Zap className="size-4 sm:size-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm sm:text-base font-semibold text-paper">
                  Connect Edge Sensor & Infrastructure
                </h2>
                <span className="rounded-full bg-void-700/60 px-2 py-0.5 text-[10px] font-mono text-fog border border-fog-deep/60 hidden xs:inline">
                  v2.4
                </span>
              </div>
              <p className="text-[11px] sm:text-xs text-fog line-clamp-1 sm:line-clamp-none">
                Transition from benchmark replay to live neural threat forecasting
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-fog hover:bg-void-700 hover:text-paper transition-colors shrink-0"
          >
            <X className="size-4" />
          </button>
        </div>

        {/* Explainability Pipeline Mini-Banner */}
        <div className="bg-void-950/70 border-b border-fog-deep/40 px-4 sm:px-6 py-2 flex items-center justify-between text-[10px] sm:text-[11px] text-fog overflow-x-auto">
          <div className="flex items-center gap-2 whitespace-nowrap py-0.5">
            <span className="font-semibold text-paper shrink-0">Pipeline:</span>
            <span className="flex items-center gap-1 text-teal shrink-0">
              <Network className="size-3" /> Mirror/TAP
            </span>
            <span className="text-fog-deep">➔</span>
            <span className="flex items-center gap-1 text-teal shrink-0">
              <Cpu className="size-3" /> 54-D Edge AI
            </span>
            <span className="text-fog-deep">➔</span>
            <span className="flex items-center gap-1 text-teal shrink-0">
              <Database className="size-3" /> Apache Kafka
            </span>
            <span className="text-fog-deep">➔</span>
            <span className="flex items-center gap-1 text-teal shrink-0">
              <Activity className="size-3" /> SOC Dashboard
            </span>
          </div>
        </div>

        {/* Multi-Step Nav */}
        <div className="grid grid-cols-3 border-b border-fog-deep/40 text-center text-xs font-medium bg-void-900/60">
          <button
            onClick={() => setStep(1)}
            className={`py-2.5 sm:py-3 transition-colors flex items-center justify-center gap-1.5 ${
              step === 1 ? "border-b-2 border-teal text-teal font-semibold bg-void-800/40" : "text-fog hover:text-paper"
            }`}
          >
            <Network className="size-3.5 shrink-0" />
            <span className="hidden sm:inline">1. Architecture & Scope</span>
            <span className="sm:hidden">1. Scope</span>
          </button>
          <button
            onClick={() => setStep(2)}
            className={`py-2.5 sm:py-3 transition-colors flex items-center justify-center gap-1.5 ${
              step === 2 ? "border-b-2 border-teal text-teal font-semibold bg-void-800/40" : "text-fog hover:text-paper"
            }`}
          >
            <Terminal className="size-3.5 shrink-0" />
            <span className="hidden sm:inline">2. Deployment</span>
            <span className="sm:hidden">2. Deploy</span>
          </button>
          <button
            onClick={() => setStep(3)}
            className={`py-2.5 sm:py-3 transition-colors flex items-center justify-center gap-1.5 ${
              step === 3 ? "border-b-2 border-teal text-teal font-semibold bg-void-800/40" : "text-fog hover:text-paper"
            }`}
          >
            <Activity className="size-3.5 shrink-0" />
            <span className="hidden sm:inline">3. Verification</span>
            <span className="sm:hidden">3. Verify</span>
          </button>
        </div>

        {/* Modal Scrollable Body */}
        <div className="p-6 overflow-y-auto space-y-5 flex-1">
          {/* STEP 1: ARCHITECTURE & SCOPE */}
          {step === 1 && (
            <form onSubmit={handleSaveStep1} className="space-y-5">
              
              {/* Architecture & Kafka explanation card */}
              <div className="rounded-xl border border-teal/20 bg-teal/5 p-4 space-y-3">
                <div className="flex items-start gap-3">
                  <div className="rounded-lg bg-teal/15 p-2 text-teal border border-teal/30 shrink-0">
                    <Shield className="size-4" />
                  </div>
                  <div className="space-y-1 text-xs text-paper">
                    <span className="font-semibold text-teal-light">
                      Non-Intrusive, Zero-Disruption Architecture
                    </span>
                    <p className="text-fog leading-relaxed">
                      The Aegis Vantage Edge Sensor attaches out-of-band to a network SPAN / mirror port or virtual interface. It performs completely passive, read-only packet inspection:
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 pt-1 text-[11px]">
                  <div className="rounded-lg border border-fog-deep/60 bg-void-800/60 p-2.5 space-y-1">
                    <div className="flex items-center gap-1.5 font-semibold text-paper">
                      <Lock className="size-3 text-teal" /> Zero Payload Exposure
                    </div>
                    <p className="text-fog">
                      Computes 54 statistical metrics (entropy, inter-arrival times, burstiness). Raw payload bodies are never logged or stored.
                    </p>
                  </div>
                  <div className="rounded-lg border border-fog-deep/60 bg-void-800/60 p-2.5 space-y-1">
                    <div className="flex items-center gap-1.5 font-semibold text-paper">
                      <Zap className="size-3 text-amber" /> Zero In-Line Latency
                    </div>
                    <p className="text-fog">
                      Operates purely out-of-band on mirrored packets. It cannot drop, delay, or impact production traffic.
                    </p>
                  </div>
                  <div className="rounded-lg border border-fog-deep/60 bg-void-800/60 p-2.5 space-y-1">
                    <div className="flex items-center gap-1.5 font-semibold text-paper">
                      <Database className="size-3 text-teal" /> On-Demand Kafka Broker
                    </div>
                    <p className="text-fog">
                      In demo mode, Kafka remains idle. Once a sensor connects, the high-throughput Kafka streaming pipeline is dynamically engaged.
                    </p>
                  </div>
                </div>
              </div>

              {/* Environment Type */}
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-fog mb-2">
                  Select Deployment Environment
                </label>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                  {[
                    { id: "enterprise", label: "Enterprise Core", desc: "Hardware SPAN / Switch Mirror" },
                    { id: "cloud_vpc", label: "Cloud VPC", desc: "AWS / Azure / GCP Mirroring" },
                    { id: "homelab", label: "Office / Host", desc: "Local Interface Sniffing" },
                    { id: "evaluation", label: "Interactive Gateway", desc: "Direct Ingress Tap Portal" },
                  ].map((env) => (
                    <button
                      type="button"
                      key={env.id}
                      onClick={() => setEnvironmentType(env.id)}
                      className={`flex flex-col items-start p-3 rounded-lg border text-left transition-all ${
                        environmentType === env.id
                          ? "border-teal bg-teal/10 text-paper ring-1 ring-teal/30"
                          : "border-fog-deep/60 bg-void-800/50 text-fog hover:border-fog hover:text-paper"
                      }`}
                    >
                      <span className="text-xs font-medium">{env.label}</span>
                      <span className="text-[11px] text-fog mt-0.5">{env.desc}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Monitored Subnets */}
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-fog mb-1.5">
                  Internal Monitored Subnets (CIDR notation)
                </label>
                <input
                  type="text"
                  value={subnetsInput}
                  onChange={(e) => setSubnetsInput(e.target.value)}
                  placeholder="e.g. 192.168.10.0/24, 10.0.0.0/16"
                  className="w-full rounded-lg border border-fog-deep bg-void-800 px-3.5 py-2.5 text-xs text-paper focus:border-teal focus:outline-none mono"
                  required
                />
                <p className="text-[11px] text-fog mt-1">
                  Specify your internal enterprise subnets. The neural Cyber World Model uses these boundaries to classify lateral pivot movements vs external perimeter breaches.
                </p>
              </div>

              {/* Actions */}
              <div className="flex flex-col-reverse sm:flex-row sm:items-center justify-between gap-3 pt-4 border-t border-fog-deep/40">
                <button
                  type="button"
                  onClick={onClose}
                  className="text-xs text-fog hover:text-paper transition-colors py-2 sm:py-0 text-center"
                >
                  Cancel (Stay in Demo Mode)
                </button>
                <ActionButton type="submit" disabled={isSaving} className="w-full sm:w-auto">
                  {isSaving ? "Saving Scope..." : "Next: Sensor Deployment Guide →"}
                </ActionButton>
              </div>
            </form>
          )}

          {/* STEP 2: SENSOR DEPLOYMENT */}
          {step === 2 && (
            <div className="space-y-5">
              
              {/* Secret Key Card */}
              <div className="rounded-xl border border-fog-deep bg-void-800/60 p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Lock className="size-3.5 text-teal" />
                    <span className="text-xs font-semibold uppercase tracking-wider text-paper">
                      Your Organization Sensor Secret Key
                    </span>
                  </div>
                  <button
                    onClick={handleRegenerateKey}
                    className="text-[11px] text-amber hover:underline flex items-center gap-1 transition-colors"
                    title="Rotate sensor key"
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
                      className="w-full rounded-lg border border-fog-deep bg-void-950 px-3.5 py-2 text-xs text-paper mono pr-9"
                    />
                    <button
                      type="button"
                      onClick={() => setShowKey(!showKey)}
                      className="absolute right-2.5 top-2.5 text-fog hover:text-paper"
                      title={showKey ? "Hide key" : "Show key"}
                    >
                      {showKey ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                    </button>
                  </div>
                  <ActionButton
                    variant="ghost"
                    onClick={() => handleCopy(apiKey, "key")}
                    className="shrink-0 flex items-center gap-1.5 text-xs px-3"
                  >
                    {copiedKey ? <Check className="size-3.5 text-teal" /> : <Copy className="size-3.5" />}
                    {copiedKey ? "Copied" : "Copy Key"}
                  </ActionButton>
                </div>
                <p className="text-[11px] text-fog">
                  This key authenticates high-throughput telemetry packets. Keep it confidential.
                </p>
              </div>

              {/* Sensor Parameters Customizer */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-fog mb-1">
                    Sensor Identifier (Tag)
                  </label>
                  <input
                    type="text"
                    value={sensorIdInput}
                    onChange={(e) => setSensorIdInput(e.target.value)}
                    placeholder="e.g. edge-probe-core-01"
                    className="w-full rounded-lg border border-fog-deep bg-void-800 px-3 py-1.5 text-xs text-paper mono focus:border-teal focus:outline-none"
                  />
                  <span className="text-[10px] text-fog">Unique name displayed in multi-sensor dropdowns</span>
                </div>
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-fog mb-1">
                    Host Network Interface
                  </label>
                  <input
                    type="text"
                    value={interfaceInput}
                    onChange={(e) => setInterfaceInput(e.target.value)}
                    placeholder="e.g. eth0, ens192, any"
                    className="w-full rounded-lg border border-fog-deep bg-void-800 px-3 py-1.5 text-xs text-paper mono focus:border-teal focus:outline-none"
                  />
                  <span className="text-[10px] text-fog">Target SPAN mirror interface on the sensor host</span>
                </div>
              </div>

              {/* Deployment Method Tabs */}
              <div>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                  <label className="text-xs font-semibold uppercase tracking-wider text-fog">
                    Deployment Method
                  </label>
                  <div className="grid grid-cols-3 sm:flex rounded-lg border border-fog-deep/60 bg-void-950 p-0.5 text-xs w-full sm:w-auto">
                    <button
                      type="button"
                      onClick={() => setDeployMethod("docker")}
                      className={`px-2.5 sm:px-3 py-1 rounded-md transition-colors text-center ${
                        deployMethod === "docker"
                          ? "bg-teal text-void-950 font-semibold"
                          : "text-fog hover:text-paper"
                      }`}
                    >
                      Docker<span className="hidden sm:inline"> (Rec.)</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setDeployMethod("python")}
                      className={`px-2.5 sm:px-3 py-1 rounded-md transition-colors text-center ${
                        deployMethod === "python"
                          ? "bg-teal text-void-950 font-semibold"
                          : "text-fog hover:text-paper"
                      }`}
                    >
                      Python<span className="hidden sm:inline"> CLI</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setDeployMethod("span")}
                      className={`px-2.5 sm:px-3 py-1 rounded-md transition-colors text-center ${
                        deployMethod === "span"
                          ? "bg-teal text-void-950 font-semibold"
                          : "text-fog hover:text-paper"
                      }`}
                    >
                      SPAN<span className="hidden sm:inline"> Guide</span>
                    </button>
                  </div>
                </div>

                {/* DOCKER TAB */}
                {deployMethod === "docker" && (
                  <div className="space-y-2">
                    <div className="relative rounded-xl border border-fog-deep bg-void-950 p-3.5 font-mono text-xs text-teal-light overflow-x-auto">
                      <pre className="whitespace-pre-wrap leading-relaxed">{dockerCmd}</pre>
                      <button
                        onClick={() => handleCopy(dockerCmd, "cmd")}
                        className="absolute top-2.5 right-2.5 rounded bg-void-800 px-2 py-1 text-fog hover:text-paper text-[11px] flex items-center gap-1 border border-fog-deep/60"
                        title="Copy command"
                      >
                        {copiedCmd ? <Check className="size-3 text-teal" /> : <Copy className="size-3" />}
                        {copiedCmd ? "Copied" : "Copy"}
                      </button>
                    </div>
                    <p className="text-[11px] text-fog leading-relaxed">
                      Runs the sensor in a lightweight Alpine container (~40MB). Uses <code className="mono text-paper">--net=host</code> and <code className="mono text-paper">--cap-add=NET_ADMIN</code> to bind passively to the raw mirror socket.
                    </p>
                  </div>
                )}

                {/* PYTHON CLI TAB */}
                {deployMethod === "python" && (
                  <div className="space-y-2">
                    <div className="relative rounded-xl border border-fog-deep bg-void-950 p-3.5 font-mono text-xs text-teal-light overflow-x-auto">
                      <pre className="whitespace-pre-wrap leading-relaxed">{pythonCmd}</pre>
                      <button
                        onClick={() => handleCopy(pythonCmd, "cmd")}
                        className="absolute top-2.5 right-2.5 rounded bg-void-800 px-2 py-1 text-fog hover:text-paper text-[11px] flex items-center gap-1 border border-fog-deep/60"
                        title="Copy command"
                      >
                        {copiedCmd ? <Check className="size-3 text-teal" /> : <Copy className="size-3" />}
                        {copiedCmd ? "Copied" : "Copy"}
                      </button>
                    </div>
                    <p className="text-[11px] text-fog leading-relaxed">
                      Requires Python 3.10+. Zero third-party dependencies required for base telemetry. Runs standard raw packet sniffer on the specified interface.
                    </p>
                  </div>
                )}

                {/* SPAN CONFIG GUIDE */}
                {deployMethod === "span" && (
                  <div className="rounded-xl border border-fog-deep/70 bg-void-950/80 p-3.5 space-y-3 text-xs text-fog">
                    <div>
                      <span className="font-semibold text-paper block mb-1">
                        1. Cisco Catalyst / Nexus Switch SPAN Configuration:
                      </span>
                      <pre className="bg-void-900 border border-fog-deep/40 rounded p-2 font-mono text-[11px] text-paper">
{`switch(config)# monitor session 1 source interface GigabitEthernet0/1 both
switch(config)# monitor session 1 destination interface GigabitEthernet0/2`}
                      </pre>
                    </div>
                    <div>
                      <span className="font-semibold text-paper block mb-1">
                        2. Cloud VPC Traffic Mirroring (AWS / Azure / GCP):
                      </span>
                      <p className="text-[11px] leading-relaxed">
                        Create a Traffic Mirror Filter (All Ingress/Egress) pointing to a Traffic Mirror Target (Network Interface or Network Load Balancer attached to the Aegis Sensor VM).
                      </p>
                    </div>
                  </div>
                )}
              </div>

              {/* Actions */}
              <div className="flex flex-col-reverse sm:flex-row sm:items-center justify-between gap-3 pt-3 border-t border-fog-deep/40">
                <button
                  type="button"
                  onClick={() => setStep(1)}
                  className="text-xs text-fog hover:text-paper transition-colors py-2 sm:py-0 text-center"
                >
                  ← Back to Scope
                </button>
                <ActionButton onClick={() => setStep(3)} className="w-full sm:w-auto">
                  I have started the sensor → Check Live Stream
                </ActionButton>
              </div>
            </div>
          )}

          {/* STEP 3: LIVE VERIFICATION */}
          {step === 3 && (
            <div className="space-y-6 text-center py-4">
              {config?.isLive ? (
                <div className="space-y-4 animate-fade-in max-w-lg mx-auto">
                  <div className="mx-auto flex size-16 items-center justify-center rounded-full bg-teal/20 text-teal border border-teal/40">
                    <Check className="size-8" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-paper">
                      Live Telemetry Stream Active!
                    </h3>
                    <p className="text-xs text-fog mt-1">
                      Aegis Vantage is receiving real-time 2.0-second telemetry from{" "}
                      <span className="font-semibold text-teal">
                        {config.activeSensorsCount} sensor{config.activeSensorsCount === 1 ? "" : "s"}
                      </span>
                      .
                    </p>
                  </div>

                  <div className="rounded-xl border border-teal/30 bg-teal/5 p-3.5 text-left text-xs space-y-2">
                    <div className="flex items-center justify-between text-teal-light font-semibold">
                      <span>Telemetry Pipeline Status:</span>
                      <span className="flex items-center gap-1.5 text-teal">
                        <span className="size-2 rounded-full bg-teal animate-ping" /> Active Live Feed
                      </span>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-[11px] text-fog pt-1 border-t border-teal/20">
                      <div>
                        Ingestion Target: <span className="mono text-paper">/api/sensors/telemetry</span>
                      </div>
                      <div>
                        Message Broker: <span className="mono text-paper">{config.kafkaActive ? "Apache Kafka (Active)" : "High-Speed Memory Stream"}</span>
                      </div>
                    </div>
                  </div>

                  <div className="pt-2">
                    <ActionButton
                      onClick={() => {
                        onClose();
                        if (onConnected) onConnected();
                      }}
                      className="px-8 py-3 text-sm font-semibold"
                    >
                      Open Live SOC Dashboard →
                    </ActionButton>
                  </div>
                </div>
              ) : (
                <div className="space-y-4 max-w-lg mx-auto">
                  <div className="mx-auto flex size-14 items-center justify-center rounded-full bg-amber/15 text-amber border border-amber/30 animate-pulse">
                    <Activity className="size-7 animate-spin" />
                  </div>
                  <div>
                    <h3 className="text-base font-semibold text-paper">
                      Listening for Ingress Telemetry...
                    </h3>
                    <p className="text-xs text-fog mt-1">
                      Waiting for the first 2.0s telemetry packet at{" "}
                      <span className="mono text-teal-light break-all">{upstreamUrl}</span>
                    </p>
                  </div>

                  <div className="rounded-xl border border-fog-deep/60 bg-void-950 p-3.5 text-left text-xs space-y-2">
                    <span className="font-semibold text-paper block">Troubleshooting Checklist:</span>
                    <ul className="space-y-1.5 text-[11px] text-fog">
                      <li className="flex items-center gap-2">
                        <Check className="size-3 text-teal shrink-0" />
                        Ensure your container/host has network connectivity to this server.
                      </li>
                      <li className="flex items-center gap-2">
                        <Check className="size-3 text-teal shrink-0" />
                        Check that the API key <code className="mono text-paper">{apiKey.slice(0, 10)}...</code> matches your configuration.
                      </li>
                      <li className="flex items-center gap-2">
                        <Check className="size-3 text-teal shrink-0" />
                        Make sure your interface is receiving packets (or start with <code className="mono text-paper">--mode live</code> for local testing).
                      </li>
                    </ul>
                  </div>

                  <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
                    <ActionButton variant="ghost" onClick={() => setStep(2)} className="w-full sm:w-auto">
                      ← Review Command & API Key
                    </ActionButton>
                    <button
                      onClick={onClose}
                      className="text-xs text-fog hover:text-paper transition-colors px-3 py-2 w-full sm:w-auto text-center"
                    >
                      Close & Keep Exploring Demo
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
