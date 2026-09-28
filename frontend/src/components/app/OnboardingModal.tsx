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
} from "lucide-react";
import {
  fetchSensorsConfig,
  saveSensorSetup,
  regenerateSensorKey,
  type SensorsConfigResponse,
} from "@/api/sensorsApi";
import { ActionButton, FlatPanel } from "@/components/app/panels";

interface OnboardingModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConnected?: () => void;
}

export function OnboardingModal({ isOpen, onClose, onConnected }: OnboardingModalProps) {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [config, setConfig] = useState<SensorsConfigResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [subnetsInput, setSubnetsInput] = useState<string>("192.168.10.0/24");
  const [environmentType, setEnvironmentType] = useState<string>("enterprise");
  const [isCopied, setIsCopied] = useState<boolean>(false);
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

    const interval = setInterval(loadConfig, 3000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [isOpen, onConnected]);

  if (!isOpen) return null;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
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

  const runCommand = `python edge_sensor/run_sensor.py --mode tap --interface eth0 --upstream ${upstreamUrl} --api-key ${config?.sensorApiKey || "av_sec_..."}`;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-void-950/80 p-4 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-2xl rounded-xl border border-fog-deep bg-void-900 shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-fog-deep/60 px-6 py-4 bg-void-800/40">
          <div className="flex items-center gap-2.5">
            <div className="flex size-8 items-center justify-center rounded-lg bg-teal/15 text-teal border border-teal/30">
              <Zap className="size-4" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-paper">
                Connect Edge Sensor & Infrastructure Setup
              </h2>
              <p className="text-xs text-fog">
                Transition from demonstration benchmark replay to live neural forecasting
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-fog hover:bg-void-700 hover:text-paper transition-colors"
          >
            <X className="size-4" />
          </button>
        </div>

        {/* Multi-Step Nav */}
        <div className="grid grid-cols-3 border-b border-fog-deep/40 text-center text-xs font-medium">
          <button
            onClick={() => setStep(1)}
            className={`py-3 transition-colors flex items-center justify-center gap-1.5 ${
              step === 1 ? "border-b-2 border-teal text-teal font-semibold bg-void-800/30" : "text-fog hover:text-paper"
            }`}
          >
            <Network className="size-3.5" /> 1. Environment Scope
          </button>
          <button
            onClick={() => setStep(2)}
            className={`py-3 transition-colors flex items-center justify-center gap-1.5 ${
              step === 2 ? "border-b-2 border-teal text-teal font-semibold bg-void-800/30" : "text-fog hover:text-paper"
            }`}
          >
            <Terminal className="size-3.5" /> 2. Sensor Deployment
          </button>
          <button
            onClick={() => setStep(3)}
            className={`py-3 transition-colors flex items-center justify-center gap-1.5 ${
              step === 3 ? "border-b-2 border-teal text-teal font-semibold bg-void-800/30" : "text-fog hover:text-paper"
            }`}
          >
            <Activity className="size-3.5" /> 3. Live Verification
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6">
          {/* STEP 1 */}
          {step === 1 && (
            <form onSubmit={handleSaveStep1} className="space-y-4">
              <div className="rounded-lg border border-amber/30 bg-amber/10 p-3 text-xs text-amber-light">
                <span className="font-semibold">Notice:</span> You are currently viewing simulated benchmark data (CSE-CIC-IDS2018). Tell us about your network environment so the Cyber World Model can accurately contextualize your live ingress flows.
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-fog mb-1.5">
                  Deployment Environment
                </label>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                  {[
                    { id: "enterprise", label: "Enterprise Core", desc: "SPAN / Mirror Tap" },
                    { id: "cloud_vpc", label: "Cloud VPC", desc: "Traffic Mirroring" },
                    { id: "homelab", label: "Homelab / Office", desc: "Local Interface Tap" },
                    { id: "evaluation", label: "Interactive Gateway", desc: "Mobile / Device Web Tap" },
                  ].map((env) => (
                    <button
                      type="button"
                      key={env.id}
                      onClick={() => setEnvironmentType(env.id)}
                      className={`flex flex-col items-start p-3 rounded-lg border text-left transition-all ${
                        environmentType === env.id
                          ? "border-teal bg-teal/10 text-paper"
                          : "border-fog-deep/60 bg-void-800/50 text-fog hover:border-fog hover:text-paper"
                      }`}
                    >
                      <span className="text-xs font-medium">{env.label}</span>
                      <span className="text-[11px] text-fog mt-0.5">{env.desc}</span>
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-fog mb-1.5">
                  Primary Monitored Subnets (CIDR notation)
                </label>
                <input
                  type="text"
                  value={subnetsInput}
                  onChange={(e) => setSubnetsInput(e.target.value)}
                  placeholder="e.g. 192.168.10.0/24, 10.0.0.0/16"
                  className="w-full rounded-lg border border-fog-deep bg-void-800 px-3.5 py-2 text-sm text-paper focus:border-teal focus:outline-none mono"
                  required
                />
                <p className="text-[11px] text-fog mt-1">
                  Comma-separated CIDRs. Traffic between these subnets will be correlated as internal lateral movement vs external perimeter threats.
                </p>
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-fog-deep/40">
                <button
                  type="button"
                  onClick={onClose}
                  className="text-xs text-fog hover:text-paper transition-colors"
                >
                  Skip for now (Stay in Demo Mode)
                </button>
                <ActionButton type="submit" disabled={isSaving}>
                  {isSaving ? "Saving..." : "Save & Continue to Sensor Setup →"}
                </ActionButton>
              </div>
            </form>
          )}

          {/* STEP 2 */}
          {step === 2 && (
            <div className="space-y-4">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-xs font-semibold uppercase tracking-wider text-fog">
                    Your Organization Sensor Secret Key
                  </label>
                  <button
                    onClick={handleRegenerateKey}
                    className="text-[11px] text-amber hover:underline flex items-center gap-1"
                  >
                    <RefreshCw className="size-3" /> Rotate Key
                  </button>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="password"
                    readOnly
                    value={config?.sensorApiKey || "Generating key..."}
                    className="flex-1 rounded-lg border border-fog-deep bg-void-800 px-3.5 py-2 text-xs text-paper mono"
                  />
                  <ActionButton
                    variant="ghost"
                    onClick={() => config?.sensorApiKey && handleCopy(config.sensorApiKey)}
                    className="shrink-0 flex items-center gap-1.5 text-xs"
                  >
                    {isCopied ? <Check className="size-3.5 text-teal" /> : <Copy className="size-3.5" />}
                    {isCopied ? "Copied" : "Copy"}
                  </ActionButton>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-fog mb-1.5">
                  Run Edge Sensor via CLI (Passive SPAN / Mirror Mode)
                </label>
                <div className="relative rounded-lg border border-fog-deep bg-void-950 p-3 font-mono text-xs text-teal-light overflow-x-auto">
                  <code>{runCommand}</code>
                  <button
                    onClick={() => handleCopy(runCommand)}
                    className="absolute top-2 right-2 rounded bg-void-800 p-1 text-fog hover:text-paper"
                    title="Copy command"
                  >
                    <Copy className="size-3.5" />
                  </button>
                </div>
                <p className="text-[11px] text-fog mt-1.5">
                  The sensor calculates 54-dimensional physical features every 2.0s, runs local SparseRSSM + TFCNet neural inference, and streams telemetry directly to your dashboard.
                </p>
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-fog-deep/40">
                <button
                  type="button"
                  onClick={() => setStep(1)}
                  className="text-xs text-fog hover:text-paper transition-colors"
                >
                  ← Back to Scope
                </button>
                <ActionButton onClick={() => setStep(3)}>
                  I have started the sensor → Check Status
                </ActionButton>
              </div>
            </div>
          )}

          {/* STEP 3 */}
          {step === 3 && (
            <div className="space-y-5 text-center py-4">
              {config?.isLive ? (
                <div className="space-y-3 animate-fade-in">
                  <div className="mx-auto flex size-14 items-center justify-center rounded-full bg-teal/20 text-teal border border-teal/40">
                    <Check className="size-7" />
                  </div>
                  <h3 className="text-base font-semibold text-paper">
                    Live Infrastructure Sensor Active!
                  </h3>
                  <p className="text-xs text-fog max-w-md mx-auto">
                    Aegis Vantage is receiving live 2.0-second telemetry from{" "}
                    <span className="font-semibold text-teal">
                      {config.activeSensorsCount} sensor{config.activeSensorsCount === 1 ? "" : "s"}
                    </span>
                    . Your dashboard graph and alerts have automatically switched to real-time predictive monitoring.
                  </p>
                  <div className="pt-2">
                    <ActionButton
                      onClick={() => {
                        onClose();
                        if (onConnected) onConnected();
                      }}
                      className="px-6 py-2.5 text-sm"
                    >
                      Open Live Dashboard
                    </ActionButton>
                  </div>
                </div>
              ) : (
                <div className="space-y-3">
                  <div className="mx-auto flex size-12 items-center justify-center rounded-full bg-amber/15 text-amber border border-amber/30 animate-pulse">
                    <Activity className="size-6 animate-spin" />
                  </div>
                  <h3 className="text-sm font-semibold text-paper">
                    Listening for Edge Sensor Telemetry...
                  </h3>
                  <p className="text-xs text-fog max-w-md mx-auto">
                    Ensure the edge sensor is running and attached to an interface or running in gateway mode. Once the first 2.0s telemetry packet arrives at{" "}
                    <span className="mono text-teal-light">{upstreamUrl}</span>, this indicator will turn green.
                  </p>
                  <div className="flex items-center justify-center gap-3 pt-2">
                    <ActionButton variant="ghost" onClick={() => setStep(2)}>
                      ← Check Command & API Key
                    </ActionButton>
                    <button
                      onClick={onClose}
                      className="text-xs text-fog hover:text-paper transition-colors px-3 py-2"
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
