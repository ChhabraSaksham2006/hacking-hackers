import { useState, useRef, useEffect } from "react";
import {
  Terminal,
  X,
  Send,
  Maximize2,
  Minimize2,
  Trash2,
  Cpu,
  ShieldAlert,
  Sparkles,
  Copy,
  Check,
  ChevronRight,
  ExternalLink,
} from "lucide-react";
import { cn } from "../../lib/utils";
import { useChatQuery, useSuggestedQueries, type ChatQueryResponse } from "../../hooks/useApi";

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  references?: string[] | undefined;
  timestamp: string;
  provider?: string | undefined;
}

// ── Simple Markdown Renderer for Cyber Console ─────────────────

function MarkdownContent({ content }: { content: string }) {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const handleCopy = (code: string, idx: number) => {
    navigator.clipboard.writeText(code);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const lines = content.split("\n");
  const elements: React.ReactNode[] = [];
  let inCodeBlock = false;
  let codeBlockContent: string[] = [];
  let codeBlockLang = "";
  let blockIndex = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    if (line.startsWith("```")) {
      if (inCodeBlock) {
        // End code block
        const fullCode = codeBlockContent.join("\n");
        const currIndex = blockIndex++;
        elements.push(
          <div key={`code-${i}`} className="relative my-2.5 rounded-md border border-fog-deep/60 bg-void-950 p-3 font-mono text-[12px]">
            <div className="mb-2 flex items-center justify-between border-b border-fog-deep/40 pb-1 text-[10px] text-fog">
              <span>{codeBlockLang || "bash"}</span>
              <button
                type="button"
                onClick={() => handleCopy(fullCode, currIndex)}
                className="flex items-center gap-1 hover:text-paper"
              >
                {copiedIndex === currIndex ? (
                  <>
                    <Check className="size-3 text-teal" />
                    <span className="text-teal">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="size-3" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <pre className="overflow-x-auto text-paper">{fullCode}</pre>
          </div>
        );
        inCodeBlock = false;
        codeBlockContent = [];
      } else {
        inCodeBlock = true;
        codeBlockLang = line.replace("```", "").trim();
      }
      continue;
    }

    if (inCodeBlock) {
      codeBlockContent.push(line);
      continue;
    }

    // Headers
    if (line.startsWith("### ")) {
      elements.push(
        <h4 key={`h4-${i}`} className="mt-2.5 mb-1.5 font-mono text-[13px] font-bold text-teal tracking-wide">
          {line.replace("### ", "")}
        </h4>
      );
      continue;
    }

    if (line.startsWith("#### ")) {
      elements.push(
        <h5 key={`h5-${i}`} className="mt-2 mb-1 font-mono text-[12px] font-semibold text-paper/90 uppercase tracking-wider">
          {line.replace("#### ", "")}
        </h5>
      );
      continue;
    }

    // Bullet points & checkboxes
    if (line.startsWith("- [ ] ") || line.startsWith("- [x] ")) {
      const isChecked = line.startsWith("- [x] ");
      const text = line.replace(/- \[[ x]\] /, "");
      elements.push(
        <div key={`cb-${i}`} className="my-1 flex items-start gap-2 text-[12.5px] leading-relaxed text-paper/90">
          <span className={cn("mt-1 size-3 rounded border flex items-center justify-center shrink-0", isChecked ? "bg-teal border-teal text-void-950" : "border-fog-deep")}>
            {isChecked && <Check className="size-2.5" />}
          </span>
          <span>{renderInlineStyles(text)}</span>
        </div>
      );
      continue;
    }

    // Markdown Table handling
    if (line.trim().startsWith("|") && line.trim().endsWith("|")) {
      const tableLines: string[] = [];
      while (i < lines.length && lines[i]!.trim().startsWith("|") && lines[i]!.trim().endsWith("|")) {
        tableLines.push(lines[i]!.trim());
        i++;
      }
      i--; // adjust loop increment

      if (tableLines.length >= 2) {
        const headerRow = tableLines[0]!
          .split("|")
          .filter((_, idx, arr) => idx > 0 && idx < arr.length - 1)
          .map((c) => c.trim());
        
        const isDivider = (str: string) => /^:?-+:?$/.test(str.trim());
        const hasDivider = tableLines[1] && tableLines[1].split("|").some(isDivider);
        const dataStartIndex = hasDivider ? 2 : 1;

        const bodyRows = tableLines.slice(dataStartIndex).map((row) =>
          row
            .split("|")
            .filter((_, idx, arr) => idx > 0 && idx < arr.length - 1)
            .map((c) => c.trim())
        );

        elements.push(
          <div key={`tbl-${i}`} className="my-2.5 overflow-x-auto rounded border border-fog-deep/60 bg-void-950/70">
            <table className="w-full text-left font-mono text-[11px] text-paper">
              <thead>
                <tr className="border-b border-fog-deep/50 bg-void-900/80 text-teal">
                  {headerRow.map((h, colIdx) => (
                    <th key={`th-${colIdx}`} className="px-2.5 py-1.5 font-semibold">
                      {renderInlineStyles(h)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-fog-deep/30">
                {bodyRows.map((row, rIdx) => (
                  <tr key={`tr-${rIdx}`} className="hover:bg-void-800/40">
                    {row.map((cell, cIdx) => (
                      <td key={`td-${cIdx}`} className="px-2.5 py-1.5 text-paper/85">
                        {renderInlineStyles(cell)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
        continue;
      }
    }

    if (line.startsWith("- ") || line.startsWith("* ")) {
      elements.push(
        <div key={`bullet-${i}`} className="my-1 flex items-start gap-2 text-[12.5px] leading-relaxed text-paper/90 pl-1">
          <span className="mt-1.5 size-1.5 rounded-full bg-teal shrink-0" />
          <span>{renderInlineStyles(line.slice(2))}</span>
        </div>
      );
      continue;
    }

    // Numbered lists
    const numMatch = line.match(/^(\d+)\.\s+(.*)/);
    if (numMatch) {
      elements.push(
        <div key={`num-${i}`} className="my-1 flex items-start gap-2 text-[12.5px] leading-relaxed text-paper/90 pl-1">
          <span className="mono shrink-0 font-medium text-teal">{numMatch[1]}.</span>
          <span>{renderInlineStyles(numMatch[2]!)}</span>
        </div>
      );
      continue;
    }

    // Empty line
    if (line.trim() === "") {
      elements.push(<div key={`sp-${i}`} className="h-1.5" />);
      continue;
    }

    // Standard paragraph
    elements.push(
      <p key={`p-${i}`} className="my-1 text-[12.5px] leading-relaxed text-paper/90">
        {renderInlineStyles(line)}
      </p>
    );
  }

  return <div className="space-y-0.5">{elements}</div>;
}

function renderInlineStyles(text: string): React.ReactNode {
  // Process bold (**text**) and code (`code`)
  const parts: React.ReactNode[] = [];
  const regex = /(\*\*.*?\*\*|`.*?`|\*.*?\*)/g;
  let lastIdx = 0;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIdx) {
      parts.push(text.slice(lastIdx, match.index));
    }
    const token = match[0];
    if (token.startsWith("**") && token.endsWith("**")) {
      parts.push(
        <strong key={match.index} className="font-semibold text-paper">
          {token.slice(2, -2)}
        </strong>
      );
    } else if (token.startsWith("`") && token.endsWith("`")) {
      parts.push(
        <code key={match.index} className="rounded bg-void-950 px-1.5 py-0.5 font-mono text-[11px] text-teal border border-fog-deep/40">
          {token.slice(1, -1)}
        </code>
      );
    } else if (token.startsWith("*") && token.endsWith("*")) {
      parts.push(
        <em key={match.index} className="italic text-fog">
          {token.slice(1, -1)}
        </em>
      );
    }
    lastIdx = regex.lastIndex;
  }

  if (lastIdx < text.length) {
    parts.push(text.slice(lastIdx));
  }

  return parts.length > 0 ? parts : text;
}

// ── Main Console Panel Component ──────────────────────────────

export function ConsolePanel() {
  const [open, setOpen] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [query, setQuery] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const { data: suggestedData } = useSuggestedQueries();
  const chatMutation = useChatQuery();

  const liveState = suggestedData?.liveState;
  const isCritical = liveState?.riskLevel === "critical";
  const isWatch = liveState?.riskLevel === "watch";

  const [messages, setMessages] = useState<ChatMessage[]>(() => [
    {
      id: "initial-welcome",
      role: "assistant",
      content: `### Aegis Vantage Telemetry Copilot Initialized

Ground-truth stream connected to **SparseRSSM World Model** and **MITRE ATT&CK Engine**.

- **Teleprompter:** Synchronized with real-time CSE-CIC-IDS2018 Infiltration episode.
- **Provider Cascade:** **Groq API** (\`openai/gpt-oss-20b\` & \`120b\`) $\\rightarrow$ **OpenRouter** (\`nemotron-3.5-lightning:free\`) $\\rightarrow$ **Offline Cyber Engine**.

Inquire below about current attack probability, model confidence, flow/packet feature changes, host diagnostics, or containment playbooks.`,
      references: ["Live Stream", "192.168.10.44", "T1021.002", "Port 445"],
      timestamp: "Just now",
      provider: "groq: gpt-oss-20b",
    },
  ]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    if (open) {
      scrollToBottom();
      setTimeout(() => inputRef.current?.focus(), 150);
    }
  }, [open, messages]);

  const handleSend = (textToSend?: string) => {
    const text = (textToSend ?? query).trim();
    if (!text || chatMutation.isPending) return;

    const userMsg: ChatMessage = {
      id: `usr-${Date.now()}`,
      role: "user",
      content: text,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setQuery("");

    chatMutation.mutate(
      {
        query: text,
        live: true, // Always fetch the current real-time telemetry state!
      },
      {
        onSuccess: (data: ChatQueryResponse) => {
          const assistantMsg: ChatMessage = {
            id: `ast-${Date.now()}`,
            role: "assistant",
            content: data.answer,
            references: data.references,
            timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
            provider: data.context.provider,
          };
          setMessages((prev) => [...prev, assistantMsg]);
        },
        onError: (err: any) => {
          const errorMsg: ChatMessage = {
            id: `err-${Date.now()}`,
            role: "assistant",
            content: `**Query Error:** Unable to reach telemetry engine (${err?.message || "Unknown error"}). Please retry or check server connection.`,
            timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          };
          setMessages((prev) => [...prev, errorMsg]);
        },
      }
    );
  };

  const handleClearHistory = () => {
    setMessages([
      {
        id: `clear-${Date.now()}`,
        role: "assistant",
        content: `Telemetry console session cleared. Ask about any active host, SHAP feature attributions, or MITRE playbooks.`,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      },
    ]);
  };

  const handleReferenceClick = (ref: string) => {
    if (ref.includes("192.168.") || ref.includes("203.0.") || ref.includes("corp-")) {
      handleSend(`What is the forensic status and traffic profile of host ${ref}?`);
    } else if (ref.startsWith("T10") || ref.startsWith("T11") || ref.startsWith("M10")) {
      handleSend(`What are the detection rules and containment playbooks for MITRE ${ref}?`);
    } else if (ref.toLowerCase().includes("shap") || ref.toLowerCase().includes("feature") || ref.includes("entropy")) {
      handleSend(`Explain top SHAP drivers and anomaly features.`);
    } else if (ref.includes("Port")) {
      handleSend(`Show active traffic and risks on ${ref}.`);
    } else {
      setQuery(`Diagnostic for ${ref}`);
      inputRef.current?.focus();
    }
  };

  // Render Launcher Button when closed
  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className={cn(
          "fixed right-6 bottom-6 z-40 flex items-center gap-2.5 rounded-lg border px-3.5 py-2.5 text-[13px] font-medium transition-all shadow-xl backdrop-blur-md",
          isCritical
            ? "border-crimson/50 bg-void-800/90 text-paper hover:bg-void-700 hover:border-crimson"
            : isWatch
            ? "border-amber/50 bg-void-800/90 text-paper hover:bg-void-700 hover:border-amber"
            : "border-fog-deep bg-void-800/90 text-paper hover:bg-void-700 hover:border-teal/50"
        )}
      >
        <span className="relative flex size-2">
          {isCritical ? (
            <>
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-crimson opacity-75" />
              <span className="relative inline-flex size-2 rounded-full bg-crimson" />
            </>
          ) : isWatch ? (
            <>
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-amber opacity-75" />
              <span className="relative inline-flex size-2 rounded-full bg-amber" />
            </>
          ) : (
            <span className="relative inline-flex size-2 rounded-full bg-teal" />
          )}
        </span>

        <Terminal className="size-4 text-teal" strokeWidth={1.75} />
        <span>Query Telemetry</span>

        <span className="mono rounded bg-void-950 px-1.5 py-0.5 text-[10px] text-fog border border-fog-deep/40">
          AI Copilot
        </span>
      </button>
    );
  }

  const suggestedList = suggestedData?.suggestedQueries || [
    "Why is 192.168.10.44 flagged for lateral movement?",
    "What is the recommended isolation playbook for port 445?",
    "Explain top SHAP drivers for current threat probability",
    "What is the forecasted breach lead time?",
  ];

  return (
    <aside
      className={cn(
        "fixed right-6 bottom-6 z-40 flex flex-col rounded-xl border border-fog-deep/80 bg-void-900/95 shadow-2xl backdrop-blur-xl transition-all duration-200 overflow-hidden",
        expanded
          ? "w-[620px] h-[720px] max-h-[90vh]"
          : "w-[440px] md:w-[480px] h-[580px] max-h-[85vh]"
      )}
    >
      {/* ── Console Header ────────────────────────────────────── */}
      <div className="flex items-center justify-between border-b border-fog-deep/60 bg-void-950/80 px-4 py-3">
        <div className="flex items-center gap-2.5">
          <div className="flex size-7 items-center justify-center rounded-md border border-teal/30 bg-teal/10 text-teal">
            <Terminal className="size-4" strokeWidth={1.75} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[13px] font-semibold text-paper">Telemetry Copilot</span>
              <span className="mono rounded bg-void-800 px-1.5 py-0.2 text-[10px] font-medium text-teal border border-teal/20">
                RAG v4.2
              </span>
            </div>
            <p className="text-[11px] text-fog">
              {liveState
                ? `Window #${liveState.windowIndex} · ${liveState.stage} · ${(liveState.probability * 100).toFixed(0)}% Risk`
                : "Active Stream · CSE-CIC-IDS2018 Infiltration"}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1.5 text-fog">
          <button
            onClick={handleClearHistory}
            title="Clear console transcript"
            className="rounded p-1 hover:bg-void-800 hover:text-paper transition-colors"
          >
            <Trash2 className="size-3.5" />
          </button>
          <button
            onClick={() => setExpanded(!expanded)}
            title={expanded ? "Restore panel size" : "Expand panel"}
            className="rounded p-1 hover:bg-void-800 hover:text-paper transition-colors"
          >
            {expanded ? <Minimize2 className="size-3.5" /> : <Maximize2 className="size-3.5" />}
          </button>
          <button
            onClick={() => setOpen(false)}
            title="Close console"
            className="rounded p-1 hover:bg-void-800 hover:text-paper transition-colors"
          >
            <X className="size-4" />
          </button>
        </div>
      </div>

      {/* ── Subheader / Telemetry Teleprompter ────────────────── */}
      <div className="flex items-center justify-between border-b border-fog-deep/40 bg-void-950/40 px-4 py-1.5 text-[11px] text-fog">
        <div className="flex items-center gap-2">
          <span
            className={cn(
              "size-2 rounded-full",
              isCritical ? "bg-crimson animate-pulse" : isWatch ? "bg-amber animate-pulse" : "bg-teal"
            )}
          />
          <span className="font-mono">
            {liveState ? `${liveState.stage.toUpperCase()} | P=${(liveState.probability * 100).toFixed(1)}%` : "BENIGN BASELINE"}
          </span>
        </div>
        <div className="flex items-center gap-1 mono text-[10px] text-fog/80">
          <Cpu className="size-3 text-teal" />
          <span>SparseRSSM + TFCNet</span>
        </div>
      </div>

      {/* ── Message Transcript ────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto px-4 py-3.5 space-y-4">
        {messages.map((m) => (
          <div key={m.id} className={cn("space-y-1.5", m.role === "user" ? "pl-4" : "pr-2")}>
            {/* Message header */}
            <div className="flex items-center justify-between text-[10.5px] text-fog font-mono">
              <div className="flex items-center gap-1.5">
                {m.role === "user" ? (
                  <span className="text-teal font-semibold">&gt; analyst</span>
                ) : (
                  <span className="flex items-center gap-1 text-paper/80 font-medium">
                    <Sparkles className="size-3 text-teal" />
                    <span>aegis-copilot</span>
                    {m.provider && (
                      <span className="text-[9.5px] text-fog/70">
                        ({m.provider.startsWith("groq:openai/")
                          ? `groq: ${m.provider.replace("groq:openai/", "")}`
                          : m.provider.startsWith("openrouter:nvidia/")
                          ? `openrouter: ${m.provider.replace("openrouter:nvidia/", "").replace(":free", "")}`
                          : m.provider === "cyber_causality_engine"
                          ? "offline-engine"
                          : m.provider})
                      </span>
                    )}
                  </span>
                )}
              </div>
              <span>{m.timestamp}</span>
            </div>

            {/* Message body */}
            {m.role === "user" ? (
              <div className="rounded-lg border border-teal/30 bg-teal/5 px-3.5 py-2.5 font-mono text-[13px] text-paper">
                {m.content}
              </div>
            ) : (
              <div className="rounded-lg border border-fog-deep/50 bg-void-800/80 px-3.5 py-3 text-paper shadow-sm">
                <MarkdownContent content={m.content} />

                {/* References Chips */}
                {m.references && m.references.length > 0 && (
                  <div className="mt-3 pt-2.5 border-t border-fog-deep/40 flex flex-wrap items-center gap-1.5">
                    <span className="text-[10.5px] text-fog mono mr-1">Entities:</span>
                    {m.references.map((ref) => (
                      <button
                        key={ref}
                        type="button"
                        onClick={() => handleReferenceClick(ref)}
                        className="inline-flex items-center gap-1 rounded bg-void-950 px-2 py-0.5 font-mono text-[10.5px] text-teal border border-teal/30 hover:bg-teal/10 hover:border-teal transition-all"
                        title={`Query entity ${ref}`}
                      >
                        <span>{ref}</span>
                        <ChevronRight className="size-2.5 opacity-60" />
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}

        {/* Loading typing indicator */}
        {chatMutation.isPending && (
          <div className="space-y-1 pr-2">
            <div className="flex items-center gap-1.5 text-[10.5px] text-fog font-mono">
              <Sparkles className="size-3 text-teal animate-spin" />
              <span>aegis-copilot thinking...</span>
            </div>
            <div className="flex items-center gap-2 rounded-lg border border-fog-deep/50 bg-void-800/80 px-4 py-3">
              <span className="size-1.5 rounded-full bg-teal animate-bounce" />
              <span className="size-1.5 rounded-full bg-teal animate-bounce [animation-delay:0.15s]" />
              <span className="size-1.5 rounded-full bg-teal animate-bounce [animation-delay:0.3s]" />
              <span className="mono text-[11px] text-fog ml-2">Grounding response in real-time telemetry...</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* ── Suggested Query Chips ─────────────────────────────── */}
      <div className="border-t border-fog-deep/50 bg-void-950/60 px-3.5 py-2">
        <div className="mb-1 flex items-center justify-between text-[10px] uppercase font-mono tracking-wider text-fog">
          <span>Suggested queries</span>
          <span className="text-[9px] text-fog/60">click to execute</span>
        </div>
        <div className="flex flex-wrap gap-1.5 max-h-16 overflow-y-auto pr-1">
          {suggestedList.slice(0, 3).map((sq) => (
            <button
              key={sq}
              type="button"
              disabled={chatMutation.isPending}
              onClick={() => handleSend(sq)}
              className="rounded border border-fog-deep/60 bg-void-800/70 px-2.5 py-1 text-left text-[11px] text-paper/85 hover:border-teal/50 hover:bg-void-700 hover:text-teal transition-all disabled:opacity-50"
            >
              {sq}
            </button>
          ))}
        </div>
      </div>

      {/* ── Input Box ─────────────────────────────────────────── */}
      <div className="border-t border-fog-deep/60 bg-void-950 px-4 py-3">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex items-center gap-2.5"
        >
          <span className="mono text-[14px] font-bold text-teal select-none">&gt;</span>
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            disabled={chatMutation.isPending}
            placeholder="Ask about host 192.168.10.44, T1021.002, or containment..."
            className="mono w-full bg-transparent text-[13px] text-paper outline-none placeholder:text-fog-deep disabled:opacity-50"
          />
          <button
            type="submit"
            disabled={!query.trim() || chatMutation.isPending}
            className="flex size-8 shrink-0 items-center justify-center rounded-md bg-teal text-void-950 transition-all hover:bg-teal/90 disabled:opacity-40 disabled:cursor-not-allowed"
            title="Send query (Enter)"
          >
            <Send className="size-3.5" />
          </button>
        </form>
        <div className="mt-1.5 flex items-center justify-between text-[10px] text-fog mono">
          <span>Grounded RAG · Zero-key offline engine enabled</span>
          <span>Esc to minimize</span>
        </div>
      </div>
    </aside>
  );
}
