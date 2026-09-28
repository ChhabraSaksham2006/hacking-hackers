import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { stateColorVar, type RiskState } from "@/lib/telemetry";

export function PanelHeader({
  title,
  control,
  className,
}: {
  title: string;
  control?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-5 sm:py-4",
        className,
      )}
    >
      <h2 className="font-display text-[18px] sm:text-[20px] font-medium text-paper">{title}</h2>
      {control ? <div className="flex flex-wrap items-center gap-2">{control}</div> : null}
    </div>
  );
}

/** Tier 2 — the single dominant live surface on a page. */
export function HeroPanel({
  title,
  control,
  state = "normal",
  children,
  className,
  bodyClassName,
}: {
  title?: string;
  control?: ReactNode;
  state?: RiskState;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section
      className={cn("glass-hero overflow-hidden", className)}
      style={{ ["--state-color" as string]: stateColorVar[state] }}
    >
      {title ? (
        <>
          <PanelHeader title={title} control={control} />
          <div className="h-px bg-[var(--glass-border)]" />
        </>
      ) : null}
      <div className={cn("p-3.5 sm:p-5", bodyClassName)}>{children}</div>
    </section>
  );
}

/** Tier 1 — secondary live widget. */
export function GlassPanel({
  title,
  control,
  children,
  className,
}: {
  title?: string;
  control?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("glass overflow-hidden", className)}>
      {title ? (
        <>
          <PanelHeader title={title} control={control} className="py-2.5 sm:py-3.5" />
          <div className="h-px bg-[var(--glass-border)]" />
        </>
      ) : null}
      <div className="p-3.5 sm:p-5">{children}</div>
    </section>
  );
}

/** Tier 3 — dense, read-heavy content. */
export function FlatPanel({
  title,
  control,
  children,
  className,
  bodyClassName,
}: {
  title?: string;
  control?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={cn("flat overflow-hidden", className)}>
      {title ? (
        <>
          <PanelHeader title={title} control={control} className="py-2.5 sm:py-3.5" />
          <div className="h-px bg-fog-deep/60" />
        </>
      ) : null}
      <div className={cn("p-3.5 sm:p-5", bodyClassName)}>{children}</div>
    </section>
  );
}

export function RiskBadge({
  state,
  label,
  className,
}: {
  state: RiskState;
  label?: string;
  className?: string;
}) {
  const text =
    label ??
    { normal: "Normal", watch: "Watch", critical: "Critical" }[state];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[12px] font-medium whitespace-nowrap",
        className,
      )}
      style={{
        color: stateColorVar[state],
        borderColor: `color-mix(in oklab, ${stateColorVar[state]} 40%, transparent)`,
        background: `color-mix(in oklab, ${stateColorVar[state]} 12%, transparent)`,
      }}
    >
      <span
        className="size-1.5 rounded-full shrink-0"
        style={{ background: stateColorVar[state] }}
      />
      {text}
    </span>
  );
}

export function PageTitle({
  title,
  note,
  actions,
}: {
  title: string;
  note?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-4 sm:mb-6 flex flex-wrap items-end justify-between gap-3 sm:gap-4">
      <div className="min-w-0">
        <h1 className="font-display text-[22px] sm:text-[28px] font-semibold text-paper leading-tight">{title}</h1>
        {note ? (
          <p className="mt-1 max-w-[70ch] text-[13px] sm:text-[15px] text-fog leading-relaxed">{note}</p>
        ) : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function ActionButton({
  children,
  variant = "primary",
  className,
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "ghost" | "quiet";
}) {
  return (
    <button
      {...rest}
      className={cn(
        "rounded-md px-3.5 py-2 text-[13px] font-medium transition-colors",
        variant === "primary" &&
          "bg-teal text-void-900 hover:bg-teal/85",
        variant === "ghost" &&
          "border border-fog-deep text-paper hover:bg-void-700",
        variant === "quiet" && "text-fog hover:text-paper",
        className,
      )}
    >
      {children}
    </button>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <p className="max-w-[70ch] py-8 text-[15px] text-fog">{message}</p>
  );
}
