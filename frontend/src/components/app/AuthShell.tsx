import type { ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { graphNodes } from "./charts";

export function AuthShell({
  title,
  note,
  children,
  footer,
}: {
  title: string;
  note?: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-void-900 px-4">
      <svg
        viewBox="0 0 780 340"
        className="pointer-events-none absolute inset-0 h-full w-full opacity-[0.16]"
        aria-hidden="true"
        preserveAspectRatio="xMidYMid slice"
      >
        {graphNodes.map((a, i) =>
          graphNodes.slice(i + 1, i + 3).map((b) => (
            <line
              key={a.id + b.id}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              stroke="var(--signal-teal)"
              strokeWidth="0.6"
            />
          )),
        )}
        {graphNodes.map((n, i) => (
          <circle
            key={n.id}
            cx={n.x}
            cy={n.y}
            r={5}
            fill="var(--signal-teal)"
            className="pulse-node"
            style={{ animationDelay: `${i * 0.35}s` }}
          />
        ))}
      </svg>

      <div className="relative w-full max-w-[620px]">
        <Link to="/" className="mb-6 flex items-center gap-3">
          <span className="size-[18px] rotate-45 rounded-[4px] border-2 border-teal" />
          <span className="font-display text-[15px] font-semibold">
            Flow दृष्टि
          </span>
        </Link>
        <div className="flat p-8">
          <h1 className="font-display text-[28px] font-semibold">{title}</h1>
          {note ? <p className="mt-2 text-[15px] text-fog">{note}</p> : null}
          <div className="mt-7">{children}</div>
        </div>
        {footer ? (
          <div className="mt-4 text-[13px] text-fog">{footer}</div>
        ) : null}
      </div>
    </div>
  );
}

import type { InputHTMLAttributes } from "react";

export function Field({
  label,
  hint,
  ...props
}: {
  label: string;
  hint?: string;
} & InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="block">
      <span className="text-[13px] font-medium">{label}</span>
      <input
        {...props}
        className="mt-1.5 w-full rounded-md border border-fog-deep bg-void-700 px-3 py-2.5 text-[15px] outline-none placeholder:text-fog-deep focus:border-teal"
      />
      {hint ? <span className="mt-1 block text-[12px] text-fog">{hint}</span> : null}
    </label>
  );
}
