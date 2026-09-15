import { useMemo } from "react";
import katex from "katex";

interface MathFormulaProps {
  math: string;
  displayMode?: boolean;
  className?: string;
}

export function MathFormula({ math, displayMode = false, className = "" }: MathFormulaProps) {
  const html = useMemo(() => {
    try {
      return katex.renderToString(math, {
        displayMode,
        throwOnError: false,
        strict: false,
      });
    } catch (e) {
      console.error("KaTeX render error:", e);
      return `<code>${math}</code>`;
    }
  }, [math, displayMode]);

  if (displayMode) {
    return (
      <div
        className={`katex-block-container block w-full overflow-x-auto py-2 scrollbar-none [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden text-center ${className}`}
        dangerouslySetInnerHTML={{ __html: html }}
      />
    );
  }

  return (
    <span
      className={`katex-inline-container inline align-baseline whitespace-nowrap overflow-visible ${className}`}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}
