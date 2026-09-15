import { useMemo } from "react";
import katex from "katex";

interface MathFormulaProps {
  math: string;
  displayMode?: boolean;
  className?: string;
}

export function MathFormula({ math, displayMode = true, className = "" }: MathFormulaProps) {
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

  return (
    <span
      className={`katex-render-container inline-block max-w-full overflow-x-auto ${className}`}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}
