import { useEffect, useRef } from "react";

interface BackgroundDotEffectProps {
  dotColor?: string;
  glowColor?: string;
  spacing?: number;
  dotSize?: number;
}

export function BackgroundDotEffect({
  dotColor = "rgba(100, 116, 139, 0.22)",
  glowColor = "rgba(45, 212, 191, 0.75)",
  spacing = 28,
  dotSize = 1.3,
}: BackgroundDotEffectProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    // Mouse coordinates in window space
    let mouse = {
      x: -1000,
      y: -1000,
      targetX: -1000,
      targetY: -1000,
      radius: 170,
    };

    const handleMouseMove = (e: MouseEvent) => {
      mouse.targetX = e.clientX;
      mouse.targetY = e.clientY;
    };

    const handleMouseLeave = () => {
      mouse.targetX = -1000;
      mouse.targetY = -1000;
    };

    window.addEventListener("mousemove", handleMouseMove, { passive: true });
    window.addEventListener("mouseleave", handleMouseLeave, { passive: true });

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    window.addEventListener("resize", handleResize, { passive: true });

    let time = 0;

    const render = () => {
      time += 0.015;

      // Smooth mouse lerp
      mouse.x += (mouse.targetX - mouse.x) * 0.15;
      mouse.y += (mouse.targetY - mouse.y) * 0.15;

      ctx.clearRect(0, 0, width, height);

      const cols = Math.ceil(width / spacing) + 1;
      const rows = Math.ceil(height / spacing) + 1;

      for (let i = 0; i < cols; i++) {
        for (let j = 0; j < rows; j++) {
          const x = i * spacing;
          const y = j * spacing;

          // Wave pulse offset
          const wave = Math.sin(time + (i + j) * 0.18) * 0.5 + 0.5;

          // Mouse proximity calculation
          const dx = x - mouse.x;
          const dy = y - mouse.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          ctx.beginPath();

          if (dist < mouse.radius) {
            // Highlighting dots near cursor
            const proximity = 1 - dist / mouse.radius;
            const currentSize = dotSize + proximity * 2.2;
            const alpha = 0.25 + proximity * 0.7;

            ctx.arc(x, y, currentSize, 0, Math.PI * 2);
            ctx.fillStyle = glowColor.replace(/[\d.]+\)$/, `${alpha})`);
            ctx.shadowBlur = proximity * 14;
            ctx.shadowColor = "rgba(45, 212, 191, 0.8)";
            ctx.fill();
            ctx.shadowBlur = 0; // reset
          } else {
            // Default background dot with wave breathing
            const baseAlpha = 0.12 + wave * 0.1;
            const currentSize = dotSize + wave * 0.4;

            ctx.arc(x, y, currentSize, 0, Math.PI * 2);
            ctx.fillStyle = dotColor.replace(/[\d.]+\)$/, `${baseAlpha})`);
            ctx.fill();
          }
        }
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseleave", handleMouseLeave);
      window.removeEventListener("resize", handleResize);
    };
  }, [dotColor, glowColor, spacing, dotSize]);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-0 h-full w-full opacity-70 transition-opacity duration-1000"
    />
  );
}
