import React from "react";
import { cn } from "@/lib/utils";

interface BrandLogoProps {
  className?: string;
  size?: "sm" | "md" | "lg";
  showText?: boolean;
}

export function BrandLogo({ className, size = "md", showText = true }: BrandLogoProps) {
  const iconSizes = {
    sm: "size-5",
    md: "size-6",
    lg: "size-8",
  };

  const badgeSizes = {
    sm: "size-7 p-1",
    md: "size-8 p-1",
    lg: "size-10 p-1.5",
  };

  const textSizes = {
    sm: "text-sm",
    md: "text-base",
    lg: "text-lg",
  };

  return (
    <div className={cn("inline-flex items-center gap-2.5", className)}>
      <div className={cn("relative inline-flex items-center justify-center rounded-lg bg-white shadow-sm shadow-black/20 ring-1 ring-black/10 transition-transform hover:scale-[1.02]", badgeSizes[size])}>
        <img
          src="/flow-drishti-icon.png"
          alt="Flow दृष्टि"
          className={cn(iconSizes[size], "object-contain")}
        />
      </div>
      {showText && (
        <span className={cn("font-display font-bold tracking-tight text-paper select-none", textSizes[size])}>
          <span className="text-paper">Flow </span>
          <span className="text-teal font-sans">दृष्टि</span>
        </span>
      )}
    </div>
  );
}

export default BrandLogo;
