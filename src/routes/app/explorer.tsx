import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { FlatPanel, PageTitle } from "@/components/app/panels";
import { pageHead } from "@/lib/head";
import { flows } from "@/lib/telemetry";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/app/explorer")({
  head: pageHead(
    "Flow explorer — Aegis Vantage",
    "Dense flow and packet reference table with per-flow feature values and packet sequences.",
  ),
  component: Explorer;
});

function Explorer() {
  return null;
}
