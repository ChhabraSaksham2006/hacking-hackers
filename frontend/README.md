# Aegis Vantage — Frontend

Predictive cyber-defence dashboard built with **TanStack Start**, **React 19**, **Tailwind CSS 4**, and **Recharts**.

## Development

```sh
npm install
npm run dev
```

The dev server starts at [http://localhost:8080](http://localhost:8080) and proxies `/api/*` requests to the backend at `http://localhost:5000`.

## Production Build

```sh
npm run build
```

Output goes to `.vercel/output/` (Nitro vercel preset) — ready for Vercel deployment.

## Tech Stack

- **Framework**: TanStack Start (SSR via Nitro)
- **UI**: React 19 + Radix UI + shadcn/ui
- **Styling**: Tailwind CSS 4
- **Charts**: Recharts
- **State**: TanStack Query
- **Realtime**: Socket.IO
