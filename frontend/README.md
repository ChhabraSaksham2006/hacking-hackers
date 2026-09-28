<div align="center">
  <h1>ðŸ›¡ï¸ Flow Drishti</h1>
  <p><strong>Predictive Cyber-Defence Dashboard</strong></p>

  <p>
    <img src="https://img.shields.io/badge/React_19-20232A?style=for-the-badge&logo=react&logoColor=61DAFB" alt="React" />
    <img src="https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white" alt="Tailwind" />
    <img src="https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript" />
    <img src="https://img.shields.io/badge/Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white" alt="Vercel" />
  </p>
</div>

<br />

Welcome to the frontend of **Flow Drishti**, a cutting-edge interface designed for security operations centers (SOCs) to forecast and mitigate attacker progression *before* compromise is complete.

## âœ¨ Features

- **Real-time Predictive Analytics**: Monitor active threats and network flows via live Socket.IO streams.
- **Dynamic Topologies**: Visualize intricate network nodes and endpoints seamlessly.
- **Actionable Insights**: Intuitive data visualization powered by Recharts.
- **Blazing Fast SSR**: Rendered at the edge using TanStack Start and Nitro.
- **Modern & Responsive UI**: Built with Shadcn UI, Radix primitives, and Tailwind CSS v4.

---

## ðŸ› ï¸ Tech Stack

- **Framework**: [TanStack Start](https://tanstack.com/start) (SSR via Nitro)
- **UI Architecture**: React 19 + Radix UI + shadcn/ui
- **Styling**: Tailwind CSS 4
- **Data Visualization**: Recharts, D3
- **State Management**: TanStack Query
- **Realtime Comms**: Socket.IO Client

---

## Getting Started

Follow these instructions to get a copy of the project up and running on your local machine for development and testing.

### Prerequisites

Ensure you have Node.js (>= 22.12.0) and npm installed.

### Installation

1. **Navigate to the frontend directory:**
   ```bash
   cd frontend
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Set up Environment Variables:**
   Copy the example environment file and configure it as needed.
   ```bash
   cp .env.example .env
   ```
   *(Ensure `VITE_API_URL` points to your running backend server, e.g., `http://localhost:5000`)*

4. **Start the Development Server:**
   ```bash
   npm run dev
   ```

> **Note:** The dev server runs at [http://localhost:8080](http://localhost:8080) and automatically proxies `/api/*` requests to the backend.

---

## ðŸŒ Deployment (Vercel)

Flow Drishti is configured for zero-hassle deployment to Vercel via Nitro's serverless preset.

1. **Build the Application:**
   ```bash
   npm run build
   ```
   *(The optimized serverless output is generated in `.vercel/output/`)*

2. **Deploy to Vercel:**
   Connect your GitHub repository to Vercel and ensure the **Root Directory** is set to `frontend`. Vercel will automatically detect the build configurations. Remember to configure your `VITE_API_URL` in the Vercel project settings!

---

<div align="center">
  <sub>Built with passion for next-generation cyber-security.</sub>
</div>
