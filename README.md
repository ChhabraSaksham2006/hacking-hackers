<p align="center">
  <img src="frontend/public/flow-drishti-icon.png" alt="Flow Drishti Logo" width="80" />
</p>

<h1 align="center">Flow दृष्टि &nbsp;(Flow Drishti)</h1>

<p align="center">
  <strong>Cyber World Model — Predictive Network Defense Platform</strong>
</p>

<p align="center">
  <a href="#-architecture"><img src="https://img.shields.io/badge/Architecture-Monorepo-1e293b?style=for-the-badge&logo=github" alt="Monorepo" /></a>
  <a href="#-tech-stack"><img src="https://img.shields.io/badge/Frontend-React_19_%2B_Vite-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React" /></a>
  <a href="#-tech-stack"><img src="https://img.shields.io/badge/Backend-Express_5_%2B_MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white" alt="Express" /></a>
  <a href="#-tech-stack"><img src="https://img.shields.io/badge/ML_Engine-PyTorch_%2B_FastAPI-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white" alt="PyTorch" /></a>
  <a href="#-deployment"><img src="https://img.shields.io/badge/Deploy-Render_%2B_Vercel-000?style=for-the-badge&logo=vercel" alt="Deploy" /></a>
</p>

<p align="center">
  <em>Deep hybrid world model (SparseRSSM + TFCNet) that forecasts attacker lateral movement and C2 progression <strong>20 seconds before</strong> kill-chain completion.</em>
</p>

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Backend Setup](#1-backend-server)
  - [Frontend Setup](#2-frontend)
  - [ML Microservice Setup](#3-ml-microservice-optional)
  - [Edge Sensor Setup](#4-edge-sensor-optional)
  - [Kafka Setup](#5-kafka-message-broker-optional)
- [Environment Variables](#-environment-variables)
- [API Reference](#-api-reference)
- [ML Model Details](#-ml-model-details)
- [Deployment](#-deployment)
- [Testing](#-testing)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🌐 Overview

**Flow Drishti** is an end-to-end predictive cyber defense platform that moves beyond traditional per-packet signature detection. Instead of inspecting isolated packets *after* damage is done, Flow Drishti runs a **continuous temporal world model** over **54-dimensional network behavioral telemetry**, projecting latent kill-chain trajectories forward to catch lateral movement **20 seconds before** domain takeover.

The platform is designed for Security Operations Center (SOC) analysts, threat hunters, and enterprise security teams who need real-time, actionable threat intelligence with deep explainability.

### 🎯 What Makes It Different?

| Legacy Per-Flow Classifiers | Flow Drishti World Model |
|:---|:---|
| Scores each TCP/UDP stream independently | Encodes 54 behavioral dimensions across 10 temporal windows |
| Alerts fire *after* ransomware encryption starts | Forecasts lateral propagation trajectory **20s ahead** |
| Flat per-flow score (undetected) | State trajectory forecast with kill-chain stage tracking |
| No temporal context | Autoregressive rollout predicting K=10 windows |

---

## ✨ Key Features

### 🧠 Deep Hybrid Neural Ensemble
- **SparseRSSM** — 214,334-parameter Recurrent State-Space Model with Top-K sparsity (k=32, 25% keep ratio) and GRU deterministic memory
- **TFCNet-F** — Time-Frequency Convolution Network with 4 parallel dilated 1D convolutions + RFFT spectral projection and inverted variable-token Transformer
- **Gated Ensemble Fusion** — Zero-parameter confirmation via two-stage SOC architecture (Scout → Confirmation Gate → Temporal Aggregator)

### 📊 Real-Time SOC Dashboard
- Live infiltration probability timeline with attack stage progression (Normal → Recon → Initial Access → Lateral Movement → C2)
- Interactive 3D state manifold visualization (Three.js / WebGL)
- Network topology graph with per-host threat scoring
- SHAP-based model explainability with per-feature attribution
- Real-time alert feed with MITRE ATT&CK technique mapping

### 🤖 AI Telemetry Copilot (RAG)
- Retrieval-Augmented Generation with cascading LLM fallback: **Groq → OpenRouter → Built-in Cyber Causality Engine**
- Grounded on live packet/flow metrics, temporal deltas, and MITRE ATT&CK knowledge base
- Context-aware suggested queries that adapt to current threat level

### 🛡️ Enterprise Security
- JWT authentication with access/refresh token rotation and 2FA (TOTP via Speakeasy)
- Role-Based Access Control (RBAC) with org-scoped data isolation
- Helmet security headers, rate limiting, and input validation (Zod)
- Real-time WebSocket (Socket.io) push for cross-org alert broadcast

### 📡 Edge Sensor Network
- Distributed Python sensor agent for live network perimeter monitoring
- Real-time packet capture → 54-dimensional feature extraction → upstream telemetry dispatch
- Configurable triage thresholds (entropy, SYN flood ratio, auth port ratio, exfiltration byte rate)
- Docker-ready with systemd service support

### 📨 Event Streaming (Apache Kafka)
- Optional Kafka/Redpanda message broker for high-throughput telemetry ingestion
- Graceful in-memory fallback when Kafka is unavailable
- Topics: `aegis.telemetry.raw`, `aegis.alerts.stream`
- Consumer group processing with org-partitioned ordering

---

## 🏗 Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Flow Drishti Platform                         │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────────────────┐   │
│  │  Frontend   │    │   Backend    │    │  ML Microservice       │   │
│  │  (React 19) │◄──►│  (Express 5) │◄──►│  (FastAPI + PyTorch)   │   │
│  │  Vite + SSR │    │  MongoDB     │    │  SparseRSSM + TFCNet   │   │
│  │  TanStack   │    │  Socket.io   │    │  Ensemble Inference    │   │
│  │  Tailwind 4 │    │  JWT + RBAC  │    │  54-D Feature Pipeline │   │
│  └──────┬──────┘    └──────┬───────┘    └────────────────────────┘   │
│         │                  │                                         │
│         │           ┌──────┴───────┐                                 │
│         │           │ Apache Kafka │  (Optional)                     │
│         │           │  Redpanda    │                                 │
│         │           └──────┬───────┘                                 │
│         │                  │                                         │
│         │           ┌──────┴───────┐    ┌────────────────────────┐   │
│         └──────────►│ Edge Sensor  │    │  ML Research Pipeline  │   │
│                     │  (Python)    │    │  (Training + Data Eng) │   │
│                     │  Packet I/O  │    │  CIC-IDS-2018 Dataset  │   │
│                     └──────────────┘    └────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 🛠 Tech Stack

### Frontend
| Technology | Purpose |
|:---|:---|
| **React 19** | UI framework with latest concurrent features |
| **Vite 8** | Build tooling with HMR |
| **TanStack Router** | Type-safe file-based routing with SSR |
| **TanStack React Query** | Server state management & caching |
| **Tailwind CSS 4** | Utility-first styling |
| **Radix UI** | Accessible headless component primitives |
| **Recharts** | Data visualization charts & timelines |
| **Three.js** | 3D WebGL state manifold visualization |
| **Socket.io Client** | Real-time WebSocket events |
| **Zod** | Runtime schema validation |
| **KaTeX** | Mathematical formula rendering |

### Backend
| Technology | Purpose |
|:---|:---|
| **Express 5** | HTTP API framework |
| **MongoDB + Mongoose** | Document database & ODM |
| **Socket.io** | Real-time bidirectional WebSocket server |
| **KafkaJS** | Apache Kafka producer/consumer client |
| **JWT (jsonwebtoken)** | Access/refresh token authentication |
| **Speakeasy** | TOTP-based two-factor authentication |
| **Helmet** | Security HTTP headers |
| **Zod** | Request validation & env parsing |
| **PDFKit** | Dynamic PDF report generation |
| **Node-Cron** | Scheduled background jobs |
| **Multer** | File upload handling |
| **Brevo** | Transactional email service |

### ML Microservice
| Technology | Purpose |
|:---|:---|
| **FastAPI** | High-performance async REST API |
| **PyTorch** | Deep learning inference engine |
| **NumPy / Pandas** | Numerical computation & data manipulation |
| **scikit-learn** | Feature preprocessing (StandardScaler) |
| **Gradio** | Optional web UI for model health check |

### Edge Sensor
| Technology | Purpose |
|:---|:---|
| **Python 3.11+** | Sensor runtime |
| **Scapy / Raw Sockets** | Live packet capture & inspection |
| **Custom Feature Extractor** | 54-dimensional behavioral telemetry pipeline |
| **HTTP / NDJSON** | Upstream telemetry dispatch & local logging |

### Infrastructure
| Technology | Purpose |
|:---|:---|
| **Apache Kafka / Redpanda** | Event streaming (optional) |
| **Docker** | Containerization for sensor & ML service |
| **Render** | Backend API & ML service hosting |
| **Vercel** | Frontend deployment with SSR |
| **GitHub Actions** | CI/CD (database cleanup workflow) |

---

## 📂 Project Structure

```
flow-drishti/
├── frontend/                   # React 19 + Vite + TanStack frontend
│   ├── src/
│   │   ├── api/                # API client layer (dashboard, sensors)
│   │   ├── components/         # UI components (app, common, landing, ui)
│   │   ├── hooks/              # Custom React hooks
│   │   ├── lib/                # Utilities, API client, telemetry helpers
│   │   ├── routes/             # File-based TanStack routes
│   │   │   ├── app/            # Authenticated SOC console pages
│   │   │   │   ├── dashboard   # Live threat dashboard
│   │   │   │   ├── alerts      # Alert management
│   │   │   │   ├── topology    # Network topology graph
│   │   │   │   ├── ingestion   # Data ingestion & sensor management
│   │   │   │   ├── reports     # PDF report generation
│   │   │   │   ├── audit       # Audit trail
│   │   │   │   ├── rbac        # Role management
│   │   │   │   └── ...         # Explorer, simulation, benchmark, etc.
│   │   │   ├── index.tsx       # Public landing page
│   │   │   ├── login.tsx       # Authentication
│   │   │   ├── docs.tsx        # Technical whitepaper
│   │   │   └── ...
│   │   ├── styles.css          # Global styles & design tokens
│   │   └── server.ts           # SSR server configuration
│   └── package.json
│
├── server/                     # Express 5 + MongoDB backend
│   ├── src/
│   │   ├── config/             # Database, CORS, environment config
│   │   ├── controllers/        # Route controller logic
│   │   ├── middleware/         # Auth, RBAC, rate limiting, validation
│   │   ├── models/             # Mongoose schemas (14 models)
│   │   ├── routes/             # Express route definitions (20 routes)
│   │   ├── services/           # Business logic services
│   │   │   ├── ragService      # AI copilot with MITRE ATT&CK KB
│   │   │   ├── kafkaService    # Event streaming integration
│   │   │   ├── emailService    # Transactional emails (Brevo)
│   │   │   ├── reportService   # PDF report generation
│   │   │   ├── replayService   # CIC-IDS-2018 benchmark replay
│   │   │   └── ...
│   │   ├── utils/              # JWT, pagination, helpers
│   │   ├── socket.ts           # Socket.io real-time events
│   │   └── index.ts            # Server entry point
│   ├── scripts/                # DB management & utility scripts
│   ├── tests/                  # Integration tests (Vitest)
│   └── package.json
│
├── edge_sensor/                # Python edge sensor agent
│   ├── core/
│   │   ├── packet_ingress.py   # Raw packet capture
│   │   ├── flow_tracker.py     # TCP/UDP flow state tracking
│   │   ├── feature_extractor.py # 54-D behavioral feature extraction
│   │   ├── neural_evaluator.py # Local neural inference
│   │   ├── edge_sentinel.py    # Threat triage & alerting
│   │   ├── live_gateway.py     # HTTP upstream gateway
│   │   └── telemetry_dispatcher.py # NDJSON telemetry dispatch
│   ├── run_sensor.py           # Sensor entry point
│   ├── config.json             # Sensor configuration
│   └── Dockerfile
│
├── microservices/
│   └── model_service/          # FastAPI ML inference microservice
│       ├── app.py              # SparseRSSM + TFCNet ensemble API
│       ├── model_arch/         # Neural network architecture files
│       ├── assets/             # Model weights, scaler, data slices
│       ├── requirements.txt
│       └── Dockerfile
│
├── model/
│   └── network_attacks-features-data_pipeline/  # ML research & training
│       ├── src/                # Model source code & training scripts
│       ├── configs/            # Training hyperparameter configs
│       ├── data/               # Dataset processing pipeline
│       ├── deployment/         # Production model artifacts
│       ├── reports/            # Evaluation reports & metrics
│       └── tests/              # Model unit tests
│
├── sample_captures/            # PCAP/CSV sample network captures
├── scripts/                    # Utility scripts (rebranding, fixes)
├── logs/                       # Application log files
│
├── docker-compose.kafka.yml    # Kafka/Redpanda broker setup
├── render.yaml                 # Render deployment blueprint
├── tsconfig.json               # Root TypeScript config
└── .github/workflows/          # CI/CD GitHub Actions
```

---

## 🚀 Getting Started

### Prerequisites

| Tool | Version | Purpose |
|:---|:---|:---|
| **Node.js** | ≥ 22.x | Backend & frontend runtime |
| **npm** | ≥ 10.x | Package manager |
| **MongoDB** | ≥ 7.x | Database (local or Atlas) |
| **Python** | ≥ 3.11 | ML microservice & edge sensor |
| **Docker** | Latest | Kafka broker (optional) |

### 1. Backend Server

```bash
# Navigate to server directory
cd server

# Install dependencies
npm install

# Copy environment template and configure
cp .env.example .env
# Edit .env with your MongoDB URI, JWT secrets, etc.

# Seed the database (optional)
npm run seed

# Start development server (hot-reload via tsx)
npm run dev
```

The API server starts at `http://localhost:5000`.

### 2. Frontend

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Copy environment template
cp .env.example .env
# Set VITE_API_URL to your backend URL

# Start Vite dev server
npm run dev
```

The frontend starts at `http://localhost:5173`.

### 3. ML Microservice (Optional)

```bash
# Navigate to model service
cd microservices/model_service

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies (CPU-only PyTorch)
pip install -r requirements.txt

# Start FastAPI server
uvicorn app:app --host 0.0.0.0 --port 7860 --reload
```

The ML API starts at `http://localhost:7860` with Swagger docs at `/docs`.

### 4. Edge Sensor (Optional)

```bash
# Navigate to edge sensor
cd edge_sensor

# Install Python dependencies
pip install scapy requests

# Run sensor with default config
python run_sensor.py
```

> **Note:** Packet capture requires elevated privileges (`sudo` on Linux, Administrator on Windows).

### 5. Kafka Message Broker (Optional)

```bash
# Start Kafka (Redpanda) broker with Docker
docker-compose -f docker-compose.kafka.yml up -d

# Kafka broker: localhost:9092
# Kafka Console UI: http://localhost:8085
```

Set `KAFKA_BROKERS=localhost:9092` in your server `.env` to enable event streaming.

---

## 🔐 Environment Variables

### Backend (`server/.env`)

| Variable | Required | Description |
|:---|:---:|:---|
| `MONGODB_URI` | ✅ | MongoDB connection string |
| `JWT_SECRET` | ✅ | Access token signing secret (≥32 chars) |
| `JWT_REFRESH_SECRET` | ✅ | Refresh token signing secret (≥32 chars) |
| `JWT_2FA_CHALLENGE_SECRET` | ❌ | 2FA challenge token secret |
| `PORT` | ❌ | Server port (default: `5000`) |
| `FRONTEND_URL` | ❌ | CORS origin (default: `http://localhost:5173`) |
| `ML_SERVICE_URL` | ❌ | ML microservice URL |
| `KAFKA_BROKERS` | ❌ | Kafka broker addresses (comma-separated) |
| `GROQ_API_KEY` | ❌ | Groq API key for AI copilot |
| `OPENROUTER_API_KEY` | ❌ | OpenRouter API key (fallback LLM) |
| `BREVO_API_KEY` | ❌ | Brevo email service API key |
| `S3_ENDPOINT` | ❌ | Object storage endpoint |
| `REDIS_URL` | ❌ | Redis URL for job queues |

### Frontend (`frontend/.env`)

| Variable | Required | Description |
|:---|:---:|:---|
| `VITE_API_URL` | ✅ | Backend API base URL |

---

## 📡 API Reference

### Health & Readiness

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/api/health` | Basic health check |
| `GET` | `/api/ready` | Database connectivity check |

### Authentication

| Method | Endpoint | Description |
|:---|:---|:---|
| `POST` | `/api/auth/register` | User registration |
| `POST` | `/api/auth/login` | Login (returns JWT cookies) |
| `POST` | `/api/auth/refresh` | Refresh access token |
| `POST` | `/api/auth/logout` | Clear auth cookies |
| `POST` | `/api/auth/verify-email` | Email verification |
| `POST` | `/api/auth/forgot-password` | Password reset request |
| `POST` | `/api/auth/2fa/*` | Two-factor authentication endpoints |

### Core Platform

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/api/dashboard` | Live threat dashboard state |
| `GET` | `/api/alerts` | Alert feed with filtering |
| `GET` | `/api/flows` | Network flow records |
| `GET` | `/api/predictions` | Model prediction history |
| `GET` | `/api/network` | Network topology graph |
| `GET` | `/api/segments` | Network segment management |
| `POST` | `/api/ingestion/*` | Telemetry data ingestion |
| `GET` | `/api/reports` | Report generation & retrieval |
| `GET` | `/api/audit` | Audit trail logs |
| `GET` | `/api/sensors` | Edge sensor management |
| `POST` | `/api/chat` | AI copilot (RAG) queries |
| `GET` | `/api/explainability` | SHAP feature attributions |
| `GET` | `/api/models` | Model version management |
| `GET` | `/api/simulations` | Attack simulation scenarios |
| `GET` | `/api/demonstration` | Live benchmark demonstration |

### ML Microservice

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/health` | Model status & metadata |
| `POST` | `/predict` | Raw (10×54) telemetry inference |
| `POST` | `/predict/step` | Benchmark step simulation |
| `GET` | `/predict/init` | Baseline 48-window timeline |
| `GET` | `/replay/dataset` | CIC-IDS-2018 dataset metadata |

---

## 🧬 ML Model Details

### Neural Architecture

```
Input: (batch, 10, 54) — 10 consecutive 2-second network state windows
                         54 behavioral feature dimensions

  ┌─────────────────────────┐    ┌──────────────────────────┐
  │     SparseRSSM          │    │      TFCNet-F            │
  │  (State-Space Model)    │    │  (Spectral Transformer)  │
  │                         │    │                          │
  │  GRU Cell (128-D)       │    │  4× Dilated Conv1D       │
  │  Top-K Sparsity (k=32)  │    │  RFFT Spectral Branch    │
  │  Autoregressive Rollout │    │  Sigmoid Gated Fusion    │
  │  K=10 Future Windows    │    │  Inverted Transformer    │
  │                         │    │  (Variable Tokenization) │
  │  214,334 params         │    │                          │
  └───────────┬─────────────┘    └───────────┬──────────────┘
              │                              │
              └──────────┬───────────────────┘
                         │
              ┌──────────┴─────────┐
              │  Ensemble Fusion   │
              │  p = 0.6·RSSM +    │
              │      0.4·TFC       │
              │                    │
              │  Two-Stage SOC:    │
              │  Scout → Confirm   │
              │  → Aggregate       │
              └─────────┬──────────┘
                        │
              ┌─────────┴──────────┐
              │  Kill-Chain Stage  │
              │  Progression       │
              │                    │
              │  Normal → Recon    │
              │  → Initial Access  │
              │  → Lateral Move    │
              │  → C2 → Exfil      │
              └────────────────────┘
```

### 54-Dimensional Feature Vector

| Category | Features |
|:---|:---|
| **Flow Dynamics** | `flow_count`, `total_ip_bytes`, `total_packets`, `flow_rate`, `byte_rate`, `packet_rate` |
| **Protocol Ratios** | `tcp_ratio`, `udp_ratio`, `icmp_ratio` |
| **Port Dispersion** | `unique_dst_ports`, `port_concentration`, `dst_port_entropy`, `auth_port_ratio` |
| **TCP Flags** | `syn_count/ratio`, `ack_count/ratio`, `rst_count/ratio`, `fin_count`, `psh_count` |
| **Handshake** | `rst_to_syn_ratio`, `handshake_completion_ratio` |
| **Packet Stats** | `fwd_packet_ratio`, `fwd_byte_ratio`, `down_up_ratio_mean/std`, `pkt_len_mean/std/max/min`, `zero_payload_ratio` |
| **Temporal** | `flow_iat_mean/std/max/min`, `active_connection_lifetime_mean` |
| **State Deltas** | 17 first-order temporal derivative features (Δ flow, Δ bytes, Δ entropy, etc.) |

### Benchmark Performance

| Metric | Value |
|:---|:---|
| **Dataset** | CSE-CIC-IDS2018 (Thursday-01-03-2018 Infiltration) |
| **F1 Score** | 94.3% |
| **False Positive Rate** | 0.014 |
| **Early Warning Lead Time** | 20.0 seconds |
| **Window Duration** | 2 seconds |
| **Context Windows** | 10 (sliding) |

---

## 🚢 Deployment

### Render (Backend + ML Service)

The project includes a [`render.yaml`](render.yaml) blueprint for one-click deployment:

```bash
# Backend API → Render Web Service (Node.js)
# ML Microservice → Render Web Service (Python)
```

1. Connect your GitHub repository to [Render](https://render.com)
2. Use the `render.yaml` blueprint for automatic service creation
3. Set environment variables (MongoDB URI, JWT secrets) in the Render dashboard

### Vercel (Frontend)

```bash
# Frontend deploys automatically via Vercel Git Integration
# Set VITE_API_URL environment variable to your Render backend URL
```

The frontend includes a [`vercel.json`](frontend/vercel.json) configuration for SSR deployment.

---

## 🧪 Testing

### Backend Tests

```bash
cd server

# Run all integration tests
npm run test

# Tests use mongodb-memory-server for isolated DB testing
```

Test coverage includes:
- **Kafka integration** — Producer/consumer lifecycle, message serialization, fallback behavior
- **Sensor API** — Registration, telemetry ingestion, heartbeat endpoints

### ML Microservice

```bash
cd microservices/model_service

# Run inference smoke tests
python -m pytest tests/ -v
```

---

## 🤝 Contributing

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/your-feature`)
3. **Commit** your changes (`git commit -m 'feat: add new feature'`)
4. **Push** to the branch (`git push origin feature/your-feature`)
5. **Open** a Pull Request

### Commit Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Purpose |
|:---|:---|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `docs:` | Documentation |
| `refactor:` | Code restructuring |
| `test:` | Adding tests |
| `chore:` | Maintenance tasks |

---

## 📄 License

This project is proprietary. All rights reserved.

---

<p align="center">
  <sub>Built by team <strong>Hacking Hackers</strong>— Forecasting threats before they strike .</sub>
</p>
