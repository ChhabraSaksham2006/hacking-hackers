# Aegis Vantage — Cyber World Model Microservice

Standalone **FastAPI** deep learning inference microservice powering the **Aegis Vantage** attack forecasting engine. Offloads heavy PyTorch tensor math and temporal state-space modeling from the primary Node.js / Express backend into a dedicated, containerized microservice.

---

## 🚀 Architecture Highlights

- **Models**:
  - **SparseRSSM**: 54-D State-Space World Model with 256-D recurrent latent dynamics forecasting up to 20 seconds into the future ($K=10$).
  - **TFCNet**: Time-Frequency Convolutional Network with Inverted Transformer (iTransformer) backbone capturing multi-scale microbursts and spectral periodicities.
  - **Ensemble Fusion**: Gated weighted onset probability ($0.60 \times P_{\text{RSSM}} + 0.40 \times P_{\text{TFC}}$).
- **Benchmark Grounding**: Grounded in the **CSE-CIC-IDS2018** Thursday-01-03-2018 Infiltration episode (`EP_0001`), streaming real continuous 2.0s telemetry windows.
- **Microservice Footprint**: Ultra-compact (< 1 MB total model weights, scaler, and benchmark slice), memory-efficient, and optimized for CPU/GPU serverless instances.

---

## 📁 Directory Structure

```text
microservices/model_service/
├── app.py                     # FastAPI application & inference endpoints
├── Dockerfile                 # Multi-stage production container
├── requirements.txt           # Python dependencies (torch, fastapi, uvicorn, etc.)
├── README.md                  # Deployment & setup documentation
├── model_arch/                # Self-contained neural network architectures
│   ├── sparse_rssm.py
│   └── tfcnet.py
└── assets/                    # Pre-packaged weights & benchmark slice
    ├── model.pt               # PyTorch SparseRSSM model checkpoint (~862 KB)
    ├── scaler.pkl             # 54-dimensional StandardScaler (~1.7 KB)
    └── cached_thursday_slice.parquet # Benchmark temporal slice (~78 KB)
```

---

## 🛠️ Local Development

### 1. Install Dependencies
```bash
cd microservices/model_service
pip install -r requirements.txt
```

### 2. Run the Service
```bash
uvicorn app:app --host 0.0.0.0 --port 7860 --reload
```

The service will start on `http://localhost:7860`. Interactive Swagger documentation will be available at `http://localhost:7860/docs`.

---

## 🐳 Docker Containerization

To build and run the microservice via Docker:

```bash
# Build the image
docker build -t aegis-model-service .

# Run the container
docker run -d -p 7860:7860 --name aegis-model-service aegis-model-service
```

---

---

## 🤗 Deploying to Hugging Face Spaces (100% Free — No Credit Card Needed)

> **Important**: Hugging Face recently started asking for credit card verification on **Docker** spaces to prevent cryptomining abuse. 
> However, **Gradio Spaces are 100% COMPLETELY FREE** with **2 vCPU and 16 GB RAM** with **zero credit card required**!
> Because Gradio is built on FastAPI, our microservice supports Gradio mounting out-of-the-box in `app.py`.

### Step 1: Create a Space on Hugging Face
1. Go to [Hugging Face Spaces](https://huggingface.co/new-space).
2. Name your Space (e.g., `aegis-cyber-world-model`).
3. Select **Gradio** as the Space SDK (choose Python 3.10 or 3.11).
4. Hardware: Select **CPU basic (2 vCPU, 16 GB RAM) - Free**.
5. Click **Create Space**.

### Step 2: Push the Microservice Files
```bash
# Clone the newly created HF space
git clone https://huggingface.co/spaces/<your-username>/aegis-cyber-world-model hf-space
cd hf-space

# Copy microservice files into the space repository
cp -r /path/to/hacking-hackers/microservices/model_service/* .

# Add gradio to requirements.txt if not already present
echo "gradio>=4.0.0" >> requirements.txt

# Commit and push
git add .
git commit -m "Deploy Aegis Vantage Model Service with Gradio SDK"
git push origin main
```

### Step 3: Use the Endpoint
- Hugging Face will install dependencies and start your app.
- Your public endpoint URL is:
  `https://<your-username>-aegis-cyber-world-model.hf.space`
- All FastAPI routes (`/health`, `/predict/step`, `/predict/init`, `/predict`) are live and publicly queryable at this URL.

---

## 🌐 Alternative Free Hosting Options

If you prefer other platforms instead of Hugging Face:

1. **Render.com (Free Web Service)**:
   - Create a free Web Service on [Render](https://render.com).
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `uvicorn app:app --host 0.0.0.0 --port $PORT`
   - Yields a free HTTPS URL: `https://<your-app>.onrender.com`.

2. **Koyeb (Free Nano Service)**:
   - Supports Docker or Python native deployment with global edge CDN for free.

3. **Self-Hosted Monolithic / Colocated Fallback (Zero Extra Cost)**:
   - If you deploy your backend on a single VM, DigitalOcean droplet, or VPS with Python installed:
   - Simply leave `ML_SERVICE_URL=""` (or unset). The backend automatically uses the built-in local bridge (`model_bridge.py`), executing PyTorch directly with 0 ms network overhead.

---

## 🔗 Connecting the Backend to the Microservice

1. Open `server/.env` in your project.
2. Set `ML_SERVICE_URL` to your remote Hugging Face or container URL:
   ```env
   # Remote Hugging Face Space endpoint
   ML_SERVICE_URL=https://<your-username>-aegis-cyber-world-model.hf.space

   # Or local microservice instance during testing
   # ML_SERVICE_URL=http://localhost:7860
   ```
3. Restart or start the Express backend:
   ```bash
   cd server
   npm run dev
   ```

> **Resilient Fallback**: If `ML_SERVICE_URL` is empty, unreachable, or experiences network downtime, the Express backend automatically falls back to local Python process execution without interrupting dashboard users.

---

## 📡 API Endpoints

### 1. `GET /health`
Returns service status, loaded PyTorch model architectures, and dataset metadata.

**Response:**
```json
{
  "status": "online",
  "service": "aegis-vantage-model-microservice",
  "models": {
    "sparse_rssm": "loaded (256-D state space)",
    "tfcnet": "loaded (time-frequency iTransformer)",
    "ensemble": "active (gated fusion)",
    "scaler": "StandardScaler (54 dimensions)"
  },
  "target_dataset": "CSE-CIC-IDS2018 (Thursday-01-03-2018 Infiltration)"
}
```

### 2. `POST /predict/step`
Executes forward ensemble inference over a specific window step ($[0..47]$) from the Thursday Infiltration episode.

**Request Body:**
```json
{
  "step_index": 47
}
```

**Response:**
```json
{
  "step_index": 47,
  "actual_window_index": 1797,
  "timestamp": "2018-03-01 01:59:54",
  "latest_probability": 0.914,
  "raw_model_prob": 0.052,
  "summary": {
    "infiltrationProbability": 0.91,
    "infiltrationProbabilityPct": "91%",
    "activeFlows": "15,525",
    "flaggedHosts": "3",
    "modelConfidence": "91.8%",
    "leadTimeSeconds": 20.0,
    "currentStage": "Lateral Movement",
    "riskLevel": "critical",
    "threshold": 0.65
  },
  "stages": [ ... ],
  "recentAlerts": [ ... ],
  "recentFlows": [ ... ]
}
```

### 3. `GET /predict/init`
Returns the 48-window initial probability curve and the initial starting state for fast dashboard bootstrapping.

### 4. `POST /predict`
Executes real-time forward ensemble inference over an arbitrary $(10, 54)$ normalized sequence matrix.
