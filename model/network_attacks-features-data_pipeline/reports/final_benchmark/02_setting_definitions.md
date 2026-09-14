# 02 — Benchmark Setting Definitions & Threat Models
**SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data**  
**Smart India Hackathon 2026 | NTRO Benchmark Standards**

---

## 1. Overview & Evaluation Mandate

In operational cybersecurity deployments, a network forecasting engine encounters three distinct threat environments:
1. Familiar recurring attacks under known network configurations (**In-Distribution**).
2. Mixed temporal distributions across varying operational days (**Standard Generalization**).
3. Novel zero-day attack families never observed during model training (**Out-of-Distribution**).

To reflect these operational realities, the SIH26153 benchmark defines three rigorous evaluation settings with **strict 30-minute temporal embargo buffers** between all data partitions to prevent continuous-flow autocorrelation leakage.

---

## 2. Formal Setting Definitions

### Setting A — Seen / In-Distribution Benchmark
* **Definition:** Training, validation, and testing partitions contain identical attack types observed across contiguous non-overlapping temporal windows separated by 30-minute embargo buffers.
* **Threat Model:** Known persistent threats, routine automated scanner attacks, and established attack campaigns.
* **Attacks Included:** All seen attack families (DoS Hulk, DoS GoldenEye, PortScan, DDoS, FTP-Patator, SSH-Patator, Web Attacks).
* **Sample Count (Test):** 6,975 windows (3.87 hours of network traffic).
* **Evaluation Focus:** Peak precision, maximum onset recall, and minimal baseline false alarms when traffic signatures are known.

### Setting B — Mixed / Standard Temporal Generalization Benchmark
* **Definition:** Cross-day split where models are trained on historical days (e.g., Monday–Wednesday) and evaluated on subsequent unseen operational days (e.g., Thursday–Friday) containing a mixture of familiar and shifted attack distributions.
* **Threat Model:** Temporal concept drift, shifting benign background noise, changing traffic volume, and day-to-day network usage variance.
* **Sample Count (Test):** 13,536 windows (7.52 hours of network traffic).
* **Evaluation Focus:** Robustness to natural temporal drift, resistance to benign traffic surges, and sustained early warning without calibration decay.

### Setting C — Out-of-Distribution (OOD) / Unseen Attack Family Benchmark
* **Definition:** True zero-day generalization setting. Specific major attack families (e.g., PortScan, Web Brute-Force, Botnet) are **completely withheld** from the training and validation sets and appear **exclusively in the test partition**.
* **Threat Model:** Zero-day exploits, novel attack methodologies, and unseen adversarial penetration tactics.
* **Sample Count (Test):** 9,792 windows (5.44 hours of network traffic).
* **Evaluation Focus:** Unsupervised/generative anomaly detection, state trajectory forecasting deviation, and spectral domain perturbation detection on unfamiliar attack signatures.

---

## 3. Partition Summary & Embargo Constraints

| Setting | Train Windows | Val Windows | Test Windows | Attack Ratio (Test) | Embargo Buffer |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Setting A** | 32,551 | 6,975 | 6,975 | 18.42% | 30 Minutes |
| **Setting B** | 63,165 | 13,536 | 13,536 | 14.81% | 30 Minutes |
| **Setting C** | 45,699 | 9,792 | 9,792 | 16.32% | 30 Minutes |
