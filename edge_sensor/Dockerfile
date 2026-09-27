# ===============================================================
# Aegis Vantage — Enterprise Distributed Edge Sensor Agent
# Lightweight, Zero-Dependency Network Telemetry Daemon
# ===============================================================
FROM python:3.11-alpine

LABEL maintainer="Aegis Vantage Cyber World Model Team"
LABEL description="Distributed Edge Network Sensor Agent for Real-Time Threat Forecasting"

WORKDIR /app

# The edge sensor runs with zero external Python dependencies!
COPY core/ /app/core/
COPY demo/ /app/demo/
COPY config.json /app/config.json
COPY run_sensor.py /app/run_sensor.py

ENV PYTHONUNBUFFERED=1
ENV SENSOR_ID="edge-probe-prod-01"
ENV WINDOW_SEC="2.0"

# Default: Headless daemon streaming to local NDJSON and central ingestion
ENTRYPOINT ["python", "run_sensor.py"]
CMD ["--mode", "tap", "--headless", "--output", "/var/log/aegis_telemetry.ndjson"]
