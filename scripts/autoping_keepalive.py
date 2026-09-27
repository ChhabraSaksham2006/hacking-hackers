#!/usr/bin/env python3
"""
Aegis Vantage — Render Services Keep-Alive & AutoPing Daemon
Continuously pings the ML Microservice (and backend) every 5 minutes to prevent
Render free-tier inactivity hibernation / cold start (15-minute timeout).

Usage:
    python scripts/autoping_keepalive.py
    python scripts/autoping_keepalive.py --interval 300 --url https://hacking-hackers.onrender.com/health
"""

import argparse
import datetime
import json
import os
import sys
import time
import urllib.error
import urllib.request

# Ensure UTF-8 console output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def ping_endpoint(url: str, timeout: float = 25.0) -> dict:
    """Sends a GET request to the target health endpoint and measures latency."""
    t0 = time.time()
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "AegisVantage-AutoPingDaemon/1.0 (Keep-Alive Service)",
            "Accept": "application/json",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed_ms = round((time.time() - t0) * 1000, 1)
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                data = json.loads(raw)
            except Exception:
                data = {"raw": raw[:120]}
            return {
                "success": True,
                "status": resp.status,
                "latency_ms": elapsed_ms,
                "data": data,
                "error": None,
            }
    except urllib.error.HTTPError as e:
        elapsed_ms = round((time.time() - t0) * 1000, 1)
        return {
            "success": False,
            "status": e.code,
            "latency_ms": elapsed_ms,
            "data": None,
            "error": str(e),
        }
    except Exception as e:
        elapsed_ms = round((time.time() - t0) * 1000, 1)
        return {
            "success": False,
            "status": 0,
            "latency_ms": elapsed_ms,
            "data": None,
            "error": str(e),
        }


def main():
    parser = argparse.ArgumentParser(
        description="Aegis Vantage AutoPing Keep-Alive Daemon for Render",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--url",
        type=str,
        default="https://hacking-hackers.onrender.com/health",
        help="Health check URL of the Render ML service (default: https://hacking-hackers.onrender.com/health)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=300,
        help="Ping interval in seconds (default: 300s / 5 minutes)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single ping check and exit",
    )

    args = parser.parse_args()

    target_url = args.url
    if not target_url.endswith("/health"):
        target_url = target_url.rstrip("/") + "/health"

    interval_sec = max(30, args.interval)

    print("=" * 68)
    print("🛡️  Aegis Vantage — Render Keep-Alive AutoPing Daemon")
    print(f"[*] Target Endpoint: {target_url}")
    print(f"[*] Ping Frequency:  Every {interval_sec}s ({interval_sec / 60:.1f} minutes)")
    print(f"[*] Purpose:         Prevent Render 15-min free tier coldstart")
    print("=" * 68)

    ping_count = 0
    success_count = 0

    try:
        while True:
            ping_count += 1
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n[#{ping_count:04d} | {now_str}] 🏓 Pinging {target_url} ...")

            result = ping_endpoint(target_url)

            if result["success"]:
                success_count += 1
                service_info = result["data"].get("service", "ML Service") if isinstance(result["data"], dict) else "online"
                print(
                    f"       ✅ Status: HTTP {result['status']} | Latency: {result['latency_ms']}ms | Service: {service_info} [COLDSTART PREVENTED]"
                )
            else:
                print(
                    f"       ⚠️ Status: {result['status'] or 'TIMEOUT'} | Latency: {result['latency_ms']}ms | Warming up container: {result['error']}"
                )

            if args.once:
                break

            print(f"       ⏱️ Next ping in {interval_sec}s... (Press Ctrl+C to stop)")
            time.sleep(interval_sec)

    except KeyboardInterrupt:
        print("\n\n[*] AutoPing daemon stopped by user.")
        print(f"[*] Summary: {success_count}/{ping_count} pings successful.")


if __name__ == "__main__":
    main()
