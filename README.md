# Network Traffic Analyzer — Malicious Pattern Detection

A Python-based tool that analyzes captured network traffic (.pcap files) to detect common attack patterns — port scanning and brute-force login attempts — using custom sliding-window detection logic.

## Overview

This project simulates real attacks in a controlled lab environment, captures the resulting traffic with **Wireshark/tcpdump**, and then parses that traffic with **Python (Scapy)** to flag suspicious behavior — similar to how a lightweight Intrusion Detection System (IDS) works.

## Lab Setup

- **Environment:** GitHub Codespaces (Ubuntu container)
- **Target:** DVWA (Damn Vulnerable Web Application) running in a Docker container
- **Attacker tools:** Nmap (port scanning), Hydra (brute-force), tcpdump (traffic capture)
- **Analysis:** Python 3 + Scapy

Attacker and target run as separate processes/containers on the same host, connected via Docker's internal network.

## Attacks Simulated

1. **Port Scan** — `nmap -sV` against the DVWA container, scanning all ports to fingerprint running services.
2. **Brute-Force Login** — `hydra` attempting repeated logins against the DVWA login form using a custom wordlist.

Each attack's traffic was captured separately into its own `.pcap` file.

## Detection Logic

Both detectors use a **sliding time-window** approach:

- **Port Scan Detection** (`detect_portscan.py`): Flags a source IP if it contacts **10+ distinct ports** on the target within a **10-second window**.
- **Brute-Force Detection** (`detect_bruteforce.py`): Flags a source IP if it sends **5+ HTTP requests with payload data** to the target's login endpoint within a **15-second window**.

Traffic is filtered to only packets destined for the target IP, which excludes reply traffic and unrelated background noise from the capture.

## Combined Report

`analyzer.py` runs both detectors together and generates a unified report (printed to console and saved as `report.txt`).

### Sample Output
## Live Detection Dashboard

Beyond offline `.pcap` analysis, this project also includes a **real-time detection system** with a live web dashboard.

- `live_detector.py` — sniffs live traffic using Scapy and prints alerts to the console the moment a threshold is crossed, instead of analyzing a saved file after the fact.
- `app.py` + `templates/index.html` — a Flask web application that runs the same live-sniffing logic in a background thread and exposes a `/api/alerts` endpoint. The dashboard auto-refreshes every 2 seconds and displays alerts as color-coded rows (red for Port Scan, orange for Brute-Force).

### Running the Live Dashboard

### Running the Live Dashboard

The included `setup.sh` script automates the entire process — starting the target container, detecting its IP and the correct network interface, and launching the dashboard.

```bash
sudo bash setup.sh
```

Then open the forwarded port 5000 URL in your browser (or `http://localhost:5000` on a local machine). Generate traffic against the target (e.g. `nmap -sV <target-ip>`) and watch alerts appear on the dashboard in real time.

**Manual setup (if not using the script):**

```bash
pip install flask --break-system-packages
export TARGET_IP=<target-container-ip>
export IFACE=<network-interface>
sudo -E python3 app.py
```

`TARGET_IP` and `IFACE` default to `172.17.0.2` and `docker0` if not set, matching this project's Docker-based lab setup.

Then open `http://localhost:5000` (or the forwarded port URL if running in a container/cloud environment). Generate traffic against the target (e.g. `nmap -sV <target-ip>`) and watch alerts appear on the dashboard in real time.

**Note:** the sniffing interface (`IFACE` in `app.py`) must match wherever the target's traffic actually flows — e.g. `docker0` if the target is a Docker container on the same host, or `eth0`/`any` for a real network interface.