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