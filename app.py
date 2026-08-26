from flask import Flask, render_template, jsonify
from scapy.all import sniff, TCP, IP
from collections import defaultdict
import threading
import time
import os

app = Flask(__name__)

TARGET_IP = os.environ.get("TARGET_IP", "172.17.0.2")
TARGET_PORT = 80
IFACE = os.environ.get("IFACE", "docker0")
PORT_THRESHOLD = 10
PORT_TIME_WINDOW = 10

REQUEST_THRESHOLD = 5
REQUEST_TIME_WINDOW = 15

port_activity = defaultdict(list)
request_activity = defaultdict(list)

alerted_portscan = set()
alerted_bruteforce = set()

alerts = []          # yeh list dashboard ko dikhegi
alerts_lock = threading.Lock()


def clean_old(events, window):
    cutoff = time.time() - window
    return [e for e in events if (e[0] if isinstance(e, tuple) else e) >= cutoff]


def add_alert(alert_type, src_ip, detail):
    with alerts_lock:
        alerts.insert(0, {
            "type": alert_type,
            "source_ip": src_ip,
            "target": f"{TARGET_IP}",
            "detail": detail,
            "time": time.strftime("%H:%M:%S")
        })
        if len(alerts) > 50:
            alerts.pop()


def check_port_scan(src_ip):
    events = clean_old(port_activity[src_ip], PORT_TIME_WINDOW)
    port_activity[src_ip] = events
    distinct_ports = set(p for _, p in events)
    if len(distinct_ports) >= PORT_THRESHOLD and src_ip not in alerted_portscan:
        add_alert("Port Scan", src_ip, f"{len(distinct_ports)} distinct ports within {PORT_TIME_WINDOW}s")
        alerted_portscan.add(src_ip)


def check_brute_force(src_ip):
    events = clean_old(request_activity[src_ip], REQUEST_TIME_WINDOW)
    request_activity[src_ip] = events
    if len(events) >= REQUEST_THRESHOLD and src_ip not in alerted_bruteforce:
        add_alert("Brute-Force", src_ip, f"{len(events)} requests within {REQUEST_TIME_WINDOW}s")
        alerted_bruteforce.add(src_ip)


def process_packet(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    if pkt[IP].dst != TARGET_IP:
        return

    src_ip = pkt[IP].src
    dst_port = pkt[TCP].dport
    now = time.time()

    port_activity[src_ip].append((now, dst_port))
    check_port_scan(src_ip)

    if dst_port == TARGET_PORT and pkt.haslayer('Raw'):
        request_activity[src_ip].append(now)
        check_brute_force(src_ip)


def start_sniffing():
    sniff(iface=IFACE, filter="tcp", prn=process_packet, store=False)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts")
def api_alerts():
    with alerts_lock:
        return jsonify(alerts)


if __name__ == "__main__":
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    app.run(host="0.0.0.0", port=5000)