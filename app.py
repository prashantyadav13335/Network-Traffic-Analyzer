from flask import Flask, render_template, jsonify, request
from scapy.all import sniff, TCP, IP
from collections import defaultdict
import threading
import time
import socket
import os

app = Flask(__name__)

IFACE = os.environ.get("IFACE", "docker0")

PORT_THRESHOLD = 10
PORT_TIME_WINDOW = 10
REQUEST_THRESHOLD = 5
REQUEST_TIME_WINDOW = 15
CONNECTION_STALE_AFTER = 30  # seconds — purani connections table se hata do

# ---- Target state (dashboard se dynamically set hota hai) ----
target_lock = threading.Lock()
current_target = {
    "domain": os.environ.get("TARGET_DOMAIN", ""),
    "ips": set([os.environ.get("TARGET_IP", "172.17.0.2")])
}

# ---- Detection state ----
port_activity = defaultdict(list)
request_activity = defaultdict(list)
alerted_portscan = set()
alerted_bruteforce = set()

alerts = []
alerts_lock = threading.Lock()

# ---- Connections table state ----
connections = {}   # key: (peer_ip, port, proto) -> {packets, bytes, last_seen, first_seen}
connections_lock = threading.Lock()


def clean_old(events, window):
    cutoff = time.time() - window
    return [e for e in events if (e[0] if isinstance(e, tuple) else e) >= cutoff]


def add_alert(alert_type, src_ip, target_ip, detail):
    with alerts_lock:
        alerts.insert(0, {
            "type": alert_type,
            "source_ip": src_ip,
            "target": target_ip,
            "detail": detail,
            "time": time.strftime("%H:%M:%S")
        })
        if len(alerts) > 50:
            alerts.pop()


def check_port_scan(src_ip, target_ip):
    key = (src_ip, target_ip)
    events = clean_old(port_activity[key], PORT_TIME_WINDOW)
    port_activity[key] = events
    distinct_ports = set(p for _, p in events)
    if len(distinct_ports) >= PORT_THRESHOLD and key not in alerted_portscan:
        add_alert("Port Scan", src_ip, target_ip, f"{len(distinct_ports)} distinct ports within {PORT_TIME_WINDOW}s")
        alerted_portscan.add(key)


def check_brute_force(src_ip, target_ip):
    key = (src_ip, target_ip)
    events = clean_old(request_activity[key], REQUEST_TIME_WINDOW)
    request_activity[key] = events
    if len(events) >= REQUEST_THRESHOLD and key not in alerted_bruteforce:
        add_alert("Brute-Force", src_ip, target_ip, f"{len(events)} requests within {REQUEST_TIME_WINDOW}s")
        alerted_bruteforce.add(key)


def record_connection(local_role, peer_ip, port, proto, pkt_len):
    """local_role: 'outbound' (hum bhej rahe) ya 'inbound' (hum receive kar rahe)"""
    key = (peer_ip, port, proto)
    with connections_lock:
        now = time.time()
        if key not in connections:
            connections[key] = {"packets": 0, "bytes": 0, "first_seen": now, "last_seen": now, "direction": local_role}
        connections[key]["packets"] += 1
        connections[key]["bytes"] += pkt_len
        connections[key]["last_seen"] = now


def process_packet(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    dst_port = pkt[TCP].dport
    src_port = pkt[TCP].sport
    pkt_len = len(pkt)
    now = time.time()

    with target_lock:
        target_ips = set(current_target["ips"])

    # ---- Connections table: sirf target se related traffic track karo ----
    if dst_ip in target_ips:
        record_connection("outbound", dst_ip, dst_port, "TCP", pkt_len)
    elif src_ip in target_ips:
        record_connection("inbound", src_ip, src_port, "TCP", pkt_len)
    else:
        return  # is packet ka current target se lena dena nahi

    # ---- Attack detection: sirf tab chalega jab traffic TARGET ki taraf jaa raha ho (incoming attack) ----
    if dst_ip in target_ips:
        port_activity[(src_ip, dst_ip)].append((now, dst_port))
        check_port_scan(src_ip, dst_ip)

        if pkt.haslayer('Raw'):
            request_activity[(src_ip, dst_ip)].append(now)
            check_brute_force(src_ip, dst_ip)


def start_sniffing():
    sniff(iface=IFACE, filter="tcp", prn=process_packet, store=False)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts")
def api_alerts():
    with alerts_lock:
        return jsonify(alerts)


@app.route("/api/connections")
def api_connections():
    cutoff = time.time() - CONNECTION_STALE_AFTER
    with connections_lock:
        stale_keys = [k for k, v in connections.items() if v["last_seen"] < cutoff]
        for k in stale_keys:
            del connections[k]

        result = []
        for (peer_ip, port, proto), data in connections.items():
            result.append({
                "peer_ip": peer_ip,
                "port": port,
                "protocol": proto,
                "direction": data["direction"],
                "packets": data["packets"],
                "bytes": data["bytes"],
                "last_seen": time.strftime("%H:%M:%S", time.localtime(data["last_seen"]))
            })
        result.sort(key=lambda x: x["last_seen"], reverse=True)
        return jsonify(result)


@app.route("/api/target", methods=["GET"])
def api_get_target():
    with target_lock:
        return jsonify({"domain": current_target["domain"], "ips": list(current_target["ips"])})


@app.route("/api/target", methods=["POST"])
def api_set_target():
    data = request.get_json()
    domain_or_ip = data.get("target", "").strip()
    if not domain_or_ip:
        return jsonify({"error": "target required"}), 400

    try:
        # agar valid IP hai to seedha use karo, warna resolve karo
        socket.inet_aton(domain_or_ip)
        resolved_ips = {domain_or_ip}
        domain_label = domain_or_ip
    except socket.error:
        try:
            resolved_ips = set(socket.gethostbyname_ex(domain_or_ip)[2])
            domain_label = domain_or_ip
        except socket.gaierror:
            return jsonify({"error": f"Could not resolve '{domain_or_ip}'"}), 400

    with target_lock:
        current_target["domain"] = domain_label
        current_target["ips"] = resolved_ips

    # naya target set hone par purana connection/alert history clear karo
    with connections_lock:
        connections.clear()
    with alerts_lock:
        alerts.clear()
    alerted_portscan.clear()
    alerted_bruteforce.clear()
    port_activity.clear()
    request_activity.clear()

    return jsonify({"domain": domain_label, "ips": list(resolved_ips)})


if __name__ == "__main__":
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    app.run(host="0.0.0.0", port=5000)
