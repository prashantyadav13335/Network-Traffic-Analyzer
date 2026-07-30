from scapy.all import rdpcap, TCP, IP
from collections import defaultdict
from datetime import datetime

TARGET_IP = "172.17.0.2"

PORTSCAN_PCAP = "portscan.pcap"
PORT_THRESHOLD = 10
PORT_TIME_WINDOW = 10

BRUTEFORCE_PCAP = "bruteforce.pcap"
TARGET_PORT = 80
REQUEST_THRESHOLD = 5
REQUEST_TIME_WINDOW = 15

REPORT_FILE = "report.txt"


def load_packets(pcap_file):
    print(f"Loading {pcap_file} ...")
    packets = rdpcap(pcap_file)
    print(f"  Total packets loaded: {len(packets)}")
    return packets


def detect_port_scan(pcap_file):
    packets = load_packets(pcap_file)
    activity = defaultdict(list)

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            if pkt[IP].dst != TARGET_IP:
                continue
            activity[pkt[IP].src].append((pkt.time, pkt[TCP].dport))

    alerts = []
    for src_ip, events in activity.items():
        events.sort(key=lambda x: x[0])
        n = len(events)
        for i in range(n):
            window_start = events[i][0]
            ports_in_window = set()
            for j in range(i, n):
                if events[j][0] - window_start <= PORT_TIME_WINDOW:
                    ports_in_window.add(events[j][1])
                else:
                    break
            if len(ports_in_window) >= PORT_THRESHOLD:
                alerts.append({
                    "type": "Port Scan",
                    "source_ip": src_ip,
                    "target": TARGET_IP,
                    "detail": f"{len(ports_in_window)} distinct ports within {PORT_TIME_WINDOW}s"
                })
                break
    return alerts


def detect_brute_force(pcap_file):
    packets = load_packets(pcap_file)
    activity = defaultdict(list)

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            if pkt[IP].dst != TARGET_IP or pkt[TCP].dport != TARGET_PORT:
                continue
            if not pkt.haslayer('Raw'):
                continue
            activity[pkt[IP].src].append(pkt.time)

    alerts = []
    for src_ip, timestamps in activity.items():
        timestamps.sort()
        n = len(timestamps)
        for i in range(n):
            window_start = timestamps[i]
            count_in_window = 0
            for j in range(i, n):
                if timestamps[j] - window_start <= REQUEST_TIME_WINDOW:
                    count_in_window += 1
                else:
                    break
            if count_in_window >= REQUEST_THRESHOLD:
                alerts.append({
                    "type": "Brute-Force",
                    "source_ip": src_ip,
                    "target": f"{TARGET_IP}:{TARGET_PORT}",
                    "detail": f"{count_in_window} requests within {REQUEST_TIME_WINDOW}s"
                })
                break
    return alerts


def generate_report(all_alerts):
    lines = []
    lines.append("=" * 60)
    lines.append("NETWORK TRAFFIC ANALYSIS REPORT")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)

    if not all_alerts:
        lines.append("\nNo malicious patterns detected.")
    else:
        lines.append(f"\nTotal alerts: {len(all_alerts)}\n")
        for idx, alert in enumerate(all_alerts, 1):
            lines.append(f"[{idx}] {alert['type']} ALERT")
            lines.append(f"    Source IP : {alert['source_ip']}")
            lines.append(f"    Target    : {alert['target']}")
            lines.append(f"    Detail    : {alert['detail']}")
            lines.append("")

    report_text = "\n".join(lines)
    print("\n" + report_text)

    with open(REPORT_FILE, "w") as f:
        f.write(report_text)
    print(f"\nReport saved to {REPORT_FILE}")


if __name__ == "__main__":
    all_alerts = []
    all_alerts.extend(detect_port_scan(PORTSCAN_PCAP))
    all_alerts.extend(detect_brute_force(BRUTEFORCE_PCAP))
    generate_report(all_alerts)