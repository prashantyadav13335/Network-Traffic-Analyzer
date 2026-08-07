from scapy.all import sniff, TCP, IP
from collections import defaultdict
import time

TARGET_IP = "172.17.0.2"      # jis container/machine ko protect kar rahe ho
TARGET_PORT = 80

PORT_THRESHOLD = 10
PORT_TIME_WINDOW = 10

REQUEST_THRESHOLD = 5
REQUEST_TIME_WINDOW = 15

# in-memory sliding window state
port_activity = defaultdict(list)      # src_ip -> [(timestamp, dst_port), ...]
request_activity = defaultdict(list)   # src_ip -> [timestamp, ...]

alerted_portscan = set()   # taaki same IP ke liye baar baar alert na aaye
alerted_bruteforce = set()

def clean_old(events, window):
    """Purane (window se bahar) events hata do"""
    cutoff = time.time() - window
    return [e for e in events if (e[0] if isinstance(e, tuple) else e) >= cutoff]

def check_port_scan(src_ip):
    events = clean_old(port_activity[src_ip], PORT_TIME_WINDOW)
    port_activity[src_ip] = events
    distinct_ports = set(p for _, p in events)
    if len(distinct_ports) >= PORT_THRESHOLD and src_ip not in alerted_portscan:
        print(f"[!!! LIVE ALERT !!!] Port Scan detected from {src_ip} "
              f"-> {len(distinct_ports)} distinct ports within {PORT_TIME_WINDOW}s")
        alerted_portscan.add(src_ip)

def check_brute_force(src_ip):
    events = clean_old(request_activity[src_ip], REQUEST_TIME_WINDOW)
    request_activity[src_ip] = events
    if len(events) >= REQUEST_THRESHOLD and src_ip not in alerted_bruteforce:
        print(f"[!!! LIVE ALERT !!!] Brute-Force detected from {src_ip} "
              f"-> {len(events)} requests within {REQUEST_TIME_WINDOW}s")
        alerted_bruteforce.add(src_ip)

def process_packet(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    if pkt[IP].dst != TARGET_IP:
        return

    src_ip = pkt[IP].src
    dst_port = pkt[TCP].dport
    now = time.time()

    # port scan tracking
    port_activity[src_ip].append((now, dst_port))
    check_port_scan(src_ip)

    # brute force tracking (sirf payload wale requests target port pe)
    if dst_port == TARGET_PORT and pkt.haslayer('Raw'):
        request_activity[src_ip].append(now)
        check_brute_force(src_ip)

if __name__ == "__main__":
    print(f"Live monitoring started for target {TARGET_IP} ... (Ctrl+C to stop)")
    sniff(iface="any", filter="tcp", prn=process_packet, store=False)
