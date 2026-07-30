from scapy.all import rdpcap, TCP, IP
from collections import defaultdict

PCAP_FILE = "portscan.pcap"
TARGET_IP = "172.17.0.2"   # sirf isi target ki taraf jaane wala traffic count karenge
PORT_THRESHOLD = 10
TIME_WINDOW = 10

def detect_port_scan(pcap_file):
    print(f"Loading {pcap_file} ... (bade files mein time lagega)")
    packets = rdpcap(pcap_file)
    print(f"Total packets loaded: {len(packets)}")

    activity = defaultdict(list)

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            # Sirf woh packets jo TARGET_IP ki taraf ja rahe hain
            # (replies exclude, background/unrelated traffic exclude)
            if pkt[IP].dst != TARGET_IP:
                continue
            src_ip = pkt[IP].src
            dst_port = pkt[TCP].dport
            timestamp = pkt.time
            activity[src_ip].append((timestamp, dst_port))

    print(f"\n--- Port Scan Detection Results (target: {TARGET_IP}) ---")
    found_any = False

    for src_ip, events in activity.items():
        events.sort(key=lambda x: x[0])
        n = len(events)

        for i in range(n):
            window_start = events[i][0]
            ports_in_window = set()
            for j in range(i, n):
                if events[j][0] - window_start <= TIME_WINDOW:
                    ports_in_window.add(events[j][1])
                else:
                    break

            if len(ports_in_window) >= PORT_THRESHOLD:
                found_any = True
                print(f"[ALERT] Possible port scan from {src_ip} "
                      f"-> {len(ports_in_window)} distinct ports on {TARGET_IP} "
                      f"within {TIME_WINDOW}s window")
                break

    if not found_any:
        print("No port scan pattern detected with current threshold.")

if __name__ == "__main__":
    detect_port_scan(PCAP_FILE)