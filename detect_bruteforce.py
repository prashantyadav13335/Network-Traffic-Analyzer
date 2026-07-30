from scapy.all import rdpcap, TCP, IP
from collections import defaultdict

PCAP_FILE = "bruteforce.pcap"
TARGET_IP = "172.17.0.2"
TARGET_PORT = 80
REQUEST_THRESHOLD = 5    # kitne login attempts thoda time mein suspicious
TIME_WINDOW = 15         # seconds

def detect_brute_force(pcap_file):
    print(f"Loading {pcap_file} ... (bade files mein time lagega)")
    packets = rdpcap(pcap_file)
    print(f"Total packets loaded: {len(packets)}")

    # sirf woh TCP packets jo target ke http port pe request bhej rahe hain,
    # aur jinme actual data (payload) hai — matlab POST request ka data
    activity = defaultdict(list)

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            if pkt[IP].dst != TARGET_IP:
                continue
            if pkt[TCP].dport != TARGET_PORT:
                continue
            if not pkt.haslayer('Raw'):
                continue  # sirf payload wale packets (actual requests) count karo

            src_ip = pkt[IP].src
            timestamp = pkt.time
            activity[src_ip].append(timestamp)

    print(f"\n--- Brute-Force Detection Results (target: {TARGET_IP}:{TARGET_PORT}) ---")
    found_any = False

    for src_ip, timestamps in activity.items():
        timestamps.sort()
        n = len(timestamps)

        for i in range(n):
            window_start = timestamps[i]
            count_in_window = 0
            for j in range(i, n):
                if timestamps[j] - window_start <= TIME_WINDOW:
                    count_in_window += 1
                else:
                    break

            if count_in_window >= REQUEST_THRESHOLD:
                found_any = True
                print(f"[ALERT] Possible brute-force from {src_ip} "
                      f"-> {count_in_window} requests within {TIME_WINDOW}s window")
                break

    if not found_any:
        print("No brute-force pattern detected with current threshold.")

if __name__ == "__main__":
    detect_brute_force(PCAP_FILE)