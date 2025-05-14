from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, get_working_if
from datetime import datetime

try:
    INTERFACE = get_working_if()
except Exception:
    print("[!] Couldn't auto-detect a network interface.")
    interfaces = get_if_list()
    print("[!] Please choose one of the following manually:")
    for i in interfaces:
        print("-", i)
    exit()

print(f"[+] Starting packet sniffer on interface: {INTERFACE}")

log_file = open("log.txt", "a")
def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = "OTHER"

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {protocol} Packet: {src_ip} -> {dst_ip}"
        print(log_entry)
        log_file.write(log_entry + "\n")

try:
    sniff(prn=process_packet, iface=INTERFACE, store=False)
except KeyboardInterrupt:
    print("\n[!] Sniffing stopped by user.")
finally:
    log_file.close()
