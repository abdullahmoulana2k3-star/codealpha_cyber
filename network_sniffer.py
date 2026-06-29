from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime
packet_count = 0

def analyze_packet(packet):
    """This function runs every time a packet is captured."""
    global packet_count
    packet_count += 1

    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    if IP in packet:
        src_ip = packet[IP].src       # source of the IP
        dst_ip = packet[IP].dst       # destination of IP
        protocol = ""
        extra_info = ""
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            extra_info = f"Ports: {src_port} → {dst_port}"

        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            extra_info = f"Ports: {src_port} → {dst_port}"

        elif ICMP in packet:
            protocol = "ICMP"
            extra_info = "Ping/Network test packet"

        else:
            protocol = "OTHER"
        payload = ""
        if packet.haslayer("Raw"):
            raw_data = packet["Raw"].load
            try:
                payload = raw_data.decode("utf-8", errors="ignore")[:50]  
                payload = f" | Payload: {payload}"
            except:
                payload = " | Payload: [binary data]"
        print(f"[{timestamp}] Packet #{packet_count}")
        print(f"  Protocol : {protocol}")
        print(f"  Source   : {src_ip}")
        print(f"  Dest     : {dst_ip}")
        print(f"  Info     : {extra_info}{payload}")
        print("-" * 60)
def start_sniffer(packet_limit=50):
    """Start capturing packets."""
    print("=" * 60)
    print("   CodeAlpha - Basic Network Sniffer")
    print("   Capturing packets... Press Ctrl+C to stop")
    print("=" * 60)
    print()

    try:
        # sniff() = captures packets and calls analyze_packet for each one
        # count = packet_limit means it stops after that many packets
        sniff(prn=analyze_packet, count=packet_limit, store=False)

    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")

    print(f"\n[✓] Done! Total packets captured: {packet_count}")



if __name__ == "__main__":
    start_sniffer(packet_limit=50)  
