from scapy.all import sniff, TCP, IP

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        if packet[TCP].flags == 'S':  # Looking for SYN packets
            print(f"SYN Packet Detected: Source IP {packet[IP].src}, Destination IP {packet[IP].dst}, Port {packet[TCP].dport}")

def main():
    print("Starting intrusion detection system...")
    try:
        sniff(filter="tcp", prn=packet_callback, store=0)  # filter for TCP packets only
    except PermissionError:
        print("Permission denied: Requires administrative privileges to run packet sniffing.")

if __name__ == "__main__":
    main()
