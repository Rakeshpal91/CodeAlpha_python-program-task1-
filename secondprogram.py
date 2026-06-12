from scapy.all import sniff, IP

def packet_handler(packet):
    if packet.haslayer(IP):
        proto = packet[IP].proto

        if proto == 6:
            name = "TCP"
        elif proto == 17:
            name = "UDP"
        elif proto == 1:
            name = "ICMP"
        else:
            name = f"Unknown({proto})"

        print(
            f"{packet[IP].src} -> "
            f"{packet[IP].dst} | "
            f"{name}"
        )

sniff(prn=packet_handler, store=False)