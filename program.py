from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_handler(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto

        if TCP in packet:
            print(f"TCP  {src}:{packet[TCP].sport} -> {dst}:{packet[TCP].dport}")
        elif UDP in packet:
            print(f"UDP  {src}:{packet[UDP].sport} -> {dst}:{packet[UDP].dport}")
        elif ICMP in packet:
            print(f"ICMP {src} -> {dst}")
        else:
            print(f"IP   {src} -> {dst} (Protocol {proto})")

print("Capturing packets... Press Ctrl+C to stop.")
sniff(prn=packet_handler, store=False)