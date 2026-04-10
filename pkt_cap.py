from scapy.all import IP, TCP, UDP, sniff
def process_packet(packet):
    if IP in packet:
        print("Source:",packet[IP].src)
        print("Destination:",packet[IP].dst)
        print("Protocol:",packet[IP].proto)
        if TCP in packet:
            print("TCP packet")
        elif UDP in packet:
            print("UDP packet")
        print("Size:", len(packet))
        print("------")
sniff(prn=process_packet, count=5)