import random
from scapy.all import Ether, IP, TCP, wrpcap

random.seed(1)
packets = []
t = 1_700_000_000.0


def add(pkt):
    global t
    pkt.time = t
    t += random.uniform(0.001, 0.05)
    packets.append(pkt)


ATTACKER = "10.0.0.66"
TARGET = "10.0.0.5"
CLIENT = "10.0.0.20"
OPEN_PORTS = {22, 80}

# 1. Normal traffic: one client making a few web connections
for i in range(5):
    sport = 50000 + i
    add(Ether() / IP(src=CLIENT, dst=TARGET) / TCP(sport=sport, dport=80, flags="S"))
    add(Ether() / IP(src=TARGET, dst=CLIENT) / TCP(sport=80, dport=sport, flags="SA"))
    add(Ether() / IP(src=CLIENT, dst=TARGET) / TCP(sport=sport, dport=80, flags="A"))

# 2. Synthetic port scan: one source probing ports 1-100 on one target
for port in range(1, 101):
    add(Ether() / IP(src=ATTACKER, dst=TARGET) / TCP(sport=44444, dport=port, flags="S"))
    reply = "SA" if port in OPEN_PORTS else "RA"
    add(Ether() / IP(src=TARGET, dst=ATTACKER) / TCP(sport=port, dport=44444, flags=reply))

wrpcap("samples/synthetic_scan.pcap", packets)
print(f"Wrote {len(packets)} packets")