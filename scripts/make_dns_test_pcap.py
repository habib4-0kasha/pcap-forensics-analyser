import random
import string
from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap

random.seed(2)
packets = []
t = 1_700_000_000.0

CLIENT = "10.0.0.20"
INFECTED = "10.0.0.77"
RESOLVER = "10.0.0.2"


def add(pkt):
    global t
    pkt.time = t
    t += 0.01
    packets.append(pkt)


def lookup(src, name, rcode=0):
    qid = random.randint(0, 65535)
    sport = random.randint(1024, 65000)
    add(Ether() / IP(src=src, dst=RESOLVER) / UDP(sport=sport, dport=53)
        / DNS(id=qid, rd=1, qd=DNSQR(qname=name)))
    add(Ether() / IP(src=RESOLVER, dst=src) / UDP(sport=53, dport=sport)
        / DNS(id=qid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name)))


def random_label(n):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# 1. Normal browsing: a few ordinary lookups at irregular times
for name in ["google.com", "www.python.org", "github.com", "docs.python.org", "wikipedia.org"]:
    lookup(CLIENT, name)
    t += random.uniform(1, 30)

# 2. Infected host tries 30 random domains that don't exist (NXDOMAIN burst)
for _ in range(30):
    lookup(INFECTED, random_label(16) + ".com", rcode=3)
    t += random.uniform(0.1, 1)

# 3. DNS tunnelling style: very long names
for _ in range(3):
    lookup(INFECTED, random_label(30) + "." + random_label(30) + ".tunnel-test.net")
    t += 2

# 4. Beaconing: same domain every ~60 seconds, tiny jitter
for _ in range(10):
    lookup(INFECTED, "updates.cdn-sync.net")
    t += 60 + random.uniform(-0.5, 0.5)

wrpcap("samples/synthetic_dns.pcap", packets)
print(f"Wrote {len(packets)} packets")