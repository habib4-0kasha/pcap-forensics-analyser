import random
import string
from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap

random.seed(7)
RESOLVER = "10.0.0.2"
COMMON = ["google.com", "www.google.com", "youtube.com", "github.com", "docs.python.org",
          "www.python.org", "wikipedia.org", "stackoverflow.com", "microsoft.com",
          "office.com", "outlook.com", "slack.com", "zoom.us", "cloudflare.com",
          "amazon.com", "linkedin.com", "apple.com", "netflix.com", "dropbox.com",
          "mozilla.org", "bbc.co.uk", "reddit.com", "twitter.com", "adobe.com", "npmjs.com"]
WEIGHTS = [1 / (i + 1) for i in range(len(COMMON))]

events = []  # (time, packet)


def rand_label(n):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def lookup(t, src, name, rcode=0):
    qid, sport = random.randint(0, 65535), random.randint(1024, 65000)
    q = Ether() / IP(src=src, dst=RESOLVER) / UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=name))
    r = (Ether() / IP(src=RESOLVER, dst=src) / UDP(sport=53, dport=sport)
         / DNS(id=qid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name)))
    q.time, r.time = t, t + 0.02
    events.extend([(t, q), (t + 0.02, r)])


T0 = 1_700_000_000.0

# 30 normal hosts: irregular browsing, occasional typo
for i in range(30):
    host = f"10.0.1.{10 + i}"
    for _ in range(random.randint(30, 80)):
        t = T0 + random.uniform(0, 600)
        if random.random() < 0.02:
            lookup(t, host, rand_label(random.randint(4, 7)) + ".com", rcode=3)
        else:
            lookup(t, host, random.choices(COMMON, WEIGHTS)[0])

# Anomalous host A: generated domains, mostly failing
for _ in range(60):
    lookup(T0 + random.uniform(0, 600), "10.0.1.201", rand_label(16) + ".com",
           rcode=3 if random.random() < 0.7 else 0)

# Anomalous host B: tunnelling, long names
for _ in range(12):
    lookup(T0 + random.uniform(0, 600), "10.0.1.202",
           rand_label(30) + "." + rand_label(30) + ".tunnel-test.net")

# Anomalous host C: beaconing, one domain over and over
for k in range(60):
    lookup(T0 + k * 10 + random.uniform(-0.2, 0.2), "10.0.1.203", "updates.cdn-sync.net")

events.sort(key=lambda e: e[0])
wrpcap("samples/synthetic_ml.pcap", [p for _, p in events])
print(f"Wrote {len(events)} packets")