from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR


def parse_pcap(filepath):
    """Read a PCAP file and return a list of simplified packet records."""
    records = []
    with PcapReader(filepath) as reader:
        for pkt in reader:
            record = parse_packet(pkt)
            if record:
                records.append(record)
    return records


def parse_packet(pkt):
    """Turn one raw packet into a flat dictionary of the fields we care about."""
    if pkt.haslayer(IP):
        ip = pkt[IP]
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
    else:
        return None  # not an IP packet (e.g. ARP), skip it for now

    record = {
        "timestamp": float(pkt.time),
        "src": ip.src,
        "dst": ip.dst,
        "protocol": "OTHER",
        "sport": None,
        "dport": None,
        "flags": None,
        "size": len(pkt),
        "dns_query": None,
        "dns_rcode": None,
        "dns_is_response": False,
    }

    if pkt.haslayer(TCP):
        record["protocol"] = "TCP"
        record["sport"] = pkt[TCP].sport
        record["dport"] = pkt[TCP].dport
        record["flags"] = str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        record["protocol"] = "UDP"
        record["sport"] = pkt[UDP].sport
        record["dport"] = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        record["protocol"] = "ICMP"

    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        record["dns_is_response"] = (dns.qr == 1)
        if pkt.haslayer(DNSQR):
            name = pkt[DNSQR].qname
            if isinstance(name, bytes):
                name = name.decode(errors="ignore")
            record["dns_query"] = name.rstrip(".")
        if dns.qr == 1:  # qr=1 means this packet is a DNS response
            record["dns_rcode"] = dns.rcode

    return record