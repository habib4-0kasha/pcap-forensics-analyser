import sys
from collections import Counter
from datetime import datetime, timezone
from src.parser import parse_pcap
from src.conversations import build_conversations
from src.detections import run_all_detections
from src.anomaly import detect_anomalies
from src.report import build_report, write_json_report, write_text_report


def fmt(endpoint):
    ip, port = endpoint
    return f"{ip}:{port}" if port else ip


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py path\\to\\capture.pcap")
        sys.exit(1)

    packets = parse_pcap(sys.argv[1])
    if not packets:
        print("No IP packets found in this file.")
        sys.exit(0)

    start = datetime.fromtimestamp(packets[0]["timestamp"], tz=timezone.utc)
    end = datetime.fromtimestamp(packets[-1]["timestamp"], tz=timezone.utc)

    print(f"\nPackets parsed : {len(packets)}")
    print(f"Capture start  : {start:%Y-%m-%d %H:%M:%S} UTC")
    print(f"Capture end    : {end:%Y-%m-%d %H:%M:%S} UTC")

    print("\nProtocols:")
    for proto, count in Counter(p["protocol"] for p in packets).most_common():
        print(f"  {proto:<6} {count}")

    print("\nTop 5 talkers (by packets sent):")
    for ip, count in Counter(p["src"] for p in packets).most_common(5):
        print(f"  {ip:<40} {count}")

    queries = [p["dns_query"] for p in packets if p["dns_query"] and not p["dns_is_response"]]
    nxdomain = sum(1 for p in packets if p["dns_rcode"] == 3)

    print(f"\nDNS queries seen: {len(queries)}")
    print(f"NXDOMAIN responses (domain doesn't exist): {nxdomain}")
    for name, count in Counter(queries).most_common(10):
        print(f"  {name:<50} {count}")

    convs = build_conversations(packets)
    print(f"\nConversations: {len(convs)}")
    print("Top 5 by bytes:")
    for c in sorted(convs, key=lambda c: c["bytes"], reverse=True)[:5]:
        print(f"  {c['protocol']:<4} {fmt(c['endpoint_a'])} <-> {fmt(c['endpoint_b'])}")
        print(f"       {c['packets']} packets, {c['bytes']} bytes "
              f"({c['bytes_a_to_b']} out / {c['bytes_b_to_a']} in)")

    rule_findings = run_all_detections(packets)
    ml_findings, ml_note = detect_anomalies(packets, rule_findings)
    findings = rule_findings + ml_findings

    print(f"\n{ml_note}")
    print(f"Detections: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['type']}: {f['src']} -> {f['target']}")
        print(f"       {f['detail']}")

    report = build_report(sys.argv[1], packets, convs, findings)
    print("\n[+] Text report saved to :", write_text_report(report))
    print("[+] JSON report saved to :", write_json_report(report))


if __name__ == "__main__":
    main()