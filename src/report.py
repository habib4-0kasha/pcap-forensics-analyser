import hashlib
import json
import os
from collections import Counter
from datetime import datetime, timezone


def file_sha256(filepath):
    """Hash the capture file so the report proves which evidence it describes."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def build_report(filepath, packets, conversations, findings):
    """Collect everything into one structured dictionary (the single source of truth)."""
    ts = lambda x: datetime.fromtimestamp(x, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    queries = [p["dns_query"] for p in packets if p["dns_query"] and not p["dns_is_response"]]

    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "evidence": {
            "filename": os.path.basename(filepath),
            "size_bytes": os.path.getsize(filepath),
            "sha256": file_sha256(filepath),
        },
        "summary": {
            "packets": len(packets),
            "capture_start": ts(packets[0]["timestamp"]),
            "capture_end": ts(packets[-1]["timestamp"]),
            "protocols": dict(Counter(p["protocol"] for p in packets)),
            "top_talkers": Counter(p["src"] for p in packets).most_common(5),
            "conversations": len(conversations),
            "dns_queries": len(queries),
            "nxdomain_responses": sum(1 for p in packets if p["dns_rcode"] == 3),
        },
        "findings": findings,
    }


def write_json_report(report, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"report_{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
    return path


def write_text_report(report, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"report_{stamp}.txt")
    ev, s = report["evidence"], report["summary"]

    lines = [
        "=" * 64,
        "      NETWORK FORENSICS REPORT",
        "=" * 64,
        f"Generated : {report['generated']}",
        "",
        "[ EVIDENCE ]",
        f"  File      : {ev['filename']}",
        f"  Size      : {ev['size_bytes']} bytes",
        f"  SHA-256   : {ev['sha256']}",
        "",
        "[ SUMMARY ]",
        f"  Packets        : {s['packets']}",
        f"  Capture window : {s['capture_start']}  to  {s['capture_end']}",
        f"  Protocols      : {s['protocols']}",
        f"  Conversations  : {s['conversations']}",
        f"  DNS queries    : {s['dns_queries']}  (NXDOMAIN responses: {s['nxdomain_responses']})",
        "  Top talkers    :",
    ]
    lines += [f"    {ip:<40} {n} packets" for ip, n in s["top_talkers"]]

    lines += ["", f"[ FINDINGS: {len(report['findings'])} ]"]
    if not report["findings"]:
        lines.append("  No suspicious activity matched the detection rules.")
    for i, f in enumerate(report["findings"], 1):
        lines += [
            f"  {i}. [{f['severity']}] {f['type']}",
            f"     Source  : {f['src']}",
            f"     Target  : {f['target']}",
            f"     Evidence: {f['detail']}",
            "",
        ]

    lines += [
        "-" * 64,
        "Findings are rule-based indicators, not proof of compromise.",
        "Each should be reviewed by an analyst against the raw capture.",
        "=" * 64,
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return path