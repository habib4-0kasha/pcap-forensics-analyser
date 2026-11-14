import math
import statistics
from collections import defaultdict

PORT_SCAN_THRESHOLD = 20     # distinct ports hit by one source on one target
NXDOMAIN_THRESHOLD = 10      # failed lookups by one client
ENTROPY_THRESHOLD = 3.5      # how random-looking a domain label is
MIN_LABEL_LENGTH = 12        # ignore short labels, entropy is meaningless on them
LONG_QUERY_LENGTH = 60       # total characters in one DNS name
BEACON_MIN_QUERIES = 5       # repeats needed before we look for a rhythm
BEACON_MAX_JITTER = 0.1      # gaps within 10% of each other = clockwork
MAX_VOWEL_RATIO = 0.25       # real words are vowel-rich, random strings are not
SKIP_SUFFIXES = (".arpa", ".local")


def shannon_entropy(text):
    """Bits of randomness per character. Higher means more random-looking."""
    if not text:
        return 0.0
    counts = defaultdict(int)
    for ch in text:
        counts[ch] += 1
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())

def looks_random(label):
    """High entropy AND few vowels: random text, not a long real word like 'stackoverflow'."""
    vowels = sum(ch in "aeiou" for ch in label) / len(label)
    return shannon_entropy(label) >= ENTROPY_THRESHOLD and vowels < MAX_VOWEL_RATIO


def detect_port_scans(packets, threshold=PORT_SCAN_THRESHOLD):
    """Flag sources that send SYN-only packets to many different ports on one target."""
    targets = defaultdict(lambda: {"ports": set(), "syns": 0, "first": None, "last": None})

    for p in packets:
        if p["protocol"] != "TCP" or p["flags"] != "S":
            continue
        entry = targets[(p["src"], p["dst"])]
        entry["ports"].add(p["dport"])
        entry["syns"] += 1
        ts = p["timestamp"]
        entry["first"] = ts if entry["first"] is None else min(entry["first"], ts)
        entry["last"] = ts if entry["last"] is None else max(entry["last"], ts)

    findings = []
    for (src, dst), e in targets.items():
        if len(e["ports"]) >= threshold:
            duration = round(e["last"] - e["first"], 2)
            sample = sorted(e["ports"])[:5]
            findings.append({
                "type": "Port scan",
                "severity": "HIGH",
                "src": src,
                "target": dst,
                "detail": f"{len(e['ports'])} ports probed with {e['syns']} SYN packets "
                          f"in {duration}s (first ports: {sample})",
            })
    return findings


def detect_nxdomain_bursts(packets, threshold=NXDOMAIN_THRESHOLD):
    """Flag clients that get many 'domain doesn't exist' answers."""
    failures = defaultdict(list)
    for p in packets:
        if p["dns_rcode"] == 3 and p["dns_query"]:
            failures[p["dst"]].append(p["dns_query"])  # responses go TO the client

    findings = []
    for client, names in failures.items():
        if len(names) >= threshold:
            findings.append({
                "type": "NXDOMAIN burst",
                "severity": "MEDIUM",
                "src": client,
                "target": "DNS resolver",
                "detail": f"{len(names)} failed lookups across {len(set(names))} "
                          f"distinct domains (e.g. {names[0]})",
            })
    return findings


def detect_suspicious_domains(packets):
    """Flag random-looking domains and unusually long DNS names."""
    flagged = defaultdict(list)
    for p in packets:
        name = p["dns_query"]
        if not name or p["dns_is_response"] or name.lower().endswith(SKIP_SUFFIXES):
            continue
        labels = name.split(".")
        reason = None
        if len(name) >= LONG_QUERY_LENGTH:
            reason = "Unusually long DNS query"
        elif any(len(l) >= MIN_LABEL_LENGTH and looks_random(l.lower())
                for l in labels[:-1]):
            reason = "High-entropy domain"
        if reason:
            flagged[(p["src"], reason)].append(name)

    findings = []
    for (src, reason), names in flagged.items():
        unique = sorted(set(names))
        findings.append({
            "type": reason,
            "severity": "MEDIUM",
            "src": src,
            "target": "DNS",
            "detail": f"{len(unique)} distinct names (e.g. {unique[0]})",
        })
    return findings


def detect_beaconing(packets, min_queries=BEACON_MIN_QUERIES, max_jitter=BEACON_MAX_JITTER):
    """Flag hosts that look up the same domain at near-perfectly regular intervals."""
    times = defaultdict(list)
    for p in packets:
        if p["dns_query"] and not p["dns_is_response"]:
            times[(p["src"], p["dns_query"])].append(p["timestamp"])

    findings = []
    for (src, name), stamps in times.items():
        if len(stamps) < min_queries:
            continue
        stamps.sort()
        gaps = [b - a for a, b in zip(stamps, stamps[1:])]
        mean_gap = statistics.mean(gaps)
        if mean_gap < 1:
            continue
        jitter = statistics.pstdev(gaps) / mean_gap
        if jitter <= max_jitter:
            findings.append({
                "type": "Beaconing",
                "severity": "HIGH",
                "src": src,
                "target": name,
                "detail": f"{len(stamps)} lookups roughly every {round(mean_gap)}s "
                          f"(timing variation {jitter:.1%})",
            })
    return findings


def run_all_detections(packets):
    """Run every detection and return one combined list of findings."""
    findings = []
    findings += detect_port_scans(packets)
    findings += detect_nxdomain_bursts(packets)
    findings += detect_suspicious_domains(packets)
    findings += detect_beaconing(packets)
    return findings