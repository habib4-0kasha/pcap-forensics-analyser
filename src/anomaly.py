import statistics
from collections import Counter, defaultdict

from src.detections import shannon_entropy, SKIP_SUFFIXES

MIN_HOSTS = 10   # below this there is no meaningful "normal" to compare against

FEATURES = [
    ("queries", "DNS queries sent"),
    ("unique_ratio", "share of distinct domains"),
    ("avg_name_length", "average domain length"),
    ("avg_entropy", "average domain randomness"),
    ("nxdomain_ratio", "share of failed lookups"),
    ("top_domain_share", "share of lookups to one domain"),
]


def build_host_features(packets):
    """One row of numbers per client host that sent DNS queries."""
    sent = defaultdict(list)
    failed = Counter()
    for p in packets:
        if p["dns_query"] and not p["dns_is_response"]:
            sent[p["src"]].append(p["dns_query"])
        elif p["dns_rcode"] == 3:
            failed[p["dst"]] += 1

    hosts, rows = [], []
    for host, names in sent.items():
        names = [n for n in names if not n.lower().endswith(SKIP_SUFFIXES)]
        if not names:
            continue
        total = len(names)
        entropies = [shannon_entropy(n.split(".")[0].lower()) for n in names]
        hosts.append(host)
        rows.append([
            total,
            len(set(names)) / total,
            statistics.mean(len(n) for n in names),
            statistics.mean(entropies),
            failed[host] / total,
            Counter(names).most_common(1)[0][1] / total,
        ])
    return hosts, rows


def detect_anomalies(packets, rule_findings, contamination=0.1):
    """Flag hosts whose DNS behaviour differs from the rest of the capture."""
    from sklearn.ensemble import IsolationForest

    hosts, rows = build_host_features(packets)
    if len(hosts) < MIN_HOSTS:
        return [], f"ML skipped: only {len(hosts)} DNS clients (need {MIN_HOSTS}+ to learn what is normal)"

    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
    labels = model.fit_predict(rows)
    scores = model.score_samples(rows)  # lower = more anomalous

    medians = [statistics.median(col) for col in zip(*rows)]
    spreads = [statistics.pstdev(col) or 1.0 for col in zip(*rows)]
    rule_hosts = {f["src"] for f in rule_findings}

    findings = []
    for i, host in enumerate(hosts):
        if labels[i] != -1:
            continue
        # which features are furthest from the typical host?
        devs = sorted(((abs(rows[i][j] - medians[j]) / spreads[j], j) for j in range(len(FEATURES))),
                      reverse=True)[:3]
        why = "; ".join(
            f"{FEATURES[j][1]} {rows[i][j]:.2f} (typical {medians[j]:.2f})" for _, j in devs
        )
        agree = "also flagged by rules" if host in rule_hosts else "NOT flagged by any rule"
        findings.append({
            "type": "ML anomaly",
            "severity": "INFO",
            "src": host,
            "target": "DNS behaviour",
            "detail": f"score {scores[i]:.3f}; {agree}. Most unusual: {why}",
        })
    findings.sort(key=lambda f: float(f["detail"].split()[1].rstrip(";")))
    return findings, f"ML analysed {len(hosts)} DNS clients"