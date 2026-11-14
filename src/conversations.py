def build_conversations(packets):
    """Group packets into bidirectional conversations between two endpoints."""
    convs = {}

    for p in packets:
        a = (p["src"], p["sport"])
        b = (p["dst"], p["dport"])
        key = (p["protocol"],) + tuple(sorted([a, b], key=str))

        if key not in convs:
            convs[key] = {
                "protocol": p["protocol"],
                "endpoint_a": a,
                "endpoint_b": b,
                "packets": 0,
                "bytes": 0,
                "bytes_a_to_b": 0,
                "bytes_b_to_a": 0,
                "start": p["timestamp"],
                "end": p["timestamp"],
            }

        c = convs[key]
        c["packets"] += 1
        c["bytes"] += p["size"]
        if (p["src"], p["sport"]) == c["endpoint_a"]:
            c["bytes_a_to_b"] += p["size"]
        else:
            c["bytes_b_to_a"] += p["size"]
        c["start"] = min(c["start"], p["timestamp"])
        c["end"] = max(c["end"], p["timestamp"])

    return list(convs.values())