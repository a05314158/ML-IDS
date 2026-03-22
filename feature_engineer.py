import numpy as np
import math
from collections import Counter
from config import BURST_WINDOW_SECONDS
from data_structures import PacketData, FeatureVector


def shannon_entropy(data: list) -> float:
    if not data: return 0.0
    counts = Counter(data)
    total = len(data)
    probs = [c / total for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs)


def extract_features(packet_snapshot: list[PacketData], window_end_time) -> FeatureVector:
    if not packet_snapshot:
        return FeatureVector(window_end_time, window_end_time, [0.0] * 13, {'Total_Packets': 0})

    sorted_pkts = sorted(packet_snapshot, key=lambda p: p.timestamp)
    total_pkts = len(sorted_pkts)
    lengths = [p.length for p in sorted_pkts]
    dst_ports = [p.dst_port for p in sorted_pkts if p.dst_port is not None]
    ts_vals = np.array([p.timestamp.timestamp() for p in sorted_pkts])

    tcp_pkts = [p for p in sorted_pkts if p.is_tcp]
    udp_pkts = [p for p in sorted_pkts if p.is_udp]

    # Стат. признаки 1-10
    f1 = float(total_pkts)
    f2 = float(sum(lengths))
    f3 = float(np.median(lengths))
    f4 = shannon_entropy(dst_ports)
    syns = sum(1 for p in tcp_pkts if p.tcp_flags.get('SYN') and not p.tcp_flags.get('ACK'))
    f5 = syns / len(tcp_pkts) if tcp_pkts else 0.0
    f6 = len(udp_pkts) / f1
    f7 = float(len(set(p.src_ip for p in sorted_pkts)))
    f8 = len(tcp_pkts) / f1
    f9 = (total_pkts - len(tcp_pkts) - len(udp_pkts)) / f1
    f10 = float(len(set(p.dst_ip for p in sorted_pkts)))

    # Временные признаки 11-13
    if total_pkts > 1:
        diffs = np.diff(ts_vals)
        f11, f12 = float(np.mean(diffs)), float(np.std(diffs))
        f13 = float(max([np.sum((ts_vals >= (t - BURST_WINDOW_SECONDS)) & (ts_vals <= t)) for t in ts_vals]))
    else:
        f11 = f12 = f13 = 0.0

    return FeatureVector(
        sorted_pkts[0].timestamp, window_end_time,
        [f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13],
        {'Total_Packets': total_pkts}
    )