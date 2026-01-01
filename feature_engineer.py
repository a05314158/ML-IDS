# feature_engineer.py
import numpy as np
import math
from typing import List
from collections import Counter
from datetime import datetime

from data_structures import PacketData, FeatureVector


def shannon_entropy(data: List) -> float:
    """
    Расчет энтропии Шеннона для списка элементов.
    Используется для Entropy_DPort.
    """
    if not data:
        return 0.0

    # 1. Считаем частоту каждого уникального элемента
    counts = Counter(data)
    total = len(data)

    # 2. Расчет вероятности и логарифма
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        if probability > 0:
            # Используем log2, как это принято в сетевом анализе
            entropy -= probability * math.log2(probability)

    return entropy


def extract_features(packet_snapshot: List[PacketData], window_end_time: datetime) -> FeatureVector:
    """
    Преобразует список сырых пакетов (за Time-Window) в единый вектор признаков (10 признаков).
    (Фаза 3.2 + Улучшения)
    """
    if not packet_snapshot:
        # Если пакетов нет, возвращаем вектор из нулей для ML-модели
        return FeatureVector(
            start_time=window_end_time,
            end_time=window_end_time,
            features=[0.0] * 10,  # <--- Теперь 10 нулей
            source_info={'Total_Packets': 0}
        )

    # Инициализация структур для расчета
    total_packets = len(packet_snapshot)
    total_bytes = 0
    packet_lengths = []
    dst_ports = []
    tcp_packets = []
    udp_packets = []

    # НОВЫЕ:
    other_ip_packets = 0  # Для ICMP и других
    unique_src_ips = set()
    unique_dst_ips = set()  # Улучшение 2

    start_time = packet_snapshot[0].timestamp

    # Итерация и сбор данных
    for pkt in packet_snapshot:
        total_bytes += pkt.length
        packet_lengths.append(pkt.length)
        unique_src_ips.add(pkt.src_ip)
        unique_dst_ips.add(pkt.dst_ip)

        if pkt.is_tcp:
            tcp_packets.append(pkt)
            if pkt.dst_port is not None:
                dst_ports.append(pkt.dst_port)
        elif pkt.is_udp:
            udp_packets.append(pkt)
            if pkt.dst_port is not None:
                dst_ports.append(pkt.dst_port)
        else:
            other_ip_packets += 1

            # ------------------- Расчет 10 Признаков -------------------

    # 1. Total_Packets
    feature_1 = float(total_packets)

    # 2. Total_Bytes
    feature_2 = float(total_bytes)

    # 3. Pkt_Length_Median
    feature_3 = np.median(packet_lengths) if packet_lengths else 0.0

    # 4. Entropy_DPort
    feature_4 = shannon_entropy(dst_ports)

    # 5. SYN_Ratio (Отношение SYN-пакетов к общему числу TCP-пакетов)
    syn_count = sum(1 for pkt in tcp_packets if pkt.tcp_flags.get('SYN', False) and not pkt.tcp_flags.get('ACK', False))
    feature_5 = syn_count / len(tcp_packets) if len(tcp_packets) > 0 else 0.0

    # 6. UDP_Ratio (Отношение UDP-пакетов к общему числу пакетов - старый)
    feature_6 = len(udp_packets) / total_packets

    # 7. Unique_Src_IPs
    feature_7 = float(len(unique_src_ips))

    # *** НОВЫЕ ПРИЗНАКИ (Улучшения) ***

    # 8. TCP_Total_Ratio
    feature_8 = len(tcp_packets) / total_packets

    # 9. Other_IP_Ratio
    feature_9 = other_ip_packets / total_packets

    # 10. Unique_Dst_IPs
    feature_10 = float(len(unique_dst_ips))

    # Финальный вектор признаков
    feature_vector_list = [
        feature_1, feature_2, feature_3, feature_4,
        feature_5, feature_6, feature_7, feature_8,
        feature_9, feature_10
    ]

    # Дополнительная информация для логирования
    source_info = {
        'Total_Packets': total_packets,
        'Unique_Src_IPs': feature_7,
        'Unique_Dst_IPs': feature_10,
        'Entropy_DPort': feature_4,
        'Unique_DPorts_Count': len(Counter(dst_ports)),
        'Most_Active_IP': Counter([p.src_ip for p in packet_snapshot]).most_common(1)[0][0]
        if total_packets > 0 else "N/A"
    }

    return FeatureVector(
        start_time=start_time,
        end_time=window_end_time,
        features=feature_vector_list,
        source_info=source_info
    )