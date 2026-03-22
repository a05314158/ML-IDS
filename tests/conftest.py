import pytest
from datetime import datetime, timedelta
from data_structures import PacketData


@pytest.fixture
def empty_packets():
    """Сценарий: Трафика нет"""
    return []


@pytest.fixture
def mixed_traffic_snapshot():
    """Сценарий: Набор базового рабочего трафика (TCP/UDP, разные порты и IP)"""
    base_time = datetime(2025, 1, 1, 12, 0, 0)

    return [
        # Пакет 1: HTTP-запрос (TCP, порт 80, SYN)
        PacketData(
            timestamp=base_time, src_ip="192.168.1.5", dst_ip="8.8.8.8",
            src_port=54321, dst_port=80, length=64,
            is_tcp=True, is_udp=False, tcp_flags={'SYN': True}, protocol="TCP", domain="example.com"
        ),
        # Пакет 2: Ответ сервера (TCP, порт 80, ACK) - через 100мс
        PacketData(
            timestamp=base_time + timedelta(milliseconds=100), src_ip="8.8.8.8", dst_ip="192.168.1.5",
            src_port=80, dst_port=54321, length=1500,
            is_tcp=True, is_udp=False, tcp_flags={'ACK': True}, protocol="TCP", domain=None
        ),
        # Пакет 3: DNS Запрос (UDP, порт 53) - через 50мс
        PacketData(
            timestamp=base_time + timedelta(milliseconds=150), src_ip="192.168.1.5", dst_ip="1.1.1.1",
            src_port=44444, dst_port=53, length=120,
            is_tcp=False, is_udp=True, tcp_flags={}, protocol="UDP", domain="api.github.com"
        ),
        # Пакет 4: Левый пакет на другой IP (Имитация шума/Аномалии)
        PacketData(
            timestamp=base_time + timedelta(milliseconds=150), src_ip="192.168.1.100", dst_ip="10.0.0.1",
            src_port=33333, dst_port=443, length=40,
            is_tcp=True, is_udp=False, tcp_flags={'SYN': True, 'ACK': True}, protocol="TCP", domain="unknown.org"
        )
    ]