# sniffer.py

from collections import deque
import threading
from datetime import datetime
from typing import List, Optional

# ИСПРАВЛЕНО: Убираем импорт DEFAULT_INTERFACE, но оставляем нужные
from config import BPF_FILTER, MAX_BUFFER_SIZE
from data_structures import PacketData


def _dynamic_import_scapy():
    """Безопасно импортирует Scapy."""
    try:
        from scapy.all import sniff, IP, TCP, UDP
        return sniff, IP, TCP, UDP
    except ImportError:
        print("[SNIFFER] Ошибка: Scapy не найдена. Установите ее (`pip install scapy`).")
        raise
    except Exception as e:
        print(f"[SNIFFER] Критическая ошибка при загрузке Scapy: {e}")
        raise


class PacketSniffer:

    def __init__(self):
        self.sniff, self.IP, self.TCP, self.UDP = _dynamic_import_scapy()

        self.buffer = deque(maxlen=MAX_BUFFER_SIZE)
        self.lock = threading.Lock()
        self.is_running = False
        self.sniffer_thread: Optional[threading.Thread] = None

        # ИСПРАВЛЕНО: Интерфейс теперь инициализируется как None, он будет задан извне
        self.iface_to_use: Optional[str] = None
        self.bpf_filter: str = BPF_FILTER

    def set_config(self, iface_name: str, bpf_filter: str):
        """Устанавливает конфигурацию (интерфейс и фильтр) перед запуском."""
        self.iface_to_use = iface_name
        self.bpf_filter = bpf_filter

    def start_sniffing(self):
        """Запускает Scapy sniff() в отдельном фоновом потоке."""
        if self.is_running:
            return
        if not self.iface_to_use:
            print("[SNIFFER] КРИТИЧЕСКАЯ ОШИБКА: Сетевой интерфейс не задан!")
            return

        self.is_running = True
        print(f"[SNIFFER] Запуск захвата на '{self.iface_to_use}' с фильтром: '{self.bpf_filter}'")

        self.sniffer_thread = threading.Thread(
            target=self.sniff,
            kwargs={
                'prn': self._packet_callback,
                'iface': self.iface_to_use,
                'filter': self.bpf_filter,
                'store': 0,
                'stop_filter': lambda _: not self.is_running
            },
            daemon=True
        )
        self.sniffer_thread.start()

    def stop_sniffing(self):
        """Корректно останавливает процесс захвата."""
        self.is_running = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=1.5)
        print("[SNIFFER] Захват трафика остановлен.")

    def _packet_callback(self, packet):
        """Callback-функция, вызываемая Scapy для каждого захваченного пакета."""
        if not packet.haslayer(self.IP):
            return

        ip_layer = packet.getlayer(self.IP)
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        pkt_len = len(packet)

        is_tcp = packet.haslayer(self.TCP)
        is_udp = packet.haslayer(self.UDP)

        src_port, dst_port, tcp_flags = None, None, {}

        if is_tcp:
            tcp_layer = packet.getlayer(self.TCP)
            src_port, dst_port = tcp_layer.sport, tcp_layer.dport
            flags_str = str(tcp_layer.flags)
            tcp_flags = {'SYN': 'S' in flags_str, 'ACK': 'A' in flags_str}
        elif is_udp:
            udp_layer = packet.getlayer(self.UDP)
            src_port, dst_port = udp_layer.sport, udp_layer.dport

        pkt_data = PacketData(
            timestamp=datetime.now(), src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port, length=pkt_len,
            is_tcp=is_tcp, is_udp=is_udp, tcp_flags=tcp_flags
        )
        with self.lock:
            self.buffer.append(pkt_data)

    def get_and_clear_buffer(self) -> List[PacketData]:
        """Потокобезопасно извлекает содержимое буфера."""
        with self.lock:
            buffer_snapshot = list(self.buffer)
            self.buffer.clear()
            return buffer_snapshot

