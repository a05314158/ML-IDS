# sniffer.py
# Отложенный импорт Scapy для совместимости с multiprocessing/pickle
from collections import deque
import threading
from datetime import datetime
from typing import List, Optional

from config import INTERFACE, BPF_FILTER, MAX_BUFFER_SIZE
from data_structures import PacketData


# Функция для динамического импорта Scapy
def _dynamic_import_scapy():
    """Безопасно импортирует Scapy и возвращает нужные объекты."""
    try:
        from scapy.all import sniff, IP, TCP, UDP, get_if_list
        return sniff, IP, TCP, UDP, get_if_list
    except ImportError:
        print("[SNIFFER] Ошибка: Библиотека Scapy не найдена. Убедитесь, что она установлена.")
        raise
    except Exception as e:
        print(f"[SNIFFER] Критическая ошибка при загрузке Scapy: {e}")
        raise


class PacketSniffer:

    def __init__(self):
        self.sniff = self.IP = self.TCP = self.UDP = self.get_if_list = None
        try:
            self.sniff, self.IP, self.TCP, self.UDP, self.get_if_list = _dynamic_import_scapy()
        except Exception:
            pass

        self.buffer = deque(maxlen=MAX_BUFFER_SIZE)
        self.lock = threading.Lock()
        self.is_running = False
        self.sniffer_thread = None

        self.iface_to_use = None  # Теперь устанавливается извне
        self.bpf_filter = BPF_FILTER  # Базовый фильтр по умолчанию

    # Метод для установки параметров из GUI
    def set_config(self, iface_name: str, bpf_filter: str):
        self.iface_to_use = iface_name
        self.bpf_filter = bpf_filter

    def start_sniffing(self):
        """Запускает Scapy sniff() в отдельном потоке."""
        if self.is_running:
            return
        if not self.sniff or not self.iface_to_use:
            # print("[SNIFFER] Невозможно запустить. Интерфейс не установлен или Scapy не загружен.")
            return

        self.is_running = True
        print(f"[SNIFFER] Запуск захвата на интерфейсе {self.iface_to_use} с фильтром: '{self.bpf_filter}'")

        self.sniffer_thread = threading.Thread(
            target=self.sniff,
            kwargs={
                'prn': self._packet_callback,
                'iface': self.iface_to_use,
                'filter': self.bpf_filter,  # Используем фильтр из GUI
                'store': 0,
                'stop_filter': lambda x: not self.is_running
            }
        )
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()

    def stop_sniffing(self):
        """Останавливает процесс захвата."""
        self.is_running = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=1)
            print("[SNIFFER] Захват трафика остановлен.")

    def _packet_callback(self, packet):
        """
        Callback-функция, вызываемая Scapy для каждого захваченного пакета.
        """
        if self.IP in packet:
            ip_layer = packet[self.IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            pkt_len = len(packet)

            is_tcp = self.TCP in packet
            is_udp = self.UDP in packet

            src_port = None
            dst_port = None
            tcp_flags = {}

            if is_tcp:
                tcp_layer = packet[self.TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                flags_str = str(tcp_layer.flags)
                tcp_flags = {
                    'SYN': 'S' in flags_str,
                    'ACK': 'A' in flags_str,
                    'FIN': 'F' in flags_str,
                    'RST': 'R' in flags_str,
                }
            elif is_udp:
                udp_layer = packet[self.UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport

            pkt_data = PacketData(
                timestamp=datetime.now(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                length=pkt_len,
                is_tcp=is_tcp,
                is_udp=is_udp,
                tcp_flags=tcp_flags
            )

            with self.lock:
                self.buffer.append(pkt_data)

    def get_and_clear_buffer(self) -> List[PacketData]:
        """
        Извлекает текущее содержимое буфера и очищает его.
        """
        with self.lock:
            buffer_snapshot = list(self.buffer)
            self.buffer.clear()
            return buffer_snapshot