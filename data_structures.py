# data_structures.py

from typing import Optional, List, Dict
from datetime import datetime
import numpy as np

class PacketData:
    """Хранит ключевые поля пакета."""
    def __init__(self, timestamp: datetime, src_ip: str, dst_ip: str, src_port: Optional[int], dst_port: Optional[int],
                 length: int, is_tcp: bool, is_udp: bool, tcp_flags: Optional[Dict[str, bool]] = None):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.length = length
        self.is_tcp = is_tcp
        self.is_udp = is_udp
        self.tcp_flags = tcp_flags if tcp_flags is not None else {}

class FeatureVector:
    """Хранит агрегированный вектор признаков."""
    def __init__(self, start_time: datetime, end_time: datetime, features: List[float], source_info: Dict[str, any]):
        self.start_time = start_time
        self.end_time = end_time
        self.features = features
        self.source_info = source_info

    def get_ml_vector(self) -> np.ndarray:
        """Возвращает numpy-вектор для подачи в модель."""
        return np.array([self.features])
