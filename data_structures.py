# data_structures.py
from typing import Optional, List, Dict
from datetime import datetime
import numpy as np
import pandas as pd
import time
import pickle
import os
from collections import deque

# Константы для обмена данными
DATA_FILE = "shared_status_history.pkl"
ALERT_FILE = "shared_alerts.pkl"


class PacketData:
    """Хранит ключевые поля пакета, необходимые для Feature Engineering."""

    # ... (Остается без изменений) ...
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
    # ...


class FeatureVector:
    """Хранит агрегированный вектор признаков для одного временного окна (10 признаков)."""

    # ... (Остается без изменений) ...
    def __init__(self, start_time: datetime, end_time: datetime, features: List[float], source_info: Dict[str, any]):
        self.start_time = start_time
        self.end_time = end_time
        self.features = features
        self.source_info = source_info
        self.anomaly_score: Optional[float] = None
        self.is_anomaly: Optional[bool] = None

    def get_ml_vector(self) -> np.ndarray:
        return np.array([self.features])
    # ...


class SharedDataFile:
    """
    Класс для обмена данными через файлы (вместо multiprocessing.Manager)
    для обхода ошибки pickle на Windows.
    """

    def __init__(self):
        # Инициализируем файлы, если их нет
        if not os.path.exists(DATA_FILE):
            self._save_data(self._get_initial_data())
        if not os.path.exists(ALERT_FILE):
            self._save_alerts([])

    def _get_initial_data(self) -> dict:
        return {
            'status': {
                'is_running': False,
                'is_baseline_mode': True,
                'current_interface': '',
                'start_time_s': time.time(),
                'last_feature_vector': [0.0] * 10
            },
            'score_history': []  # Хранит [time_s, score, is_anomaly]
        }

    def _save_data(self, data: dict):
        try:
            with open(DATA_FILE, 'wb') as f:
                pickle.dump(data, f)
        except Exception as e:
            # print(f"[SHARED] Ошибка записи данных: {e}") # Не выводим, чтобы не спамить консоль
            pass

    def _load_data(self) -> dict:
        if not os.path.exists(DATA_FILE):
            return self._get_initial_data()
        try:
            with open(DATA_FILE, 'rb') as f:
                return pickle.load(f)
        except:
            return self._get_initial_data()

    def _save_alerts(self, alerts: list):
        try:
            with open(ALERT_FILE, 'wb') as f:
                pickle.dump(alerts, f)
        except Exception:
            pass

    def _load_alerts(self) -> list:
        if not os.path.exists(ALERT_FILE):
            return []
        try:
            with open(ALERT_FILE, 'rb') as f:
                return pickle.load(f)
        except:
            return []

    # --- Методы, используемые Worker-процессом (ЗАПИСЬ) ---
    def update_status_and_history(self, status: dict, score_history_entry: list, alert_entry: Optional[dict] = None):
        data = self._load_data()

        data['status'] = status

        if 'score_history' not in data:
            data['score_history'] = []
        data['score_history'].append(score_history_entry)

        if len(data['score_history']) > 500:
            data['score_history'].pop(0)

        self._save_data(data)

        if alert_entry:
            alerts = self._load_alerts()
            alerts.append(alert_entry)
            if len(alerts) > 50:
                alerts.pop(0)
            self._save_alerts(alerts)

    # --- Методы, используемые Streamlit-процессом (ЧТЕНИЕ) ---
    def get_status(self) -> dict:
        return self._load_data().get('status', self._get_initial_data()['status'])

    def get_history_df(self) -> pd.DataFrame:
        data = self._load_data().get('score_history', [])
        if not data:
            return pd.DataFrame(columns=['Time (s)', 'Anomaly Score', 'Is_Anomaly'])
        return pd.DataFrame(data, columns=['Time (s)', 'Anomaly Score', 'Is_Anomaly'])

    def get_alerts_df(self) -> pd.DataFrame:
        data = self._load_alerts()
        if not data:
            return pd.DataFrame(columns=['Time', 'Score', 'Reason', 'Source IP'])
        return pd.DataFrame(data)