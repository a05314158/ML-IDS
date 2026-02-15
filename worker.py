# worker.py (обновленная версия)

import threading
import time
from datetime import datetime
from collections import deque
import numpy as np

from config import (BPF_FILTER, TIME_WINDOW, SCORE_HISTORY_SIZE, ADAPTIVE_THRESHOLD_PERCENTILE)
from sniffer import PacketSniffer
from feature_engineer import extract_features
# --- ИЗМЕНЕНИЕ: Импортируем оба класса детекторов ---
from ml_model import IsolationForestDetector, TFAutoencoderDetector
# ---------------------------------------------------
from scapy.all import conf


class MLIDS_Worker:
    def __init__(self):
        self.lock = threading.Lock()
        self.status = {
            "is_running": False, "mode": "Остановлено", "log": deque(maxlen=200),
            "interface": None, "current_score": 0.0, "adaptive_threshold": -0.1, "is_anomaly": False,
            "model_id": None
        }
        self.ml_thread = None
        self._stop_event = threading.Event()

    def _log(self, message, category='info'):
        with self.lock:
            timestamp = datetime.now().strftime('%H:%M:%S')
            self.status["log"].appendleft(f"[{timestamp}] [{category.upper()}] {message}")

    def get_status(self):
        with self.lock:
            status_copy = self.status.copy()
            status_copy["log"] = list(self.status["log"])
            return status_copy

    def stop_current_session(self):
        if self.status["is_running"]:
            self._stop_event.set()
            self._log("Получен сигнал на остановку...", "warning")

    # --- ИЗМЕНЕНИЕ: Сигнатура функции ---
    def start_training_session(self, iface_str, model_path, scaler_path, training_duration_minutes, model_type):
        if self.status["is_running"]: return
        self._stop_event.clear()
        self.ml_thread = threading.Thread(target=self._training_loop,
                                          args=(
                                          iface_str, model_path, scaler_path, training_duration_minutes, model_type),
                                          daemon=True)
        self.ml_thread.start()

    def _training_loop(self, iface_str, model_path, scaler_path, training_duration_minutes, model_type):
        with self.lock:
            self.status.update(
                {"is_running": True, "mode": f"Обучение ({model_type})", "log": deque(maxlen=200),
                 "interface": iface_str, "model_id": None})
        self._log(f"Начало сессии обучения (тип: {model_type})", "info")

        sniffer = None
        try:
            # --- ИЗМЕНЕНИЕ: Выбираем нужный класс детектора ---
            if model_type == 'tensorflow':
                detector = TFAutoencoderDetector()
            else:  # По умолчанию используем isolation_forest
                detector = IsolationForestDetector()
            # ------------------------------------------------

            sniffer = PacketSniffer()
            iface_obj = next((i for i in conf.ifaces.values() if str(i) == iface_str), None)
            if not iface_obj: raise ValueError(f"Интерфейс {iface_str} не найден")

            sniffer.set_config(iface_obj, BPF_FILTER)
            sniffer.start_sniffing()

            X_train_list, num_cycles = [], (training_duration_minutes * 60) // TIME_WINDOW
            for i in range(num_cycles):
                if self._stop_event.is_set():
                    self._log("Обучение прервано.");
                    break
                time.sleep(TIME_WINDOW)
                snapshot = sniffer.get_and_clear_buffer()
                if not snapshot: continue  # Пропускаем пустые окна
                X_train_list.append(extract_features(snapshot, datetime.now()).features)
                self._log(f"Сбор данных: {i + 1}/{num_cycles}", "info")

            if not self._stop_event.is_set():
                if len(X_train_list) < 2: raise ValueError("Собрано недостаточно данных для обучения.")

                self._log("Обучение модели...", "info")
                detector.train_and_save_model(np.array(X_train_list), model_path, scaler_path)
                self._log("Обучение завершено.", "success")
        except Exception as e:
            self._log(f"КРИТИЧЕСКАЯ ОШИБКА: {e}", "danger")
        finally:
            if sniffer and sniffer.is_running: sniffer.stop_sniffing()
            with self.lock:
                self.status.update({"is_running": False, "mode": "Остановлено", "interface": None, "model_id": None})
            self._log("Сессия обучения завершена.", "info")

    def start_monitoring_session(self, iface_str, model_id, model_path, scaler_path, model_type):
        if self.status["is_running"]: return
        self._stop_event.clear()
        self.ml_thread = threading.Thread(target=self._monitoring_loop,
                                          args=(iface_str, model_id, model_path, scaler_path, model_type), daemon=True)
        self.ml_thread.start()

    def _monitoring_loop(self, iface_str, model_id, model_path, scaler_path, model_type):
        with self.lock:
            self.status.update({
                "is_running": True, "mode": f"Мониторинг ({model_type})", "log": deque(maxlen=200),
                "interface": iface_str,
                "current_score": 0.0, "is_anomaly": False, "model_id": model_id})
        self._log(f"Начало сессии мониторинга с моделью ID: {model_id} (тип: {model_type})", "info")

        sniffer = None
        try:
            # --- ИЗМЕНЕНИЕ: Снова выбираем нужный детектор ---
            if model_type == 'tensorflow':
                detector = TFAutoencoderDetector()
            else:
                detector = IsolationForestDetector()
            # -----------------------------------------------

            if not detector.load_model(model_path, scaler_path):
                raise ValueError("Не удалось загрузить указанную модель.")

            iface_obj = next((i for i in conf.ifaces.values() if str(i) == iface_str), None)
            if not iface_obj: raise ValueError(f"Интерфейс {iface_str} не найден")

            sniffer = PacketSniffer()
            sniffer.set_config(iface_obj, BPF_FILTER)
            sniffer.start_sniffing()

            score_history = deque(maxlen=SCORE_HISTORY_SIZE)
            permanent_floor_threshold = detector.initial_threshold
            with self.lock:
                self.status["adaptive_threshold"] = float(permanent_floor_threshold)

            while not self._stop_event.is_set():
                time.sleep(TIME_WINDOW)
                packet_snapshot = sniffer.get_and_clear_buffer()
                if not packet_snapshot: continue

                feature_vector_obj = extract_features(packet_snapshot, datetime.now())
                anomaly_score = detector.predict(feature_vector_obj.get_ml_vector())

                with self.lock:
                    current_adaptive_threshold = self.status["adaptive_threshold"]

                    # --- ИЗМЕНЕНИЕ: Разная логика для разных моделей! ---
                    if model_type == 'tensorflow':
                        is_alert = anomaly_score > current_adaptive_threshold
                    else:  # isolation_forest
                        is_alert = anomaly_score < current_adaptive_threshold
                    # ----------------------------------------------------

                    if not is_alert:
                        score_history.append(anomaly_score)
                        # Пересчитываем адаптивный порог
                        percentile = 98.0 if model_type == 'tensorflow' else 2.0  # Разные перцентили
                        new_adaptive_threshold = np.percentile(list(score_history), percentile)
                        self.status["adaptive_threshold"] = float(new_adaptive_threshold)

                    self.status.update({
                        "current_score": float(anomaly_score),
                        "is_anomaly": bool(is_alert)
                    })
                    if is_alert: self._log(f"АНОМАЛИЯ! Score: {anomaly_score:.4f}", "danger")
        except Exception as e:
            import traceback
            traceback.print_exc()
            self._log(f"КРИТИЧЕСКАЯ ОШИБКА: {e}", "danger")
        finally:
            if sniffer and sniffer.is_running: sniffer.stop_sniffing()
            with self.lock:
                self.status.update({"is_running": False, "mode": "Остановлено", "interface": None, "model_id": None})
            self._log("Сессия мониторинга завершена.", "info")

