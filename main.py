# main.py (Версия для обучения на реальных данных)

import tkinter as tk
import threading
import time
from datetime import datetime
import sys
import numpy as np
import os
import ctypes
from collections import deque
from typing import Any
import socket
import ssl

from config import (TIME_WINDOW, NUM_FEATURES, BPF_FILTER, SCORE_HISTORY_SIZE,
                    ADAPTIVE_THRESHOLD_PERCENTILE, MODEL_PATH, SCALER_PATH,
                    INITIAL_THRESHOLD_PATH, TRAIN_DURATION_MINUTES, CONTAMINATION)
from sniffer import PacketSniffer
from feature_engineer import extract_features
from ml_model import MLAnomalyDetector
from gui_app import MLIDS_GUI


def generate_dummy_traffic(stop_event: threading.Event):
    """Генерирует простой HTTPS-трафик в фоне, пока идет обучение."""
    sites = ["www.google.com", "www.github.com", "www.microsoft.com", "www.python.org"]
    print("[TRAFFIC GEN] Начало генерации фонового трафика для обучения...")
    while not stop_event.is_set():
        for host in sites:
            if stop_event.is_set(): break
            try:
                context = ssl.create_default_context()
                with socket.create_connection((host, 443), timeout=2) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        ssock.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode('utf-8'))
                        ssock.recv(1024)
                time.sleep(1)  # Небольшая пауза
            except Exception:
                pass  # Игнорируем ошибки, если сайт недоступен
    print("[TRAFFIC GEN] Генерация фонового трафика завершена.")


def check_admin_rights():
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0


class MLIDS_System:
    def __init__(self, root: tk.Tk):
        self.root = root;
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        self.sniffer = PacketSniffer();
        self.detector = MLAnomalyDetector()
        self.gui_app = MLIDS_GUI(root, self.start_monitoring, self.stop_monitoring, self.reset_model)
        self.ml_thread: threading.Thread = None;
        self.ml_thread_running = False
        self.current_adaptive_threshold = -0.1
        self.score_history = deque(maxlen=SCORE_HISTORY_SIZE)
        if not check_admin_rights(): self.gui_app.log_message("ВНИМАНИЕ: Запустите с правами администратора!", 'alert')

    def reset_model(self):
        try:
            for fp in [MODEL_PATH, SCALER_PATH, INITIAL_THRESHOLD_PATH]:
                if os.path.exists(fp): os.remove(fp); self.gui_app.log_message(f"Удален: {fp}", 'info')
        except Exception as e:
            self.gui_app.log_message(f"Ошибка сброса: {e}", 'alert')

    def start_monitoring(self, iface_object: Any):
        if self.ml_thread_running: return
        self.sniffer.set_config(iface_object, BPF_FILTER)
        self.ml_thread_running = True
        self.ml_thread = threading.Thread(target=self._ml_monitor_loop, daemon=True)
        self.ml_thread.start()
        self.gui_app.log_message(f"Запуск на: {iface_object.description}", 'info')

    def stop_monitoring(self):
        if not self.ml_thread_running: return
        self.ml_thread_running = False;
        self.sniffer.stop_sniffing()
        if self.ml_thread.is_alive(): self.ml_thread.join(timeout=2)
        self.gui_app.log_message("Остановлено.", 'info')

    def _ml_monitor_loop(self):
        try:
            if not self.detector.load_model():
                self.gui_app.log_message(f"Сбор реальных данных ({TRAIN_DURATION_MINUTES} мин)...", 'info')
                self.sniffer.start_sniffing()
                X_train, _ = self._collect_baseline_data()
                self.detector.train_and_save_model(X_train, contamination=CONTAMINATION)
                self.detector.load_model()
                self.gui_app.log_message("Обучение завершено.", 'info')

            permanent_floor_threshold = self.detector.initial_threshold
            self.current_adaptive_threshold = permanent_floor_threshold
            self.score_history.clear()
            self.gui_app.log_message(f"Модель загружена. Порог: {permanent_floor_threshold:.4f}", 'info')

            if not self.sniffer.is_running: self.sniffer.start_sniffing()

            while self.ml_thread_running:
                time.sleep(TIME_WINDOW)
                packet_snapshot = self.sniffer.get_and_clear_buffer()
                if not packet_snapshot: continue

                feature_vector_obj = extract_features(packet_snapshot, datetime.now())
                anomaly_score = self.detector.predict(feature_vector_obj.get_ml_vector())

                is_alert = anomaly_score < self.current_adaptive_threshold
                is_safe_to_adapt = anomaly_score >= permanent_floor_threshold

                if is_safe_to_adapt:
                    self.score_history.append(anomaly_score)
                    new_adaptive_threshold = self.detector.calculate_adaptive_threshold(list(self.score_history),
                                                                                        ADAPTIVE_THRESHOLD_PERCENTILE)
                    self.current_adaptive_threshold = max(new_adaptive_threshold, permanent_floor_threshold)

                self.root.after_idle(self.gui_app.update_gui, anomaly_score, is_alert, self.current_adaptive_threshold)
                if is_alert: self.root.after_idle(self.gui_app.log_message, f"ALERT! Score: {anomaly_score:.3f}",
                                                  'alert')

        except Exception as e:
            import traceback;
            traceback.print_exc()
            self.root.after_idle(self.gui_app.log_message, f"КРИТИЧЕСКАЯ ОШИБКА: {e}", 'alert')

    def _collect_baseline_data(self) -> tuple[np.ndarray, list]:
        """Собирает данные, СЛУШАЯ РЕАЛЬНЫЙ ТРАФИК ПОЛЬЗОВАТЕЛЯ."""
        X_train_list, num_cycles = [], (TRAIN_DURATION_MINUTES * 60) // TIME_WINDOW

        # --- ИЗМЕНЕНИЕ: Генератор трафика отключен ---
        # stop_traffic_gen = threading.Event()
        # traffic_thread = threading.Thread(target=generate_dummy_traffic, args=(stop_traffic_gen,), daemon=True)
        # traffic_thread.start()

        for i in range(num_cycles):
            if not self.ml_thread_running: break
            time.sleep(TIME_WINDOW)
            packet_snapshot = self.sniffer.get_and_clear_buffer()
            # Теперь мы не пропускаем пустые окна, а создаем нулевой вектор,
            # чтобы модель знала, что "тишина" - это тоже нормально.
            X_train_list.append(extract_features(packet_snapshot, datetime.now()).features)
            self.root.after_idle(self.gui_app.log_message, f"BASELINE: Сбор {i + 1}/{num_cycles}", 'info')

        # --- ИЗМЕНЕНИЕ: Остановка генератора отключена ---
        # stop_traffic_gen.set()
        # traffic_thread.join(timeout=5)

        return np.array(X_train_list), []

    def _on_closing(self):
        self.stop_monitoring(); self.root.destroy(); sys.exit(0)

    def run(self):
        self.root.mainloop()


if __name__ == '__main__':
    root = tk.Tk();
    system = MLIDS_System(root);
    system.run()
