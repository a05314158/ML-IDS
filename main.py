# main.py
import tkinter as tk
import threading
import time
from datetime import datetime
import sys
import numpy as np
import os
import ctypes

# --- Импорт из разработанных модулей ---
# Все константы из config
from config import TIME_WINDOW, INTERFACE, BPF_FILTER, MODEL_PATH, SCALER_PATH, THRESHOLD_FILE
# Все классы
from sniffer import PacketSniffer
from feature_engineer import extract_features
from ml_model import MLAnomalyDetector
from gui_app import MLIDS_GUI

# Глобальная константа для порога (так как она удалена из config)
DEFAULT_ANOMALY_THRESHOLD = -0.10

# --- Проверка прав администратора ---
def check_admin_rights():
    """Проверяет права администратора (для Windows) и выдает предупреждение."""
    if os.name == 'nt':
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print("=========================================================================")
                print("!!! КРИТИЧЕСКОЕ ПРЕДУПРЕЖДЕНИЕ: Программа запущена БЕЗ прав Администратора.")
                print("!!! Захват сетевого трафика (Scapy) НЕ БУДЕТ РАБОТАТЬ!")
                print("!!! Пожалуйста, перезапустите терминал/PyCharm 'От имени администратора'.")
                print("=========================================================================")
                return False
            else:
                print("[LAUNCHER] Права администратора подтверждены.")
        except:
            pass
    return True


class MLIDS_System:
    def __init__(self):
        # --- Модули ---
        self.sniffer = PacketSniffer()
        self.detector = MLAnomalyDetector()

        # --- Потоки и синхронизация ---
        self.ml_thread: threading.Thread = None
        self.ml_thread_running = False
        self.gui_app: MLIDS_GUI = None

        # --- Флаги состояния ---
        self.is_baseline_mode = True

        # --- Настройка GUI ---
        self.root = tk.Tk()
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Проверяем права до инициализации GUI
        if not check_admin_rights():
            # Если прав нет, не продолжаем, но не выходим сразу, чтобы увидеть предупреждение
            pass

            # !!! ПЕРЕДАЧА НОВОГО CALLBACK: self.reset_model !!!
        self.gui_app = MLIDS_GUI(self.root, self.start_monitoring, self.stop_monitoring, self.reset_model)

        self.root.after(TIME_WINDOW * 1000, self._update_gui_from_ml_thread)

    def _update_gui_from_ml_thread(self):
        # Эта функция просто держит GUI активным и вызывает сама себя
        self.root.after(TIME_WINDOW * 1000, self._update_gui_from_ml_thread)

    def reset_model(self):
        """Удаляет сохраненные файлы модели и скалера (вызывается из GUI)."""
        try:
            if os.path.exists(MODEL_PATH):
                os.remove(MODEL_PATH)
            if os.path.exists(SCALER_PATH):
                os.remove(SCALER_PATH)
            self.gui_app.log_message("Файлы модели удалены. Модель будет переобучена при следующем запуске.", 'alert')
            self.is_baseline_mode = True  # Устанавливаем флаг для переобучения
        except Exception as e:
            self.gui_app.log_message(f"Ошибка сброса модели: {e}", 'alert')

    def start_monitoring(self, iface_name: str, bpf_filter: str):
        """Запуск всей системы (вызывается из GUI)."""
        if self.ml_thread_running:
            return

        # 1. Установка конфигурации
        self.sniffer.set_config(iface_name, bpf_filter)

        # 2. Обучение/Загрузка модели
        # Если модель не найдена ИЛИ был нажат СБРОС (is_baseline_mode=True)
        if self.is_baseline_mode or not self.detector.load_model():
            self.gui_app.log_message("Модель не найдена/сброшена. Начинается сбор нормального трафика (1 мин)...",
                                     'info')
            self.is_baseline_mode = True
        else:
            self.gui_app.log_message("Модель загружена. Начинается мониторинг...", 'info')
            self.is_baseline_mode = False

        # 3. Запуск ML-потока
        self.ml_thread_running = True
        self.ml_thread = threading.Thread(target=self._ml_monitor_loop)
        self.ml_thread.daemon = True
        self.ml_thread.start()

    def stop_monitoring(self):
        """Остановка всей системы (вызывается из GUI)."""
        if not self.ml_thread_running:
            return

        self.ml_thread_running = False
        self.sniffer.stop_sniffing()

        if self.ml_thread.is_alive():
            self.ml_thread.join(timeout=2)

    def _ml_monitor_loop(self):
        """
        Основной цикл захвата, агрегации и ML-предсказания (работает в фоновом потоке).
        """
        self.sniffer.start_sniffing()

        try:
            # --- Этап 1: Сбор/Обучение Baseline (если необходимо) ---
            if self.is_baseline_mode:
                X_train = self._collect_baseline_data(duration_minutes=1)
                self.detector.train_and_save_model(X_train)
                self.is_baseline_mode = False
                self.gui_app.log_message("Обучение завершено. Переход в режим мониторинга.", 'info')

            # --- Этап 2: Потоковое предсказание ---
            while self.ml_thread_running:
                time.sleep(TIME_WINDOW)
                window_end_time = datetime.now()

                # 1. Извлечение признаков
                packet_snapshot = self.sniffer.get_and_clear_buffer()
                feature_vector_obj = extract_features(packet_snapshot, window_end_time)

                # 2. ML-Предсказание
                anomaly_score = self.detector.predict(feature_vector_obj.get_ml_vector())
                is_anomaly = anomaly_score < ANOMALY_THRESHOLD

                # 3. Обновление GUI
                entropy = feature_vector_obj.source_info.get('Entropy_DPort', 0.0)

                self.root.after_idle(
                    self.gui_app.update_graph,
                    anomaly_score,
                    is_anomaly
                )

                # 4. Логирование
                if is_anomaly:
                    most_active_ip = feature_vector_obj.source_info.get('Most_Active_IP', 'N/A')
                    reason = f"Port scan (H: {entropy:.2f})"

                    self.root.after_idle(
                        self.gui_app.log_message,
                        f"ALERT! {reason}. Source: {most_active_ip}. Score: {anomaly_score:.3f}",
                        'alert'
                    )
                else:
                    self.root.after_idle(
                        self.gui_app.log_message,
                        f"Норма. Пакеты: {len(packet_snapshot)}. Энтропия: {entropy:.2f}. Score: {anomaly_score:.3f}",
                        'normal'
                    )

        except Exception as e:
            self.root.after_idle(self.gui_app.log_message, f"КРИТИЧЕСКАЯ ОШИБКА ML-ПОТОКА: {e}", 'alert')
            self.root.after_idle(self.stop_monitoring)

    def _collect_baseline_data(self, duration_minutes: int) -> np.ndarray:
        """Сбор данных для обучения модели."""
        X_train_list = []
        num_cycles = (duration_minutes * 60) // TIME_WINDOW

        for i in range(num_cycles):
            if not self.ml_thread_running: break
            time.sleep(TIME_WINDOW)

            packet_snapshot = self.sniffer.get_and_clear_buffer()
            feature_vector_obj = extract_features(packet_snapshot, datetime.now())

            X_train_list.append(feature_vector_obj.features)

            # Обновление лога о прогрессе
            self.root.after_idle(
                self.gui_app.log_message,
                f"BASELINE: Собрано {i + 1}/{num_cycles} окон. Пакеты: {len(packet_snapshot)}.",
                'info'
            )

        return np.array(X_train_list)

    def _on_closing(self):
        """Обработчик закрытия окна Tkinter."""
        self.stop_monitoring()
        self.root.destroy()
        sys.exit(0)

    def run(self):
        """Запуск главного цикла Tkinter."""
        self.root.mainloop()


if __name__ == '__main__':
    # *** ЗАПУСК С ПРАВАМИ АДМИНИСТРАТОРА (root) ОБЯЗАТЕЛЕН ***

    try:
        system = MLIDS_System()
        system.run()
    except Exception as e:
        print(f"Критическая ошибка запуска системы: {e}")
        sys.exit(1)