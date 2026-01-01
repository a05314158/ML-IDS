# worker.py
import time
import sys
import numpy as np
from datetime import datetime
import os
# import traceback # Не используем traceback, чтобы избежать ошибок pickle

# Импорт из разработанных модулей
from config import TIME_WINDOW, ANOMALY_THRESHOLD, NUM_FEATURES
from sniffer import PacketSniffer
from feature_engineer import extract_features
from ml_model import MLAnomalyDetector
from data_structures import SharedDataFile  # Используем файловый обмен


def collect_baseline_data(sniffer: PacketSniffer, detector: MLAnomalyDetector, shared_data_file: SharedDataFile,
                          duration_minutes: int):
    print(f"\n[WORKER] Начинается сбор нормального трафика в течение {duration_minutes} минут.")

    X_train_list = []
    total_seconds = duration_minutes * 60
    num_cycles = total_seconds // TIME_WINDOW

    # Обновляем статус для GUI
    status = shared_data_file.get_status()
    status['is_baseline_mode'] = True
    shared_data_file.update_status_and_history(status, [0, 0, False])  # Сохраняем начальный статус

    for i in range(num_cycles):
        time.sleep(TIME_WINDOW)
        window_end_time = datetime.now()

        packet_snapshot = sniffer.get_and_clear_buffer()
        feature_vector_obj = extract_features(packet_snapshot, window_end_time)

        X_train_list.append(feature_vector_obj.features)

        # Обновление метрик в SharedData для отображения прогресса в GUI
        status['last_feature_vector'] = feature_vector_obj.features
        shared_data_file.update_status_and_history(status, [0, 0, False])  # Обновляем метрики

        # Обновление консоли
        sys.stdout.write(
            f"\r[WORKER][BASELINE] Прогресс: {i + 1}/{num_cycles}. Пакеты: {len(packet_snapshot)}. Собрано векторов: {len(X_train_list)}")
        sys.stdout.flush()

    print("\n[WORKER] Сбор данных завершен.")

    if not X_train_list:
        print("[WORKER] ВНИМАНИЕ: Нет собранных пакетов. Обучение на нулевых данных.")
        X_train = np.zeros((1, NUM_FEATURES))
    else:
        X_train = np.array(X_train_list)

    detector.train_and_save_model(X_train)

    # Сразу после обучения, переходим в режим мониторинга
    status['is_baseline_mode'] = False
    shared_data_file.update_status_and_history(status, [0, 0, False])  # Финальное сохранение статуса


def main():
    """
    Основная функция worker-процесса, включающая захват, обучение и мониторинг.
    """
    print(f"[WORKER] Процесс запущен с PID: {os.getpid()}")
    shared_data_file = SharedDataFile()
    sniffer = PacketSniffer()
    detector = MLAnomalyDetector()

    try:
        # 1. Запуск захвата (Фаза 2.1)
        sniffer.start_sniffing()

        # Обновление статуса в SharedData
        status = shared_data_file.get_status()
        status['is_running'] = True
        status['current_interface'] = sniffer.iface_to_use
        shared_data_file.update_status_and_history(status, [0, 0, False])

        # 2. Фаза обучения (Оффлайн)
        if not detector.load_model():
            collect_baseline_data(sniffer, detector, shared_data_file, duration_minutes=1)
        else:
            status = shared_data_file.get_status()
            status['is_baseline_mode'] = False
            shared_data_file.update_status_and_history(status, [0, 0, False])

        # 3. Главный цикл потокового предсказания (Фаза 4.2)
        print(f"\n[WORKER] Запуск онлайн-мониторинга. Окно: {TIME_WINDOW} сек.")

        start_time_s = shared_data_file.get_status().get('start_time_s', time.time())

        while True:  # Запускается бесконечный цикл. Будет остановлен через terminate().
            time.sleep(TIME_WINDOW)
            window_end_time = datetime.now()

            # 3.1. Получение и извлечение признаков (Фаза 3)
            packet_snapshot = sniffer.get_and_clear_buffer()
            feature_vector_obj = extract_features(packet_snapshot, window_end_time)

            # 3.2. ML-Предсказание (Фаза 4.2)
            X_new = feature_vector_obj.get_ml_vector()
            anomaly_score = detector.predict(X_new)

            is_anomaly = anomaly_score < ANOMALY_THRESHOLD

            # 4. Обновление SharedData для Streamlit GUI

            # 4.1. Обновление истории Score (для графика)
            time_s = time.time() - start_time_s
            score_history_entry = [time_s, anomaly_score, is_anomaly]

            # 4.2. Обновление текущих метрик и статуса
            status = shared_data_file.get_status()
            status['last_feature_vector'] = feature_vector_obj.features

            # 4.3. Логирование и обновление алертов
            alert_entry = None
            if is_anomaly:
                # ... (логика создания alert_entry) ...
                entropy = feature_vector_obj.source_info.get('Entropy_DPort', 0.0)
                unique_src = feature_vector_obj.source_info.get('Unique_Src_IPs', 0)
                unique_dst = feature_vector_obj.source_info.get('Unique_Dst_IPs', 0)

                reason = "Unknown Anomaly"
                if entropy > 3.0 and unique_src < 5 and unique_dst > 50:
                    reason = f"Port Scan (H: {entropy:.2f})"
                elif feature_vector_obj.features[0] > 1000:
                    reason = f"Flood (Pkt: {feature_vector_obj.features[0]:.0f})"
                elif feature_vector_obj.features[8] > 0.5:
                    reason = "Potential ICMP/Other IP Flood"

                alert_entry = {
                    'Time': datetime.now().strftime('%H:%M:%S'),
                    'Score': f"{anomaly_score:.3f}",
                    'Reason': reason,
                    'Source IP': feature_vector_obj.source_info.get('Most_Active_IP', 'N/A')
                }

                print(f"[WORKER][ALERT] {reason}! Score: {anomaly_score:.3f}")

            # Сохраняем все данные
            shared_data_file.update_status_and_history(status, score_history_entry, alert_entry)

    except Exception as e:
        print(f"\n[WORKER] Критическая ошибка: {e}")
        # import traceback; traceback.print_exc() # Не выводим, чтобы не мешать GUI

    finally:
        sniffer.stop_sniffing()
        print("[WORKER] Процесс корректно остановлен.")


if __name__ == '__main__':
    # Worker теперь запускается как основной скрипт через subprocess
    # Это обходит проблему pickle/multiprocessing
    main()