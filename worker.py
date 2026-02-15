# worker.py (ФИНАЛЬНАЯ УПРОЩЕННАЯ ВЕРСИЯ)
import time
from datetime import datetime
from collections import deque, defaultdict
import numpy as np
import ipaddress
import os
import json
import traceback

from config import *
from sniffer import PacketSniffer
from feature_engineer import extract_features
from ml_model import IsolationForestDetector, TFAutoencoderDetector
from scapy.all import get_if_list


def is_local_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def run_main_worker():
    from app import app, db, Model, TrafficLog, ActiveState

    print("[WORKER] Запуск главного воркера...")

    sniffer = None
    ml_detector = None
    active_model_in_memory = None

    local_status = {
        "log": deque(maxlen=50), "mode": "Инициализация...", "interface": None,
        "is_running": True, "model_id": None, "current_score": 0.0,
        "adaptive_threshold": -0.1, "is_anomaly": False,
    }

    def _log(message, category='info'):
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_line = f"[{timestamp}] [{category.upper()}] {message}"
        local_status["log"].appendleft(log_line)
        print(log_line)

    while True:
        try:
            with app.app_context():
                # 1. Логика обучения (если есть необученные модели)
                untrained_model = Model.query.filter_by(model_path=None).first()
                if untrained_model:
                    _log(f"Начинаю обучение модели: '{untrained_model.name}' (тип: {untrained_model.model_type})")
                    local_status["mode"] = f"Обучение ({untrained_model.model_type})"

                    train_iface = get_if_list()[0]
                    _log(f"Использую интерфейс '{train_iface}' для сбора данных.")
                    train_sniffer = PacketSniffer()
                    train_sniffer.set_config(train_iface, BPF_FILTER)
                    train_sniffer.start_sniffing()

                    X_train_list, num_cycles = [], (TRAIN_DURATION_MINUTES * 60) // TIME_WINDOW
                    for i in range(num_cycles):
                        time.sleep(TIME_WINDOW)
                        snapshot = train_sniffer.get_and_clear_buffer()
                        if not snapshot: continue
                        X_train_list.append(extract_features(snapshot, datetime.now()).features)
                        _log(f"Сбор данных для обучения: {i + 1}/{num_cycles}")
                    train_sniffer.stop_sniffing()

                    if len(X_train_list) < 2:
                        _log("Недостаточно данных для обучения. Модель удалена.", "danger")
                        db.session.delete(untrained_model)
                    else:
                        detector = TFAutoencoderDetector() if untrained_model.model_type == 'tensorflow' else IsolationForestDetector()
                        user_model_dir = os.path.join('models', 'system')
                        os.makedirs(user_model_dir, exist_ok=True)
                        base_filename = f'{untrained_model.model_type}_{datetime.utcnow().strftime("%Y%m%d%H%M%S")}'
                        model_path = os.path.join(user_model_dir, base_filename)
                        scaler_path = f"{model_path}_scaler.joblib"
                        detector.train_and_save_model(np.array(X_train_list), model_path, scaler_path)

                        untrained_model.model_path = model_path
                        untrained_model.timestamp = datetime.utcnow()
                        _log(f"Обучение модели '{untrained_model.name}' завершено.", "success")
                    db.session.commit()
                    continue

                # 2. Логика Мониторинга
                active_state_from_db = db.session.get(ActiveState, 1) or ActiveState(id=1)

                is_monitoring_active_in_db = active_state_from_db.is_monitoring
                is_monitoring_active_in_memory = ml_detector is not None

                if is_monitoring_active_in_db != is_monitoring_active_in_memory or \
                        (is_monitoring_active_in_db and active_state_from_db.active_model_id != (
                        active_model_in_memory.id if active_model_in_memory else None)):

                    if is_monitoring_active_in_db:
                        _log("Запускаем/переключаем ML-мониторинг...")
                        active_model = db.session.get(Model, active_state_from_db.active_model_id)
                        if active_model and active_model.model_path:
                            detector = TFAutoencoderDetector() if active_model.model_type == 'tensorflow' else IsolationForestDetector()
                            scaler_path = f"{active_model.model_path}_scaler.joblib"
                            if detector.load_model(active_model.model_path, scaler_path):
                                ml_detector = detector
                                active_model_in_memory = active_model
                                local_status["mode"] = f"Мониторинг ({active_model.model_type})"
                                local_status["model_id"] = active_model.id
                                _log(f"Модель '{active_model.name}' успешно загружена и активна.", "success")
                            else:
                                _log(f"Ошибка загрузки модели ID {active_model.id}", "danger");
                                ml_detector = None
                    else:
                        _log("Останавливаем ML-мониторинг.")
                        ml_detector = None;
                        active_model_in_memory = None
                        local_status["mode"] = "Сбор статистики";
                        local_status["model_id"] = None

                # 3. Постоянный сбор статистики
                current_iface = active_state_from_db.interface or (get_if_list()[0] if get_if_list() else None)
                if current_iface and (not sniffer or not sniffer.is_running or sniffer.iface_to_use != current_iface):
                    if sniffer: sniffer.stop_sniffing()
                    sniffer = PacketSniffer()
                    sniffer.set_config(current_iface, "ip or udp port 53")
                    sniffer.start_sniffing()
                    local_status["interface"] = current_iface
                    if not ml_detector: local_status["mode"] = "Сбор статистики"
                    _log(f"Сборщик трафика запущен на интерфейсе {current_iface}")

                if sniffer and sniffer.is_running:
                    snapshot = sniffer.get_and_clear_buffer()
                    if snapshot:
                        # 3a. Сбор статистики
                        device_stats = defaultdict(
                            lambda: {"bytes": 0, "packets": 0, "protocols": set(), "domains": set()})
                        for packet in snapshot:
                            local_ip = None
                            if is_local_ip(packet.src_ip):
                                local_ip = packet.src_ip
                            elif is_local_ip(packet.dst_ip):
                                local_ip = packet.dst_ip
                            if local_ip:
                                stats = device_stats[local_ip]
                                stats["bytes"] += packet.length;
                                stats["packets"] += 1
                                stats["protocols"].add(packet.protocol)
                                if packet.domain: stats["domains"].add(packet.domain)

                        if device_stats:
                            for ip, stats in device_stats.items():
                                db.session.add(TrafficLog(local_ip=ip, total_bytes=stats["bytes"],
                                                          packet_count=stats["packets"],
                                                          protocols=','.join(stats["protocols"]),
                                                          domains=','.join(stats["domains"])))

                        # 3b. ML-Предсказание
                        if ml_detector:
                            feature_vector_obj = extract_features(snapshot, datetime.now())
                            anomaly_score = ml_detector.predict(feature_vector_obj.get_ml_vector())
                            is_alert = (
                                        anomaly_score > ml_detector.initial_threshold) if active_model_in_memory.model_type == 'tensorflow' else (
                                        anomaly_score < ml_detector.initial_threshold)
                            local_status.update({"current_score": float(anomaly_score), "is_anomaly": bool(is_alert)})
                            if is_alert: _log(f"АНОМАЛИЯ! Score: {anomaly_score:.4f}", "danger")

                # 4. Запись статуса в БД
                status_to_write = local_status.copy()
                status_to_write["log"] = list(status_to_write["log"])
                active_state_from_db.worker_status_json = json.dumps(status_to_write)
                db.session.commit()

        except Exception as e:
            print("--- КРИТИЧЕСКАЯ ОШИБКА ВОРКЕРА ---")
            traceback.print_exc()
            print("---------------------------------")

        time.sleep(TIME_WINDOW)


if __name__ == '__main__':
    run_main_worker()

