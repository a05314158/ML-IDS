# config.py (Полная и правильная версия)

import os

# --- Основные настройки ---
TRAIN_DURATION_MINUTES = 10 # Время обучения в минутах
TIME_WINDOW = 5             # Окно агрегации трафика в секундах (T)
BPF_FILTER = "ip"           # Фильтр для Scapy, ловим весь IP-трафик

# --- Настройки буфера и признаков ---
MAX_BUFFER_SIZE = 10000
NUM_FEATURES = 13
BURST_WINDOW_SECONDS = 0.1

# --- Настройки путей (остаются для совместимости) ---
MODEL_DIR = "models"
# Замечание: TensorFlow сохраняет модели в своем формате (как папку),
# поэтому MODEL_PATH теперь указывает на директорию.
MODEL_PATH = os.path.join(MODEL_DIR, "tf_autoencoder_model")
SCALER_PATH = os.path.join(MODEL_DIR, "standard_scaler.joblib")
INITIAL_THRESHOLD_PATH = os.path.join(MODEL_DIR, "initial_threshold.joblib")

# --- Настройки TensorFlow Автоэнкодера ---
NN_EPOCHS = 100              # Эпох может быть меньше, TF учится эффективнее
NN_LEARNING_RATE = 0.001       # Скорость обучения для Adam
NN_BATCH_SIZE = 32             # Размер пакета данных на одной итерации обучения
NN_HIDDEN_LAYER_SIZE = 6       # Размер сжатого слоя (должен быть < NUM_FEATURES)

# --- Настройки АДАПТИВНОГО ПОРОГА (для Автоэнкодера) ---
SCORE_HISTORY_SIZE = 300
ADAPTIVE_THRESHOLD_PERCENTILE = 98.0 # Ищем выбросы с высокой ошибкой

# --- Устаревшая настройка (нужна для worker.py, но не используется в TF) ---
# worker.py все еще импортирует CONTAMINATION, оставим его, чтобы избежать ошибок.
CONTAMINATION = 0.035
