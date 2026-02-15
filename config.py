# config.py (ПОЛНАЯ ФИНАЛЬНАЯ ВЕРСИЯ)
import os

# --- Основные настройки ---
TIME_WINDOW = 5             # Окно агрегации трафика в секундах (T)
BPF_FILTER = "ip"           # Фильтр для Scapy, ловим весь IP-трафик
TRAIN_DURATION_MINUTES = 2  # Время обучения в минутах (для ML-панели)

# --- Настройки ML-моделей ---
MODEL_DIR = "models"
NUM_FEATURES = 13
CONTAMINATION = 0.035 # Для Isolation Forest
# --- ВОЗВРАЩАЕМ НЕДОСТАЮЩУЮ НАСТРОЙКУ ---
BURST_WINDOW_SECONDS = 0.1 # Временное окно для расчета "Burst_Rate"
# ----------------------------------------

# --- Настройки TensorFlow Автоэнкодера ---
NN_EPOCHS = 100
NN_LEARNING_RATE = 0.001
NN_BATCH_SIZE = 32
NN_HIDDEN_LAYER_SIZE = 6

# --- Настройки АДАПТИВНОГО ПОРОГА ---
SCORE_HISTORY_SIZE = 300
ADAPTIVE_THRESHOLD_PERCENTILE_IF = 2.0  # Для Isolation Forest (ищем низкие значения)
ADAPTIVE_THRESHOLD_PERCENTILE_TF = 98.0 # Для TensorFlow (ищем высокие значения)

