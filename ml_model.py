# ml_model.py
import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Optional

# *** ИСПРАВЛЕНИЕ: Убедитесь, что импорт из config.py выглядит так: ***
from config import MODEL_PATH, SCALER_PATH, CONTAMINATION, NUM_FEATURES, THRESHOLD_FILE


class MLAnomalyDetector:

    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.threshold: float = -0.10

    def train_and_save_model(self, X_train: np.ndarray):
        # ... (логика обучения) ...
        # 3. АВТОМАТИЧЕСКИЙ РАСЧЕТ ПОРОГА
        scores = self.model.decision_function(X_scaled)
        self.threshold = np.min(scores) - 0.01

        # 4. Сохранение
        joblib.dump(self.model, MODEL_PATH)
        joblib.dump(self.scaler, SCALER_PATH)
        joblib.dump(self.threshold, THRESHOLD_FILE)  # <--- ИСПОЛЬЗУЕМ THRESHOLD_FILE ИЗ CONFIG

        print(f"[ML] Обучение завершено. Порог установлен автоматически: {self.threshold:.4f}")

    def load_model(self) -> bool:
        """Загружает обученную модель, скалер И порог с диска."""
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH) and os.path.exists(THRESHOLD_FILE):
            try:
                self.model = joblib.load(MODEL_PATH)
                self.scaler = joblib.load(SCALER_PATH)
                self.threshold = joblib.load(THRESHOLD_FILE)  # <--- ЗАГРУЖАЕМ ПОРОГ
                print(f"[ML] Модель и Scaler успешно загружены. Порог: {self.threshold:.4f}")
                return True
            except:
                print("[ML] Ошибка при загрузке модели. Переобучение.")
                return False

        print("[ML] Файлы модели не найдены. Необходимо обучить модель.")
        return False
    def predict(self, X_new: np.ndarray) -> float:
        """
        Выполняет потоковое предсказание Anomaly Score для нового вектора признаков.
        (Фаза 4.2)
        """
        if self.model is None or self.scaler is None:
            # Если модель не загружена, возвращаем безопасное значение (0.0 - норма)
            return 0.0

            # 1. Нормализация вектора НОВЫМИ данными (обязательно transform, а не fit_transform!)
        X_scaled = self.scaler.transform(X_new)

        # 2. Получение Anomaly Score (decision_function)
        # Возвращает массив, берем первый (и единственный) элемент
        anomaly_score = self.model.decision_function(X_scaled)[0]

        return anomaly_score


if __name__ == '__main__':
    print("Тест ML модуля")
    # ... (тестовый блок можно оставить или удалить, он не обязателен для работы main)