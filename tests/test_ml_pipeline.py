import pytest
import numpy as np
import os
import shutil
from ml_model import IsolationForestDetector, TFAutoencoderDetector


@pytest.fixture
def dummy_dataset():
    """Генерирует 100 векторов 'нормального' трафика для обучения"""
    return np.random.rand(100, 13)


def test_isolation_forest_workflow(dummy_dataset, tmp_path):
    # Создаем временную папку для модели
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    model_path = str(model_dir / "test_iforest")

    detector = IsolationForestDetector()
    # 1. Тренировка
    detector.train_and_save_model(dummy_dataset, model_path)

    # 2. Проверка файлов
    assert os.path.exists(f"{model_path}.joblib")

    # 3. Загрузка
    new_detector = IsolationForestDetector()
    assert new_detector.load(model_path) is True

    # 4. Предсказание
    score = new_detector.predict(np.random.rand(1, 13))
    assert isinstance(score, float)


def test_tf_autoencoder_workflow(dummy_dataset, tmp_path):
    model_dir = tmp_path / "models_tf"
    model_dir.mkdir()
    model_path = str(model_dir / "test_tf")

    detector = TFAutoencoderDetector()
    # 1. Тренировка
    detector.train_and_save_model(dummy_dataset, model_path)

    # 2. Проверка файла модели (.keras)
    assert os.path.exists(f"{model_path}.keras")

    # 3. Загрузка
    new_detector = TFAutoencoderDetector()
    assert new_detector.load(model_path) is True

    # 4. Предсказание (Reconstruction Error)
    score = new_detector.predict(np.random.rand(1, 13))
    assert score >= 0