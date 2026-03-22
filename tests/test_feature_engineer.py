import pytest
import numpy as np
from datetime import datetime
from feature_engineer import shannon_entropy, extract_features


class TestShannonEntropy:
    """Группа тестов для вычисления энтропии портов"""

    def test_entropy_empty_list(self):
        # Краевой случай: списка нет
        assert shannon_entropy([]) == 0.0

    def test_entropy_single_element(self):
        # Энтропия списка из 1 элемента всегда 0 (нет неопределенности)
        assert shannon_entropy([443, 443, 443, 443]) == 0.0

    def test_entropy_mixed_elements(self):
        # Равномерное распределение: два разных значения (50/50), энтропия = 1.0 (1 бит информации)
        assert shannon_entropy([80, 443]) == 1.0
        # Энтропия из 4 разных элементов 25% должна быть 2.0
        assert shannon_entropy([80, 443, 53, 22]) == 2.0


class TestFeatureExtraction:
    """Группа тестов для ML агрегации фич"""

    def test_extract_empty_features(self, empty_packets):
        """Если трафика не было (сеть пуста), система должна отдать безопасные нули"""
        current_time = datetime.now()
        fv = extract_features(empty_packets, current_time)

        # Мы ожидаем вектор из 13 нулей
        assert len(fv.features) == 13
        assert sum(fv.features) == 0.0
        assert fv.source_info['Total_Packets'] == 0

        # Проверяем интеграцию с Numpy для Keras/Scikit-learn
        ml_vector = fv.get_ml_vector()
        assert isinstance(ml_vector, np.ndarray)
        assert ml_vector.shape == (1, 13)  # Строгий формат для подачи в нейросеть (Batch 1, 13 features)

    def test_extract_features_math_correctness(self, mixed_traffic_snapshot):
        """Проверяем, как собирается вектор на тестовых 4-х пакетах из фикстуры"""
        fv = extract_features(mixed_traffic_snapshot, window_end_time=datetime.now())
        features = fv.features

        # Проверки конкретных вычислений фич по нашим правилам из feature_engineer.py:

        # Фича 1: Общее количество пакетов (в фикстуре их 4)
        assert features[0] == 4.0

        # Фича 2: Сумма длин всех пакетов (64 + 1500 + 120 + 40)
        assert features[1] == 1724.0

        # Фича 6: Соотношение UDP пакетов (1 UDP из 4 пакетов = 0.25)
        assert features[5] == 0.25

        # Фича 7: Количество уникальных IP-источников ("192.168.1.5", "8.8.8.8", "192.168.1.100") -> 3
        assert features[6] == 3.0

        # Фича 10: Уникальных целевых IP (8.8.8.8, 192.168.1.5, 1.1.1.1, 10.0.0.1) -> 4
        assert features[9] == 4.0

        # Фича 5: Доля SYN пакетов среди TCP (TCP у нас 3. В двух стоит {'SYN': True} без {'ACK': True}??
        # Смотрим: Пакет 1 - чистый SYN (True). Пакет 4 - SYN+ACK (SYN=True, ACK=True). По правилам в `extract_features` это НЕ считается за чистый SYN
        # Значит чистый SYN только один = 1 / 3 TCP = 0.3333333...
        assert features[4] == pytest.approx(1 / 3)