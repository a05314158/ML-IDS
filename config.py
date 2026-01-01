# config.py
from scapy.all import get_if_list, get_if_addr, conf
from typing import List, Tuple
import os

# --- Константы для Фазы 2: Захват и буферизация ---
INTERFACE = "Ethernet"
BPF_FILTER = "ip and (tcp or udp)"
MAX_BUFFER_SIZE = 10000

# --- Константы для Фазы 3: Извлечение признаков ---
TIME_WINDOW = 5
NUM_FEATURES = 10

# --- Константы для Фазы 4: Машинное обучение ---
MODEL_PATH = "isolation_forest_model.joblib"
SCALER_PATH = "standard_scaler.joblib"
CONTAMINATION = 0.01

# --- КОНСТАНТЫ ДЛЯ АВТОМАТИЧЕСКОГО ПОРОГА ---
THRESHOLD_FILE = "anomaly_threshold.pkl"

def get_available_interfaces() -> List[Tuple[str, str]]:
    """
    Универсальная функция для получения списка сетевых интерфейсов.
    Возвращает список кортежей: (системное_имя_для_scapy, понятное_описание_для_юзера)
    """
    ifaces = []
    try:
        # Отключаем promisc режим при сканировании, чтобы не зависало
        conf.sniff_promisc = False

        # Получаем список всех интерфейсов от Scapy
        scapy_ifaces = get_if_list()

        for iface in scapy_ifaces:
            # Фильтрация: убираем loopback (замыкание на себя)
            # В Windows loopback часто называется 'lo0' или содержит 'Loopback'
            # В Linux 'lo'
            if 'loopback' in iface.lower() or iface.lower() == 'lo':
                continue

            ip = "Нет IP"
            try:
                # Пытаемся получить IP адрес интерфейса
                found_ip = get_if_addr(iface)
                if found_ip and found_ip != "0.0.0.0":
                    ip = found_ip
            except:
                pass

            # Для Windows Scapy использует сложные имена типа \Device\NPF_{...}
            # Мы будем показывать пользователю часть этого имени и IP, чтобы он понял

            # Описание для GUI
            description = f"{iface} [{ip}]"

            # Если это Windows и имя очень длинное, можно попробовать найти более короткое название,
            # но надежнее показывать IP, так как пользователь знает IP своего компьютера.

            # Добавляем в список (Имя_для_кода, Имя_для_GUI)
            ifaces.append((iface, description))

    except Exception as e:
        print(f"Ошибка при получении списка интерфейсов: {e}")
        # Если все сломалось, возвращаем хотя бы пустой список, чтобы программа не упала сразу

    if not ifaces:
        # Заглушка, если ничего не найдено
        ifaces.append(("eth0", "Интерфейсы не найдены (Проверьте права админа)"))

    return ifaces