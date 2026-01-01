# visualizer.py
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from datetime import datetime
import time


class RealtimeVisualizer:
    """
    Класс для интерактивной визуализации Anomaly Score (Фаза 5.2).
    На старте отображает счетчик пакетов.
    """

    def __init__(self, time_window: int, anomaly_threshold: float):
        self.time_window = time_window
        self.anomaly_threshold = anomaly_threshold

        self.times = []
        self.scores = []
        self.packet_counts = []

        # Настройка графика Matplotlib
        self.fig, self.ax = plt.subplots(figsize=(10, 6))
        self.line, = self.ax.plot([], [], 'g-', label='Anomaly Score')  # Инициализируем зеленым цветом
        self.scatter = self.ax.scatter([], [], color='g', s=30)  # Точки

        self.ax.axhline(self.anomaly_threshold, color='r', linestyle='--', label='Alert Threshold')
        self.ax.set_title("Real-time Anomaly Score (ML-IDS)")
        self.ax.set_xlabel("Time (s)")
        self.ax.set_ylabel("Anomaly Score (Y) / Pkt Count (Initial)")
        self.ax.legend()
        self.fig.autofmt_xdate()

        # Для анимации
        self.anim = None
        self.start_time = time.time()

    def _update(self, frame):
        """Функция обновления, вызываемая Matplotlib Anination."""

        # Обновляем пределы оси X в зависимости от текущего времени
        current_time_s = time.time() - self.start_time
        # Показываем последние 60 секунд
        self.ax.set_xlim(max(0, current_time_s - 60), max(60, current_time_s))

        # Перерисовка графика
        self.line.set_data(self.times, self.scores)
        self.scatter.set_offsets(list(zip(self.times, self.scores)))

        # Цветовая кодировка точек (Зеленый = Норма, Красный = Аномалия)
        colors = ['red' if score < self.anomaly_threshold else 'green' for score in self.scores]
        self.scatter.set_color(colors)

        # Перерисовать заголовок, чтобы показать текущее состояние
        if self.scores and self.scores[-1] < self.anomaly_threshold:
            self.ax.set_title(f"ALERT! Anomaly Detected (Score: {self.scores[-1]:.3f})", color='red')
        else:
            self.ax.set_title(f"Running... Last Pkts: {self.packet_counts[-1] if self.packet_counts else 0}")

        return self.line, self.scatter

    def add_data(self, score: float, packet_count: int):
        """Добавляет новую точку данных."""
        current_time = time.time() - self.start_time
        self.times.append(current_time)
        self.scores.append(score)
        self.packet_counts.append(packet_count)

    def start_animation(self):
        """Запускает интерактивный график Matplotlib."""
        plt.ion()  # Включаем интерактивный режим
        self.anim = FuncAnimation(
            self.fig,
            self._update,
            # Интервал обновления графика (должен быть меньше TIME_WINDOW)
            interval=self.time_window * 1000 * 0.2,
            blit=False
        )
        plt.show(block=False)

    def close(self):
        """Закрывает окно графика."""
        plt.close(self.fig)

# Примечание: Вначале, до обучения модели, мы будем отображать Packet Count
# вместо Anomaly Score, используя счетчик как временный "Score" для визуализации.