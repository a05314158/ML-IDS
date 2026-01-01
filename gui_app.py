# gui_app.py
import tkinter as tk
from tkinter import ttk, scrolledtext
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import time
from typing import List, Callable, Dict, Tuple

# Импортируем функцию поиска интерфейсов
from config import TIME_WINDOW, get_available_interfaces

# Значение по умолчанию для порога, пока модель не обучена
DEFAULT_ANOMALY_THRESHOLD = -0.10


class MLIDS_GUI:
    # Добавляем reset_callback в аргументы
    def __init__(self, master: tk.Tk, start_callback: Callable, stop_callback: Callable, reset_callback: Callable):
        self.master = master
        self.master.title("ML-IDS: Обнаружение Аномалий (Tkinter)")
        self.master.geometry("1000x800")

        self.start_callback = start_callback
        self.stop_callback = stop_callback
        self.reset_callback = reset_callback

        self.is_running = False
        self.threshold = DEFAULT_ANOMALY_THRESHOLD

        # --- Переменные для управления ---
        self.interfaces_list = get_available_interfaces()  # <--- ВОССТАНОВЛЕН ПОИСК
        self.interface_labels = [desc for _, desc in self.interfaces_list]

        self.selected_iface_label = tk.StringVar(master)
        if self.interface_labels:
            self.selected_iface_label.set(self.interface_labels[0])
        else:
            self.selected_iface_label.set("Нет интерфейсов")

        self.port_filter = tk.StringVar(master, value="ip and (tcp or udp)")

        # --- Переменные для графика ---
        self.times: List[float] = []
        self.scores: List[float] = []
        self.start_time: float = time.time()

        self._create_widgets()
        self._init_graph()
        self.master.after(100, self.update_gui_loop)

    def _create_widgets(self):
        # 1. Секция управления (Сверху)
        control_frame = ttk.Frame(self.master, padding="10")
        control_frame.pack(fill='x')

        # *** ВОССТАНОВЛЕН ВЫПАДАЮЩИЙ СПИСОК АДАПТЕРОВ ***
        ttk.Label(control_frame, text="Выберите интерфейс:").pack(side='left', padx=5, pady=5)
        self.iface_combo = ttk.Combobox(control_frame, textvariable=self.selected_iface_label,
                                        values=self.interface_labels, width=30, state='readonly')
        self.iface_combo.pack(side='left', padx=5, pady=5)

        # Выбор фильтра BPF
        ttk.Label(control_frame, text="BPF Фильтр:").pack(side='left', padx=15, pady=5)
        self.filter_entry = ttk.Entry(control_frame, textvariable=self.port_filter, width=20)
        self.filter_entry.pack(side='left', padx=5, pady=5)

        # Кнопка СТАРТ/СТОП
        self.start_button = ttk.Button(control_frame, text="СТАРТ МОНИТОРИНГА", command=self._toggle_monitoring,
                                       style='Green.TButton')
        self.start_button.pack(side='left', padx=15, pady=5)

        # КНОПКА СБРОСА
        self.reset_button = ttk.Button(control_frame, text="СБРОС/ПЕРЕОБУЧЕНИЕ", command=self._reset_monitoring,
                                       style='Red.TButton')
        self.reset_button.pack(side='left', padx=15, pady=5)

        # Создание стилей
        style = ttk.Style()
        style.configure('Green.TButton', background='green', foreground='black')
        style.configure('Red.TButton', background='red', foreground='black')

        # 2. Секция графика (Центр)
        graph_frame = ttk.Frame(self.master, padding="10")
        graph_frame.pack(fill='both', expand=True)
        self.fig = Figure(figsize=(10, 5), dpi=100)
        self.ax = self.fig.add_subplot(111)

        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas_widget = self.canvas.get_tk_widget()
        self.canvas_widget.pack(fill='both', expand=True)

        # 3. Секция логов (Внизу)
        log_frame = ttk.Frame(self.master, padding="10")
        log_frame.pack(fill='x')
        ttk.Label(log_frame, text="Журнал Алертов:").pack(fill='x')

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=100, height=10)
        self.log_text.pack(fill='x', padx=5, pady=5)
        self.log_text.tag_config('alert', foreground='red', font=('TkFixedFont', 10, 'bold'))
        self.log_text.tag_config('info', foreground='blue')
        self.log_text.tag_config('normal', foreground='green')

    def _init_graph(self):
        """Настройка начального вида графика."""
        self.ax.clear()
        self.ax.set_title("Anomaly Score vs. Time")
        self.ax.set_xlabel("Time (s)")
        self.ax.set_ylabel("Anomaly Score")
        # Используем self.threshold
        self.ax.axhline(self.threshold, color='r', linestyle='--', label=f'Alert Threshold ({self.threshold:.4f})')
        self.line, = self.ax.plot([], [], 'g-')
        self.scatter = self.ax.scatter([], [], color='g', s=20)
        self.ax.legend()
        self.canvas.draw()

    def _toggle_monitoring(self):
        """Обработчик нажатия кнопки СТАРТ/СТОП."""
        if self.is_running:
            # СТОП
            self.stop_callback()
            self.start_button.config(text="СТАРТ МОНИТОРИНГА", style='Green.TButton')
            self.filter_entry.config(state='enabled')
            self.iface_combo.config(state='readonly')  # Разблокируем выбор интерфейса
            self.is_running = False
            self.log_message("Система остановлена.", 'info')
        else:
            # СТАРТ
            chosen_label = self.selected_iface_label.get()
            # Находим системное имя (GUID) по выбранному описанию
            real_iface_name = next(
                (sys_name for sys_name, user_label in self.interfaces_list if user_label == chosen_label), None)

            if not real_iface_name:
                self.log_message("Ошибка: Неверный интерфейс! Выберите адаптер из списка.", "alert")
                return

            bpf_filter = self.filter_entry.get()

            self.start_callback(real_iface_name, bpf_filter)  # <--- ПЕРЕДАЕМ СИСТЕМНОЕ ИМЯ

            self.start_button.config(text="СТОП МОНИТОРИНГА", style='Red.TButton')
            self.filter_entry.config(state='disabled')
            self.iface_combo.config(state='disabled')  # Блокируем выбор интерфейса
            self.is_running = True
            self._reset_graph()
            self.log_message(f"Система запущена. Интерфейс: {chosen_label}. Фильтр: {bpf_filter}", 'info')

    def _reset_monitoring(self):
        """Обработчик нажатия кнопки СБРОС/ПЕРЕОБУЧЕНИЕ."""
        if self.is_running:
            self.log_message("Сначала остановите мониторинг!", 'alert')
        else:
            self.master.after_idle(self.reset_callback)
            self.log_message("Запрошен сброс модели. Модель будет переобучена при следующем запуске.", 'alert')

    def _reset_graph(self):
        """Сброс данных графика при старте."""
        self.times = []
        self.scores = []
        self.start_time = time.time()
        self._init_graph()

    def log_message(self, message: str, tag: str = 'normal'):
        """Вывод сообщения в текстовый лог."""
        self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n", tag)
        self.log_text.see(tk.END)

    def update_threshold(self, new_threshold: float):
        """Обновляет порог и перерисовывает график."""
        self.threshold = new_threshold
        self._init_graph()
        self.canvas.draw()

    def update_graph(self, score: float, is_anomaly: bool):
        """Обновление графика новыми данными."""
        current_time = time.time() - self.start_time
        self.times.append(current_time)
        self.scores.append(score)

        self.line.set_data(self.times, self.scores)
        self.scatter.set_offsets(list(zip(self.times, self.scores)))

        colors = ['red' if s < self.threshold else 'green' for s in self.scores]
        self.scatter.set_color(colors)

        x_min = max(0, current_time - 60)
        x_max = max(60, current_time)
        self.ax.set_xlim(x_min, x_max)

        if self.scores:
            y_min = min(min(self.scores), self.threshold) - 0.1
            y_max = max(max(self.scores), self.threshold) + 0.1
            self.ax.set_ylim(y_min, y_max)

        self.canvas.draw_idle()

    def update_gui_loop(self):
        """Главный цикл обновления Tkinter (вызывается каждые 100 мс)."""
        self.master.after(100, self.update_gui_loop)


if __name__ == '__main__':
    # Изолированный запуск
    root = tk.Tk()
    # Заглушки для теста
    app = MLIDS_GUI(root, lambda x, y: print("Start"), lambda: print("Stop"), lambda: print("Reset"))
    root.mainloop()