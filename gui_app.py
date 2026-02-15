# gui_app.py (Финальная версия с исправленными опечатками)

import tkinter as tk
from tkinter import ttk, scrolledtext
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
from typing import Callable, List, Any

try:
    from scapy.all import conf

    conf.route.resync()
except ImportError:
    conf = None


def get_available_interfaces() -> List[tuple[Any, str]]:
    """Возвращает список кортежей (ОБЪЕКТ_ИНТЕРФЕЙСА, описание)."""
    if conf is None:
        print("Критическая ошибка: библиотека Scapy не найдена.")
        return []
    ifaces = []
    try:
        for iface_object in conf.ifaces.values():
            is_loopback = getattr(iface_object, 'is_loopback', lambda: False)()
            is_active = iface_object.flags & 1
            if not is_active or is_loopback:
                continue
            desc = iface_object.description.lower()
            if 'virtual' in desc or 'miniport' in desc or 'bluetooth' in desc:
                continue
            description_for_gui = f"{iface_object.description} [{iface_object.ip}]"
            ifaces.append((iface_object, description_for_gui))
    except Exception as e:
        print(f"Ошибка получения интерфейсов: {e}")
    return ifaces


class MLIDS_GUI:
    def __init__(self, master: tk.Tk, start_cb: Callable, stop_cb: Callable, reset_cb: Callable):
        self.master = master
        self.master.title("ML-IDS: Система Обнаружения Аномалий")
        self.master.geometry("1100x850");
        self.master.minsize(800, 600)
        top_frame = ttk.Frame(self.master);
        top_frame.pack(side='top', fill='x', padx=10, pady=5)
        main_pane = ttk.PanedWindow(self.master, orient='vertical');
        main_pane.pack(side='top', fill='both', expand=True, padx=10, pady=5)
        self.start_callback, self.stop_callback, self.reset_callback = start_cb, stop_cb, reset_cb
        self.is_running, self.threshold = False, -0.1
        self.times, self.scores = [], []
        self.start_time = time.time()
        self._create_controls(top_frame)

        # ИСПРАВЛЕНО: p=5 заменено на padding=5
        graph_frame = ttk.Frame(main_pane, padding=5)
        log_frame = ttk.Frame(main_pane, padding=5)

        main_pane.add(graph_frame, weight=3);
        main_pane.add(log_frame, weight=1)
        self._create_graph_view(graph_frame);
        self._create_log_view(log_frame)
        self._init_graph();
        self.check_interfaces_and_update_gui()

    def check_interfaces_and_update_gui(self):
        if not self.interfaces_list:
            self.start_button.config(state='disabled');
            self.iface_combo.config(state='disabled')
            self.selected_iface_label.set("ИНТЕРФЕЙСЫ НЕ НАЙДЕНЫ")
            self.log_message(
                "Критическая ошибка: Сетевые адаптеры не найдены.\n1. Убедитесь, что программа запущена с правами администратора.\n2. Убедитесь, что Npcap установлен в режиме совместимости.",
                'alert')

    def _create_controls(self, parent_frame: ttk.Frame):
        parent_frame.grid_columnconfigure(1, weight=1)
        ttk.Label(parent_frame, text="Интерфейс:").grid(row=0, column=0, sticky='w', padx=(0, 5))
        self.interfaces_list = get_available_interfaces()
        self.interface_labels = [desc for _, desc in self.interfaces_list]
        self.selected_iface_label = tk.StringVar(self.master)
        if self.interface_labels: self.selected_iface_label.set(self.interface_labels[0])
        self.iface_combo = ttk.Combobox(parent_frame, textvariable=self.selected_iface_label,
                                        values=self.interface_labels, state='readonly')
        self.iface_combo.grid(row=0, column=1, sticky='ew')
        self.start_button = ttk.Button(parent_frame, text="▶", command=self._toggle_monitoring, style='Green.TButton',
                                       width=4)
        self.start_button.grid(row=0, column=2, sticky='e', padx=5)
        self.reset_button = ttk.Button(parent_frame, text="♻", command=self._reset_monitoring, style='Blue.TButton',
                                       width=4)
        self.reset_button.grid(row=0, column=3, sticky='e', padx=5)
        self.status_label = ttk.Label(parent_frame, text="Статус: Остановлено", font=('Helvetica', 10, 'bold'))
        self.status_label.grid(row=1, column=0, columnspan=2, sticky='w', pady=(5, 0))
        self.threshold_label = ttk.Label(parent_frame, text=f"Порог: {self.threshold:.4f}", font=('Helvetica', 10))
        self.threshold_label.grid(row=1, column=1, columnspan=3, sticky='e', pady=(5, 0))
        style = ttk.Style();
        style.configure('TButton', font=('Helvetica', 10, 'bold'))

    def _create_graph_view(self, parent_frame: ttk.Frame):
        self.fig = Figure(dpi=100);
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, master=parent_frame)
        self.canvas.get_tk_widget().pack(fill='both', expand=True)

    def _create_log_view(self, parent_frame: ttk.Frame):
        parent_frame.grid_rowconfigure(1, weight=1);
        parent_frame.grid_columnconfigure(0, weight=1)
        ttk.Label(parent_frame, text="Журнал:").grid(row=0, column=0, sticky='w')
        # ИСПРАВЛЕНО: h=8 заменено на height=8
        self.log_text = scrolledtext.ScrolledText(parent_frame, wrap=tk.WORD, height=8)
        self.log_text.grid(row=1, column=0, sticky='nsew', pady=(5, 0))
        self.log_text.tag_config('alert', foreground='#E74C3C');
        self.log_text.tag_config('info', foreground='#3498DB');
        self.log_text.tag_config('ok', foreground='#2ECC71')

    def _init_graph(self):
        self.ax.clear();
        self.ax.set_title("Мониторинг Anomaly Score");
        self.ax.set_xlabel("Время");
        self.ax.set_ylabel("Score")
        self.threshold_line = self.ax.axhline(self.threshold, color='orange', linestyle='--', label='Порог')
        self.line, = self.ax.plot([], [], '-o', color='#2ECC71', lw=1.5, markersize=4);
        self.ax.legend();
        self.fig.tight_layout();
        self.canvas.draw()

    def _toggle_monitoring(self):
        if self.is_running:
            self.stop_callback();
            self.start_button.config(text="▶", style='Green.TButton')
            self.iface_combo.config(state='readonly');
            self.is_running = False
            self.status_label.config(text="Статус: Остановлено")
        else:
            chosen_label = self.selected_iface_label.get()
            real_iface_object = next((obj for obj, label in self.interfaces_list if label == chosen_label), None)
            if not real_iface_object: self.log_message("Ошибка: Интерфейс не выбран.", "alert"); return
            self.start_callback(real_iface_object);
            self.start_button.config(text="■", style='Red.TButton')
            self.iface_combo.config(state='disabled');
            self.is_running = True
            self.status_label.config(text="Статус: Запущено");
            self._reset_graph()

    def _reset_monitoring(self):
        if self.is_running:
            self.log_message("Сначала остановите мониторинг!", "alert")
        else:
            self.reset_callback(); self.log_message("Запрошен сброс.", "info")

    def _reset_graph(self):
        self.times, self.scores = [], [];
        self.start_time = time.time();
        self._init_graph()

    def log_message(self, m, t='info'):
        self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {m}\n", t);
        self.log_text.see(tk.END)

    def update_gui(self, score, is_anomaly, new_threshold):
        self.threshold = new_threshold;
        self.threshold_label.config(text=f"Порог: {self.threshold:.4f}")
        self.threshold_line.set_ydata([self.threshold]);
        self.times.append(time.time() - self.start_time);
        self.scores.append(score)
        if len(self.times) > 100: self.times.pop(0); self.scores.pop(0)
        self.line.set_data(self.times, self.scores);
        self.line.set_markerfacecolor('#E74C3C' if is_anomaly else 'white')
        if self.times:
            y_min = min(min(self.scores, default=0), self.threshold) - 0.05;
            y_max = max(max(self.scores, default=0), self.threshold) + 0.05
            self.ax.set_xlim(self.times[0] - 1, self.times[-1] + 5);
            self.ax.set_ylim(y_min, y_max)
        self.canvas.draw_idle()
