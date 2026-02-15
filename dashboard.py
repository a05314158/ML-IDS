# dashboard.py

import streamlit as st
import plotly.express as px
import pandas as pd
import time
import os

# Импорт из разработанных модулей
from config import TIME_WINDOW
from data_structures import SharedDataFile

# --- Настройка страницы Streamlit ---
st.set_page_config(
    page_title="ML-IDS: Мониторинг Сетевых Аномалий",
    page_icon="🛡️",
    layout="wide"
)


# --- Функции для получения данных ---
# @st.cache_data говорит Streamlit кэшировать данные на 1 секунду,
# чтобы не перегружать систему при частых обновлениях.
@st.cache_data(ttl=1)
def get_live_data(_shared_data_file: SharedDataFile):
    """
    Безопасно извлекает все данные для дашборда.
    Параметр `_shared_data_file` с подчеркиванием говорит Streamlit не хэшировать сам объект.
    """
    return _shared_data_file.get_all_data_for_dashboard()


def display_dashboard():
    """Главная функция для отображения дашборда."""
    shared_data_file = SharedDataFile()

    st.title("🛡️ ML-IDS: Мониторинг Сетевых Аномалий")
    st.markdown(f"**ML-Модель:** Isolation Forest | **Окно агрегации (T):** {TIME_WINDOW} сек.")

    # Инструкции по запуску
    st.info(
        """
        **Для начала работы:**
        1. Убедитесь, что вы запустили `worker.py` в отдельном терминале с правами администратора (`sudo python worker.py`).
        2. Дашборд обновится автоматически, как только worker начнет передавать данные.
        """, icon="🚀"
    )

    placeholder = st.empty()

    while True:
        current_status, df_history, df_alerts = get_live_data(shared_data_file)

        with placeholder.container():
            # --- Секция 1: Статус и метрики ---
            st.subheader("Статус и Текущие Метрики")
            col1, col2, col3 = st.columns(3)

            is_running = current_status.get('is_running', False)
            mode = "ИДЕТ ОБУЧЕНИЕ" if current_status.get('is_baseline_mode', True) else "МОНИТОРИНГ"
            status_color = "green" if is_running and mode == "МОНИТОРИНГ" else ("blue" if is_running else "red")

            col1.metric(label="Статус IDS", value=mode, delta="ONLINE" if is_running else "OFFLINE",
                        delta_color=status_color)
            col2.metric(label="Сетевой Интерфейс", value=current_status.get('current_interface', 'N/A'))
            # Получаем АДАПТИВНЫЙ порог
            anomaly_threshold = current_status.get('current_adaptive_threshold', -0.1)
            col3.metric(label="Адаптивный Порог", value=f"{anomaly_threshold:.4f}")

            # --- Секция 2: График в реальном времени ---
            st.subheader("Мониторинг Anomaly Score")
            if not df_history.empty:
                # Определяем цвет точки в зависимости от того, была ли она аномалией
                df_history['Color'] = df_history['Is_Anomaly'].apply(lambda x: 'red' if x else 'green')

                fig = px.scatter(
                    df_history,
                    x='Time (s)',
                    y='Anomaly Score',
                    color='Color',
                    color_discrete_map={'green': '#2ECC71', 'red': '#E74C3C'},
                    height=400,
                    title="Динамика Anomaly Score"
                )
                # Рисуем линию АДАПТИВНОГО порога
                fig.add_hline(y=anomaly_threshold, line_dash="dash", line_color="orange",
                              annotation_text="Адаптивный порог", annotation_position="bottom right")
                fig.update_layout(showlegend=False)

                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Ожидание данных от worker'а...")

            # --- Секция 3: Журнал Алертов ---
            st.subheader("Журнал Активных Алертов")
            if not df_alerts.empty:
                df_alerts_display = df_alerts[['Time', 'Score', 'Reason', 'Source IP']]
                st.dataframe(df_alerts_display.style.applymap(lambda x: 'color: #E74C3C', subset=['Score']),
                             use_container_width=True)
            else:
                st.info("Аномалии не обнаружены.")

        time.sleep(1)  # Пауза перед следующим обновлением дашборда


if __name__ == '__main__':
    display_dashboard()
