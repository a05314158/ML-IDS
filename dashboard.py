# dashboard.py
import streamlit as st
import plotly.express as px
import pandas as pd
import time
from typing import Dict, List

# Импорт из разработанных модулей
from config import ANOMALY_THRESHOLD, TIME_WINDOW
from data_structures import SharedDataFile

# --- Настройка Streamlit ---
st.set_page_config(layout="wide")


@st.cache_data(ttl=1)
def get_live_data(_shared_data_file: SharedDataFile):
    """
    Безопасно извлекает данные для кэширования.
    Параметр _shared_data_file с подчеркиванием исключен из кэширования.
    """
    return _shared_data_file.get_status(), _shared_data_file.get_history_df(), _shared_data_file.get_alerts_df()


def display_dashboard():
    """
    Главная функция для отображения дашборда Streamlit.
    """
    # Инициализация файлового обмена (только для чтения)
    shared_data_file = SharedDataFile()

    st.title("🛡️ ML-IDS: Обнаружение Аномалий в Сетевом Трафике")
    st.markdown(f"**ML-Модель:** Isolation Forest | **Окно агрегации (T):** {TIME_WINDOW} сек.")

    # Создание пустого контейнера для обновления в реальном времени
    placeholder = st.empty()

    # --- Главный цикл обновления дашборда ---
    while True:
        # Получаем данные из разделяемых ресурсов через кэшированную функцию
        # Передаем shared_data_file без подчеркивания, но функция принимает его с подчеркиванием
        current_status, df_history, df_alerts = get_live_data(shared_data_file)

        with placeholder.container():

            # --- Секция Статуса ---
            st.subheader("Статус и Текущие Метрики")
            col1, col2, col3, col4 = st.columns(4)

            # 1. Статус IDS
            is_running = current_status.get('is_running', False)
            mode = "BASELINE" if current_status.get('is_baseline_mode', True) else "МОНИТОРИНГ"
            status_color = "green" if is_running and mode == "МОНИТОРИНГ" else ("blue" if is_running else "red")

            col1.metric(label="Статус IDS", value=mode, delta="ONLINE" if is_running else "OFFLINE",
                        delta_color=status_color)
            col2.metric(label="Сетевой Интерфейс", value=current_status.get('current_interface', 'N/A'))

            # 2. Мониторинг Метрик Окна
            features = current_status.get('last_feature_vector', [0.0] * 10)

            # Выводим только 3 основные метрики
            st.write(f"**Последнее окно (T={TIME_WINDOW}с)**")
            col_m1, col_m2, col_m3 = st.columns(3)
            col_m1.metric("Total Packets", f"{features[0]:.0f}")
            col_m2.metric("Entropy DPort", f"{features[3]:.2f}")
            col_m3.metric("Unique Src IPs", f"{features[6]:.0f}")

            # 3. График Anomaly Score
            st.subheader("Мониторинг Anomaly Score (График в реальном времени)")
            if not df_history.empty:

                df_history['Color'] = df_history['Is_Anomaly'].apply(lambda x: 'red' if x else 'green')

                fig = px.scatter(
                    df_history,
                    x='Time (s)',
                    y='Anomaly Score',
                    color='Color',
                    color_discrete_map={'green': 'green', 'red': 'red'},
                    height=350
                )
                fig.add_hline(y=ANOMALY_THRESHOLD, line_dash="dash", line_color="red", annotation_text="Порог Алерта")
                fig.update_layout(
                    yaxis_range=[df_history['Anomaly Score'].min() - 0.05, df_history['Anomaly Score'].max() + 0.05],
                    showlegend=False
                )

                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Ожидание данных...")

            # 4. Активные Алерты
            st.subheader("Журнал Активных Алертов")
            if not df_alerts.empty:
                # pandas.DataFrame.time извлекает только время
                df_alerts['Time'] = pd.to_datetime(df_alerts['Time'], format='%H:%M:%S').dt.time
                st.dataframe(df_alerts, use_container_width=True)
            else:
                st.info("Аномалии не обнаружены.")

        # Обновление раз в 1 секунду
        time.sleep(1)


if __name__ == '__main__':
    display_dashboard()