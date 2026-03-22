FROM python:3.12-slim

# Установка системных зависимостей для Scapy и Postgres
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Копируем зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install celery redis psycopg2-binary

# Копируем весь проект
COPY . .

EXPOSE 5000