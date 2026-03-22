import os
from app import celery_app, app

# Мы импортируем задачу, чтобы воркер "знал" о её существовании
from app import train_model_task

if __name__ == '__main__':
    print("=== [CELERY WORKER BOOT] ===")
    print("Ожидание задач по обучению нейросетей...")
    # Запускаем Celery. Он сам будет слушать Redis и выполнять задачи.
    # Флаг --pool=solo важен для стабильности TensorFlow в Docker
    celery_app.worker_main(['worker', '--loglevel=info', '--pool=solo'])