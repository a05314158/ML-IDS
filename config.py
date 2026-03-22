import os
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "b2b_enterprise_secure_key_123")
DATABASE_URI = os.getenv("DATABASE_URI", f"sqlite:///{BASE_DIR / 'site.db'}")

BPF_FILTER = os.getenv("BPF_FILTER", "ip or udp or tcp")
TIME_WINDOW = int(os.getenv("TIME_WINDOW", 2))
BURST_WINDOW_SECONDS = float(os.getenv("BURST_WINDOW_SECONDS", 0.5))

NUM_FEATURES = 13
TRAIN_DURATION_MINUTES = int(os.getenv("TRAIN_DURATION_MINUTES", 1))
CONTAMINATION = float(os.getenv("CONTAMINATION", 0.05))

NN_HIDDEN_LAYER_SIZE = 8
NN_EPOCHS = int(os.getenv("NN_EPOCHS", 50))
NN_LEARNING_RATE = 0.01
NN_BATCH_SIZE = 32

MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)
RUN_DIR = BASE_DIR / "run"
RUN_DIR.mkdir(exist_ok=True)

def setup_logger(name: str, log_file: str, level=logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.handlers:
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
        file_handler = RotatingFileHandler(
            LOGS_DIR / log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    return logger

app_logger = setup_logger('app', 'app.log')
worker_logger = setup_logger('worker', 'worker.log')
sniffer_logger = setup_logger('sniffer', 'sniffer.log')

def get_worker_status_file(user_id: int) -> Path:
    return RUN_DIR / f"worker_status_{user_id}.json"