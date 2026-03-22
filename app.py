import os, sys, json, subprocess, redis
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, flash, redirect, url_for
from sqlalchemy import func
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import config
from extensions import db, login_manager
from models import User, Model, ActiveState, DomainTimeLog, HourlySummary
from celery import Celery
import numpy as np

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', config.DATABASE_URI)
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- НАСТРОЙКА CELERY ---
REDIS_URL = os.getenv('REDIS_URL', 'redis://redis:6379/0')
celery_app = Celery(app.name, broker=REDIS_URL, backend=REDIS_URL)
celery_app.conf.update(app.config)

db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

# Инициализация Redis для быстрой статистики
r_client = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)


@login_manager.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))


# --- CELERY TASK (Тяжелое обучение нейросети) ---
@celery_app.task(name="app.train_model_task")
def train_model_task(model_id, user_id, all_samples):
    with app.app_context():
        from ml_model import TFAutoencoderDetector, IsolationForestDetector
        m = db.session.get(Model, model_id)
        if not m: return

        m_dir = f"/app/models/user_{user_id}"
        os.makedirs(m_dir, exist_ok=True)
        m_path = os.path.join(m_dir, f"m_{m.id}_{int(datetime.now().timestamp())}")

        # Выполняем обучение
        det = TFAutoencoderDetector() if m.model_type == 'tensorflow' else IsolationForestDetector()
        det.train_and_save_model(np.array(all_samples), m_path)

        m.model_path = m_path
        m.progress = 100
        db.session.commit()

        # Обновляем статус в Redis, чтобы Dashboard узнал об успехе
        status_key = f"worker_status_{user_id}"
        raw = r_client.get(status_key)
        status = json.loads(raw) if raw else {"log": []}
        status.setdefault("log", []).insert(0,
                                            f"[{datetime.now().strftime('%H:%M:%S')}] ИИ-ЯДРО '{m.name}' УСПЕШНО ОБУЧЕНО!")
        status["mode"] = "READY"
        r_client.set(status_key, json.dumps(status))


# --- ОСНОВНЫЕ СТРАНИЦЫ (ИНТЕРФЕЙС) ---

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/dashboard')
@login_required
def dashboard():
    st = current_user.active_state or ActiveState(user_id=current_user.id)
    # Список интерфейсов для выпадающего меню (в докере список пуст, используем заглушку)
    ifaces = [{'name': 'Remote Sensor Mode', 'value': 'remote'}]
    return render_template('dashboard.html', interfaces=ifaces, models=current_user.models.all(), active_state=st)


@app.route('/productivity')
@login_required
def productivity():
    # Получаем данные для таблицы
    raw_details = db.session.query(
        DomainTimeLog.local_ip, DomainTimeLog.domain, DomainTimeLog.category, DomainTimeLog.duration_seconds
    ).filter_by(user_id=current_user.id).order_by(DomainTimeLog.duration_seconds.desc()).limit(20).all()

    # Получаем данные для круговой диаграммы
    cat_res = db.session.query(
        DomainTimeLog.category, func.sum(DomainTimeLog.duration_seconds)
    ).filter_by(user_id=current_user.id).group_by(DomainTimeLog.category).all()

    clean_details = [{'ip': r[0], 'domain': r[1], 'cat': r[2], 't': int(r[3] or 0)} for r in raw_details]
    clean_cats = [{'category': r[0], 't': int(r[1] or 0)} for r in cat_res]

    return render_template('productivity.html', details=clean_details, cat_stats=clean_cats)


@app.route('/statistics')
@login_required
def statistics():
    period = request.args.get('period', 'hour')
    delta = timedelta(hours=1) if period == 'hour' else timedelta(days=1)

    raw = db.session.query(
        HourlySummary.local_ip, func.sum(HourlySummary.total_bytes).label('b'),
        func.sum(HourlySummary.packet_count).label('p'), func.max(HourlySummary.hour_timestamp).label('ls')
    ).filter(HourlySummary.user_id == current_user.id,
             HourlySummary.hour_timestamp >= datetime.utcnow() - delta).group_by(HourlySummary.local_ip).all()

    clean = [{'ip': r[0], 'mb': round((r[1] or 0) / (1024 * 1024), 2), 'packets': (r[2] or 0),
              'last_seen': r[3].strftime('%H:%M') if r[3] else 'N/A'} for r in raw]
    return render_template('statistics.html', stats=clean, period=period)


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


# --- API ДЛЯ СЕНСОРА И ДАШБОРДА ---

@app.route('/api/sensor_data', methods=['POST'])
def receive_sensor_data():
    try:
        data = request.get_json()
        features, p_count, b_count = data.get('features'), data.get('packet_count', 0), data.get('total_bytes', 0)

        uid = 1  # Твой ID
        status_key = f"worker_status_{uid}"
        train_key = f"train_buffer_{uid}"

        # 1. Получаем статус из Redis
        raw = r_client.get(status_key)
        status = json.loads(raw) if raw else {"mode": "ACTIVE", "log": [], "pkts_total": 0, "bytes_total_mb": 0.0,
                                              "current_score": 0}

        # 2. Обновляем счетчики
        status["pkts_total"] += p_count
        status["bytes_total_mb"] = round(status["bytes_total_mb"] + (b_count / (1024 * 1024)), 4)

        # 3. Ищем модель на обучении
        m = Model.query.filter_by(user_id=uid, model_path=None).filter(Model.progress < 100).first()

        if m:
            r_client.rpush(train_key, json.dumps(features))
            collected = r_client.llen(train_key)
            m.progress = int((collected / 500) * 100)
            status["mode"] = f"COLLECTING ({m.progress}%)"

            # --- ВОТ ЭТОТ БЛОК ОЖИВИТ ТВОИ ЛОГИ ---
            # Добавляем запись в терминал каждые 5 пачек данных, чтобы не частить
            if collected % 5 == 0:
                ts = datetime.now().strftime('%H:%M:%S')
                # Вставляем новую запись в начало списка логов
                status["log"].insert(0, f"[{ts}] Вектор #{collected} поглощен ядром '{m.name}'")

                # Чтобы лог не рос бесконечно в памяти, оставляем только 20 последних строк
                if len(status["log"]) > 20:
                    status["log"].pop()

            if collected >= 500:
                samples = [json.loads(x) for x in r_client.lrange(train_key, 0, -1)]
                train_model_task.delay(m.id, uid, samples)
                r_client.delete(train_key)
                status["mode"] = "TRAINING IN PROGRESS..."
                status["log"].insert(0,
                                     f"[{datetime.now().strftime('%H:%M:%S')}] Сбор данных завершен. Запуск Celery...")

            db.session.commit()

        # 4. Сохраняем обновленный статус с логами в Redis
        r_client.set(status_key, json.dumps(status))

        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500


@app.route('/status')
@login_required
def status():
    raw = r_client.get(f"worker_status_{current_user.id}")
    if raw:
        return jsonify(json.loads(raw))
    return jsonify({"mode": "IDLE", "pkts_total": 0, "bytes_total_mb": 0, "log": ["Ожидание данных..."]})


# --- УПРАВЛЕНИЕ МОДЕЛЯМИ ---

@app.route('/create_model', methods=['POST'])
@login_required
def create_model():
    d = request.get_json()
    new_model = Model(name=d.get('model_name'), model_type=d.get('model_type'), owner=current_user)
    db.session.add(new_model)
    db.session.commit()
    return jsonify({"status": "ok"})


@app.route('/activate_model', methods=['POST'])
@login_required
def activate_model():
    d = request.get_json()
    m = db.session.get(Model, int(d.get('model_id')))
    if m and m.user_id == current_user.id:
        current_user.models.update({Model.is_active: False})
        m.is_active = True
        st = current_user.active_state or ActiveState(user_id=current_user.id)
        st.is_monitoring, st.active_model_id = True, m.id
        db.session.add(st);
        db.session.commit()
        return jsonify({"status": "ok"})
    return jsonify({"status": "error"}), 404


@app.route('/stop_monitoring', methods=['POST'])
@login_required
def stop_monitoring():
    if current_user.active_state:
        current_user.active_state.is_monitoring = False
    current_user.models.update({Model.is_active: False})
    db.session.commit()
    return jsonify({"status": "ok"})


@app.route('/delete_model', methods=['POST'])
@login_required
def delete_model():
    d = request.get_json()
    m = db.session.get(Model, int(d.get('model_id')))
    if m and m.user_id == current_user.id:
        db.session.delete(m);
        db.session.commit()
        return jsonify({"status": "ok"})
    return jsonify({"status": "error"})


# --- АВТОРИЗАЦИЯ ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u, e, p = request.form.get('username'), request.form.get('email'), request.form.get('password')
        if User.query.filter_by(email=e).first():
            flash('Критическая ошибка: Этот Email уже зарегистрирован!', 'danger')
            return redirect(url_for('register'))
        user = User(username=u, email=e, password_hash=generate_password_hash(p))
        db.session.add(user);
        db.session.commit()
        flash('Регистрация успешна! Войдите в систему.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Ошибка: Неверный логин или пароль!', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)