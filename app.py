# app.py (ПОЛНАЯ ВЕРСИЯ С ПОЛЬЗОВАТЕЛЯМИ)

import os
import shutil
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
# --- ВОЗВРАЩАЕМ FLASK-LOGIN ---
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
# ----------------------------
from werkzeug.security import generate_password_hash, check_password_hash
from scapy.all import get_if_list

app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_and_long_key_for_flask_sessions'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- ВОЗВРАЩАЕМ LOGIN MANAGER ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# --------------------------------

# --- Модели Базы Данных ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    models = db.relationship('Model', backref='owner', lazy='dynamic', cascade="all, delete-orphan")
    traffic_logs = db.relationship('TrafficLog', backref='owner', lazy='dynamic', cascade="all, delete-orphan")
    active_state = db.relationship('ActiveState', backref='owner', uselist=False, cascade="all, delete-orphan")


class Model(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    model_type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    model_path = db.Column(db.String(200), nullable=True)
    is_active = db.Column(db.Boolean, default=False, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class TrafficLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    local_ip = db.Column(db.String(50), nullable=False, index=True)
    total_bytes = db.Column(db.BigInteger, default=0)
    packet_count = db.Column(db.Integer, default=0)
    protocols = db.Column(db.String(200))
    domains = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class ActiveState(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    is_monitoring = db.Column(db.Boolean, default=False)
    active_model_id = db.Column(db.Integer, nullable=True)
    interface = db.Column(db.String(100), nullable=True)
    worker_status_json = db.Column(db.Text, default='{}')


# --- ВОЗВРАЩАЕМ ЗАГРУЗЧИК ПОЛЬЗОВАТЕЛЯ ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ----------------------------------------

# --- Маршруты ---
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/dashboard')
@login_required  # <-- ЗАЩИЩАЕМ МАРШРУТ
def dashboard():
    interfaces = get_if_list()
    user_models = current_user.models.order_by(Model.timestamp.desc()).all()
    active_state = current_user.active_state or ActiveState(user_id=current_user.id)
    return render_template('dashboard.html', interfaces=interfaces, models=user_models, active_state=active_state)


@app.route('/statistics')
@login_required  # <-- ЗАЩИЩАЕМ МАРШРУТ
def statistics():
    period = request.args.get('period', 'hour')
    now = datetime.utcnow()
    if period == 'day':
        start_time = now - timedelta(days=1);
        title = "за последние 24 часа"
    else:
        start_time = now - timedelta(hours=1);
        title = "за последний час"

    stats_query = db.session.query(
        TrafficLog.local_ip,
        func.sum(TrafficLog.total_bytes).label('total_bytes'),
        func.group_concat(TrafficLog.protocols).label('protocols'),
        func.group_concat(TrafficLog.domains).label('domains')
    ).filter(
        TrafficLog.user_id == current_user.id,  # <-- Используем ID текущего пользователя
        TrafficLog.timestamp >= start_time
    ).group_by(TrafficLog.local_ip).order_by(func.sum(TrafficLog.total_bytes).desc())

    aggregated_stats = []
    for row in stats_query.all():
        all_protocols = sorted(list(set(filter(None, (row.protocols or '').split(',')))))
        all_domains = sorted(list(set(filter(None, (row.domains or '').split(',')))))
        aggregated_stats.append({
            'local_ip': row.local_ip,
            'total_mbytes': round(row.total_bytes / (1024 * 1024), 2) if row.total_bytes else 0,
            'protocols': ', '.join(all_protocols),
            'domains': all_domains[:15]
        })
    return render_template('statistics.html', stats=aggregated_stats, title=title, active_period=period)


# --- API для управления (все защищены) ---
@app.route('/create_model', methods=['POST'])
@login_required
def create_model():
    data = request.get_json()
    new_model = Model(name=data.get('model_name'), model_type=data.get('model_type'), owner=current_user)
    db.session.add(new_model)
    db.session.commit()
    flash(f"Модель '{new_model.name}' создана. Воркер скоро начнет ее обучение.", "success")
    return jsonify({"status": "ok"})


@app.route('/activate_model', methods=['POST'])
@login_required
def activate_model():
    data = request.get_json()
    model_id = data.get('model_id')
    iface = data.get('interface')

    current_user.models.update({Model.is_active: False})

    target_model = db.session.get(Model, int(model_id))
    if target_model and target_model.user_id == current_user.id and target_model.model_path:
        target_model.is_active = True
        active_state = current_user.active_state or ActiveState(user_id=current_user.id)
        active_state.is_monitoring = True
        active_state.active_model_id = int(model_id)
        active_state.interface = iface
        db.session.add(active_state)
        db.session.commit()
        return jsonify({"status": "ok"})
    else:
        flash("Эту модель нельзя активировать.", "danger")
        return jsonify({"status": "error", "message": "Модель не обучена или не принадлежит вам"})


@app.route('/stop_monitoring', methods=['POST'])
@login_required
def stop_monitoring():
    current_user.models.update({Model.is_active: False})
    if current_user.active_state:
        current_user.active_state.is_monitoring = False
        current_user.active_state.active_model_id = None
    db.session.commit()
    return jsonify({"status": "ok"})


@app.route('/delete_model', methods=['POST'])
@login_required
def delete_model():
    model_id = request.get_json().get('model_id')
    model = db.session.get(Model, int(model_id))
    if not model or model.user_id != current_user.id: return jsonify(
        {"status": "error", "message": "Модель не найдена"}), 404

    if model.model_path:
        try:
            if model.model_type == 'tensorflow' and os.path.exists(f"{model.model_path}.keras"):
                os.remove(f"{model.model_path}.keras")
            elif model.model_type == 'isolation_forest' and os.path.exists(f"{model.model_path}.joblib"):
                os.remove(f"{model.model_path}.joblib")
            if os.path.exists(f"{model.model_path}_scaler.joblib"): os.remove(f"{model.model_path}_scaler.joblib")
            if os.path.exists(f"{model.model_path}_threshold.joblib"): os.remove(f"{model.model_path}_threshold.joblib")
        except Exception as e:
            print(f"Ошибка при удалении файлов модели: {e}")

    db.session.delete(model)
    db.session.commit()
    flash(f"Модель '{model.name}' была успешно удалена.", "success")
    return jsonify({"status": "ok"})


@app.route('/rename_model', methods=['POST'])
@login_required
def rename_model():
    data = request.get_json()
    model_id, new_name = data.get('model_id'), data.get('new_name')
    if not new_name or not new_name.strip(): return jsonify(
        {"status": "error", "message": "Имя не может быть пустым"}), 400
    model = db.session.get(Model, int(model_id))
    if not model or model.user_id != current_user.id: return jsonify(
        {"status": "error", "message": "Модель не найдена"}), 404
    model.name = new_name.strip()
    db.session.commit()
    flash(f"Модель переименована в '{model.name}'.", "success")
    return jsonify({"status": "ok"})


@app.route('/status')
@login_required
def status():
    state = current_user.active_state
    if state and state.worker_status_json:
        try:
            return jsonify(json.loads(state.worker_status_json))
        except json.JSONDecodeError:
            pass
    return jsonify({"mode": "Воркер не запущен", "log": ["Запустите воркер с вашим ID пользователя."]})


# --- МАРШРУТЫ АУТЕНТИФИКАЦИИ ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('home'))
    if request.method == 'POST':
        username, email, password = request.form.get('username'), request.form.get('email'), request.form.get(
            'password')
        if User.query.filter((User.email == email) | (User.username == username)).first():
            flash('Пользователь с таким email или именем уже существует.', 'danger')
            return redirect(url_for('register'))
        user = User(username=username, email=email, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash(
            f'Аккаунт {user.username} успешно создан! Его ID: {user.id}. Запомните ID, он понадобится для запуска воркера.',
            'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('home'))
    if request.method == 'POST':
        email, password = request.form.get('email'), request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=True)
            return redirect(url_for('dashboard'))
        else:
            flash('Неверный email или пароль.', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)

