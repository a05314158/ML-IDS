# app.py (обновленная версия)

import os
from datetime import datetime
from flask import Flask, render_template, jsonify, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from scapy.all import get_if_list

from worker import MLIDS_Worker

# --- 1. Инициализация и Конфигурация ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_and_long_key_for_flask_sessions'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['DEBUG'] = True  # Включаем режим отладки

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- 2. Глобальный экземпляр Воркера ---
worker = MLIDS_Worker()


# --- 3. Модели Базы Данных ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    models = db.relationship('Model', backref='owner', lazy=True)


class Model(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    # --- ИЗМЕНЕНИЕ: Добавлено поле для типа модели ---
    model_type = db.Column(db.String(50), nullable=False, default='isolation_forest')
    # -----------------------------------------------
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    model_path = db.Column(db.String(200), nullable=False)
    scaler_path = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# --- 4. Маршруты Аутентификации (без изменений) ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username, email, password = request.form.get('username'), request.form.get('email'), request.form.get(
            'password')
        if User.query.filter((User.email == email) | (User.username == username)).first():
            flash('Пользователь с таким email или именем уже существует.', 'danger')
            return redirect(url_for('register'))
        user = User(username=username, email=email, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash('Аккаунт успешно создан! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
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


# --- 5. Основные Маршруты (без изменений) ---
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/dashboard')
@login_required
def dashboard():
    interfaces = [str(i) for i in get_if_list()]
    user_models = Model.query.filter_by(user_id=current_user.id).order_by(Model.timestamp.desc()).all()
    return render_template('dashboard.html', interfaces=interfaces, models=user_models)


# --- 6. API для Воркера (с изменениями) ---
@app.route('/start_training', methods=['POST'])
@login_required
def start_training():
    data = request.get_json()
    # --- ИЗМЕНЕНИЕ: Получаем тип модели из запроса ---
    iface = data.get('interface')
    model_name = data.get('model_name')
    duration = data.get('training_duration', '2')
    model_type = data.get('model_type', 'isolation_forest')
    # ----------------------------------------------
    if not iface or not model_name: return jsonify(
        {"status": "error", "message": "Интерфейс и имя модели обязательны"}), 400

    user_model_dir = os.path.join('models', f'user_{current_user.id}')
    os.makedirs(user_model_dir, exist_ok=True)
    timestamp_str = datetime.utcnow().strftime('%Y%m%d%H%M%S')

    # Уникальное имя на основе типа, чтобы файлы не путались
    base_filename = f'{model_type}_{timestamp_str}'
    model_path = os.path.join(user_model_dir, base_filename)
    scaler_path = os.path.join(user_model_dir, f'{base_filename}_scaler.joblib')

    # Передаем тип модели в воркер
    worker.start_training_session(iface, model_path, scaler_path, int(duration), model_type)

    # Сохраняем модель с ее типом в БД
    new_model_db = Model(name=model_name, model_type=model_type, model_path=model_path, scaler_path=scaler_path,
                         owner=current_user)
    db.session.add(new_model_db)
    db.session.commit()

    return jsonify({"status": "ok", "message": "Обучение начато..."})


@app.route('/activate_model', methods=['POST'])
@login_required
def activate_model():
    data = request.get_json()
    model_id, iface = data.get('model_id'), data.get('interface')
    model = db.session.get(Model, int(model_id))  # Получаем объект модели из БД
    if not model or model.user_id != current_user.id:
        return jsonify({"status": "error", "message": "Модель не найдена"}), 404
    # --- ИЗМЕНЕНИЕ: Передаем тип модели из БД в воркер ---
    worker.start_monitoring_session(iface, model.id, model.model_path, model.scaler_path, model.model_type)
    # ----------------------------------------------------
    return jsonify({"status": "ok", "message": f"Активация модели '{model.name}'..."})


@app.route('/stop_session', methods=['POST'])
@login_required
def stop_session():
    worker.stop_current_session()
    return jsonify({"status": "ok", "message": "Отправлен сигнал остановки..."})


@app.route('/delete_model', methods=['POST'])
@login_required
def delete_model():
    model_id = request.get_json().get('model_id')
    model = db.session.get(Model, int(model_id))
    if not model or model.user_id != current_user.id: return jsonify(
        {"status": "error", "message": "Модель не найдена"}), 404
    try:
        # --- ИЗМЕНЕНИЕ: Правильное удаление для папки TF или файла IF ---
        model_full_path = model.model_path
        if model.model_type == 'tensorflow' and os.path.isdir(model_full_path):
            import shutil
            shutil.rmtree(model_full_path)  # Удаляем папку
        elif model.model_type == 'isolation_forest' and os.path.exists(f"{model_full_path}.joblib"):
            os.remove(f"{model_full_path}.joblib")  # Удаляем файл

        # Удаляем остальные файлы
        if os.path.exists(model.scaler_path): os.remove(model.scaler_path)
        threshold_path = f"{model.model_path}_threshold.joblib"
        if os.path.exists(threshold_path): os.remove(threshold_path)
        # -----------------------------------------------------------------
    except Exception as e:
        print(f"Ошибка при удалении файлов модели {model_id}: {e}")
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
    return jsonify(worker.get_status())


# --- 7. Запуск Приложения ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)

