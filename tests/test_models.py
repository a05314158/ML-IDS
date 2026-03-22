import pytest
from app import app
from extensions import db
from models import User, ActiveState
from werkzeug.security import generate_password_hash


@pytest.fixture
def app_ctx():
    """Создает ИЗОЛИРОВАННУЮ БД в оперативной памяти (временно на секунду для тестов)"""
    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"
    })

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_user_creation_and_state(app_ctx):
    """Сценарий: Регистрация нового SOC-оператора генерирует правильные реляции в базе"""
    # Добавляем пользователя
    hashed_pwd = generate_password_hash("SecretCyber123")
    user = User(username="Test_Admin", email="test@soc.local", password_hash=hashed_pwd)
    db.session.add(user)
    db.session.commit()

    # Ищем его обратно в базе
    queried_user = User.query.filter_by(username="Test_Admin").first()
    assert queried_user is not None
    assert queried_user.id == 1

    # Привязываем ActiveState
    state = ActiveState(user_id=queried_user.id, interface="eth0", is_monitoring=True)
    db.session.add(state)
    db.session.commit()

    # Проверяем, что связь работает через cascade
    assert queried_user.active_state.interface == "eth0"
    assert queried_user.active_state.is_monitoring is True