"""Pytest configuration and shared fixtures."""
import pytest
from app import create_app
from app.extensions import db as _db
from app.models.user import User


@pytest.fixture(scope="session")
def app():
    app = create_app("testing")
    with app.app_context():
        _db.create_all()
        yield app
        _db.drop_all()


@pytest.fixture(scope="function")
def db(app):
    with app.app_context():
        yield _db
        _db.session.rollback()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin_user(db):
    # Remove if exists (from seed)
    existing = User.query.filter_by(username="testadmin").first()
    if existing:
        return existing
    u = User(username="testadmin", email="testadmin@test.com", role="admin")
    u.set_password("Admin@Secure1!")
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def analyst_user(db):
    existing = User.query.filter_by(username="testanalyst").first()
    if existing:
        return existing
    u = User(username="testanalyst", email="testanalyst@test.com", role="analyst")
    u.set_password("Analyst@Secure1!")
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def manager_user(db):
    existing = User.query.filter_by(username="testmanager").first()
    if existing:
        return existing
    u = User(username="testmanager", email="testmanager@test.com", role="manager")
    u.set_password("Manager@Secure1!")
    db.session.add(u)
    db.session.commit()
    return u


def login(client, username, password):
    return client.post(
        "/auth/login",
        data={"username": username, "password": password, "next": ""},
        follow_redirects=True,
    )


def logout(client):
    return client.get("/auth/logout", follow_redirects=True)
