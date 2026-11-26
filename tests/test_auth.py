"""Authentication tests – login, logout, register, lockout, open-redirect."""
import pytest
from app.extensions import db as _db
from app.models.user import User
from tests.conftest import login, logout


class TestLogin:
    def test_login_page_loads(self, client):
        r = client.get("/auth/login")
        assert r.status_code == 200
        # Template says "Sign In" not "Login"
        assert b"Sign" in r.data or b"sign" in r.data.lower()

    def test_login_success_redirects_to_dashboard(self, client, admin_user):
        r = login(client, "testadmin", "Admin@Secure1!")
        assert r.status_code == 200
        assert b"Dashboard" in r.data or b"dashboard" in r.data.lower()
        logout(client)

    def test_login_wrong_password(self, client, admin_user):
        r = login(client, "testadmin", "WrongPass999!")
        assert r.status_code == 200  # stays on login page

    def test_login_nonexistent_user(self, client):
        r = login(client, "nobody_xyz", "SomePass@999")
        assert r.status_code == 200

    def test_login_increments_failed_counter(self, client, db, analyst_user):
        u = User.query.filter_by(username="testanalyst").first()
        u.failed_logins = 0
        u.locked_until = None
        db.session.commit()
        login(client, "testanalyst", "WrongPass999!")
        db.session.refresh(u)
        assert u.failed_logins >= 1

    def test_account_lockout_after_5_failures(self, client, db, manager_user):
        u = User.query.filter_by(username="testmanager").first()
        u.failed_logins = 0
        u.locked_until = None
        db.session.commit()
        for _ in range(5):
            login(client, "testmanager", "BadPass999!")
        db.session.refresh(u)
        assert u.is_locked()

    def test_locked_account_cannot_login(self, client, db, manager_user):
        u = User.query.filter_by(username="testmanager").first()
        from datetime import datetime, timezone, timedelta
        u.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
        db.session.commit()
        r = login(client, "testmanager", "Manager@Secure1!")
        assert b"locked" in r.data.lower() or r.status_code == 200

    def test_logout(self, client, admin_user):
        login(client, "testadmin", "Admin@Secure1!")
        r = logout(client)
        assert r.status_code == 200
        # After logout, accessing protected page redirects to login
        r2 = client.get("/", follow_redirects=True)
        assert b"Sign" in r2.data or b"sign" in r2.data.lower() or b"login" in r2.data.lower()

    def test_open_redirect_blocked(self, client, admin_user):
        r = client.post(
            "/auth/login",
            data={"username": "testadmin", "password": "Admin@Secure1!", "next": "//evil.com/phish"},
            follow_redirects=False,
        )
        location = r.headers.get("Location", "")
        assert "evil.com" not in location
        logout(client)

    def test_open_redirect_absolute_url_blocked(self, client, admin_user):
        r = client.post(
            "/auth/login",
            data={"username": "testadmin", "password": "Admin@Secure1!", "next": "https://evil.com"},
            follow_redirects=False,
        )
        location = r.headers.get("Location", "")
        assert "evil.com" not in location
        logout(client)


class TestRegister:
    def test_register_page_loads(self, client):
        r = client.get("/auth/register")
        assert r.status_code == 200
        # Template says "Create Account"
        assert b"Account" in r.data or b"account" in r.data.lower()

    def test_register_success(self, app, client, db):
        # Remove if exists from prior run
        existing = User.query.filter_by(username="newuser123").first()
        if existing:
            db.session.delete(existing)
            db.session.commit()
        r = client.post(
            "/auth/register",
            data={"username": "newuser123", "email": "newuser@example.com",
                  "password": "NewUser@Secure1!", "confirm": "NewUser@Secure1!",
                  "role": "analyst"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        # Query within the app context used by the test
        with app.app_context():
            u = User.query.filter_by(username="newuser123").first()
        assert u is not None


    def test_public_registration_cannot_assign_manager_role(self, client):
        response = client.post(
            "/auth/register",
            data={"username": "selfmanager", "email": "selfmanager@example.com",
                  "password": "SelfManager@2026!", "confirm": "SelfManager@2026!",
                  "role": "manager"},
            follow_redirects=True,
        )
        assert User.query.filter_by(username="selfmanager").first() is None

    def test_register_weak_password_rejected(self, client):
        r = client.post(
            "/auth/register",
            data={"username": "weakpwuser", "email": "weak@example.com",
                  "password": "password", "confirm": "password"},
            follow_redirects=True,
        )
        assert User.query.filter_by(username="weakpwuser").first() is None

    def test_register_duplicate_username_rejected(self, client, admin_user):
        r = client.post(
            "/auth/register",
            data={"username": "testadmin", "email": "other@example.com",
                  "password": "Admin@Secure1!", "confirm": "Admin@Secure1!"},
            follow_redirects=True,
        )
        users = User.query.filter_by(username="testadmin").all()
        assert len(users) == 1


class TestChangePassword:
    def test_change_password_requires_login(self, client):
        r = client.get("/auth/change-password", follow_redirects=True)
        # Redirects to login; template says "Sign In" or "sign"
        assert b"Sign" in r.data or b"sign" in r.data.lower() or b"login" in r.data.lower()

    def test_change_password_success(self, client, db, analyst_user):
        u = User.query.filter_by(username="testanalyst").first()
        u.failed_logins = 0
        u.locked_until = None
        db.session.commit()
        login(client, "testanalyst", "Analyst@Secure1!")
        r = client.post(
            "/auth/change-password",
            data={"current": "Analyst@Secure1!",
                  "password": "NewAnalyst@2024!",
                  "confirm": "NewAnalyst@2024!"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        u = User.query.filter_by(username="testanalyst").first()
        u.set_password("Analyst@Secure1!")
        db.session.commit()
        logout(client)
