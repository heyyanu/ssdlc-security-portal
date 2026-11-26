"""Interactively create the first SSDLC portal administrator.

Run after first deployment:
    docker exec -it staging-app python scripts/create_admin.py
"""
import getpass
import os
import sys

from app import create_app
from app.extensions import db
from app.models.user import User
from app.security import validate_password


def main() -> int:
    app = create_app(os.environ.get("APP_ENV", "staging"))
    with app.app_context():
        if User.query.filter_by(role="admin").first():
            print("An administrator already exists; no account was created.")
            return 0

        username = input("Admin username: ").strip()
        email = input("Admin email: ").strip()
        password = getpass.getpass("Admin password (hidden): ")
        confirm = getpass.getpass("Confirm password: ")

        if not username or not email:
            print("Username and email are required.", file=sys.stderr)
            return 2
        if password != confirm:
            print("Passwords do not match.", file=sys.stderr)
            return 2
        valid, message = validate_password(password)
        if not valid:
            print(message, file=sys.stderr)
            return 2
        if User.query.filter_by(username=username).first():
            print("That username already exists.", file=sys.stderr)
            return 2

        admin = User(username=username, email=email, role="admin")
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        print(f"Administrator '{username}' created successfully.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
