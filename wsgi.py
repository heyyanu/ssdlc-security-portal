"""WSGI entry point used by Gunicorn in the Docker image."""
import os
from app import create_app

application = create_app(os.environ.get("APP_ENV", "staging"))
