"""Development entry point. Production containers run Gunicorn via wsgi.py."""
import os
from app import create_app

app = create_app(os.environ.get("APP_ENV", os.environ.get("FLASK_ENV", "development")))

if __name__ == "__main__":
    app.run(
        host=os.environ.get("FLASK_HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=app.config.get("DEBUG", False),
    )
