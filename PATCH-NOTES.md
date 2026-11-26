# Integration notes

- Replaced old sample `app.py`/`test_app.py` pipeline assumptions with the uploaded Flask package (`app/`, `run.py`, `tests/`).
- Added Dockerfile using Gunicorn, a non-root runtime user, and `/health` HEALTHCHECK.
- Added `/health` endpoint with a database connectivity probe.
- Added explicit `staging` config for the current HTTP-only staging deployment.
- Removed hard-coded seeded admin credentials; added interactive `scripts/create_admin.py`.
- Split runtime requirements from dev/test requirements.
- Updated Jenkins stages for package compilation, tests, Bandit tool venv, dependency audit and Docker build.
- Updated Ansible to preserve SQLite data, persist SECRET_KEY, run the new image and attempt rollback on failed health checks.
- No separate production environment is created or deployed.
