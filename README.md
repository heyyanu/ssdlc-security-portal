# SSDLC Portal - integrated with the existing Jenkins / ECR / Ansible staging pipeline

This package integrates the uploaded Flask SSDLC Portal into the existing staging pipeline. It replaces the old one-file demo app and keeps the existing AWS staging EC2 / ECR workflow. It does **not** create or deploy a separate production environment. The existing final Jenkins stage still adds the ECR tag `:production` only; that tag operation is not a deployment to a production server.

## Application contents

- Flask application factory with blueprints for authentication, projects, risks, threats, findings and audit logs
- SQLAlchemy database models and persistent SQLite staging storage
- CSRF protection, Flask-Login, role checks, input sanitisation and response security headers
- Existing pytest tests, plus an unauthenticated `/health` endpoint test
- Gunicorn container entry point; Docker runs as UID/GID 10001

## Pipeline changes

The updated Jenkinsfile now runs `requirements-dev.txt`, compiles the package, runs `pytest tests`, uses a dedicated Bandit tool environment, audits the app dependencies, builds the supplied Dockerfile, pushes to the existing ECR repository `ssdlc-app`, deploys with Ansible, checks host/container compliance with Cinc Auditor and runs OWASP ZAP against the staging endpoint.

## Before pushing to GitHub

1. Back up your current repository.
2. Replace the repository contents with this package (or copy the application files and the updated `Jenkinsfile`, `Dockerfile`, `ansible/` and CI config into the repository root).
3. Keep the existing Jenkins credentials: `AWS_REGION`, `ECR_REGISTRY`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `EC2_HOST`, `EC2_SSH_PRIVATE_KEY`, `SEMGREP_APP_TOKEN`.
4. Confirm `EC2_HOST` is the public IP/DNS of the current staging instance and that its security group allows TCP 22 from the Jenkins egress IP and TCP 8081 from the intended test client.
5. Commit and push to the `main` branch.

```bash
git add .
git commit -m "Integrate SSDLC Portal into SSDLC pipeline"
git push origin main
```

## First administrator account

The uploaded application contained a hard-coded default admin account/password. That automatic seed has been removed. After the first successful deployment, create the initial administrator interactively on the staging EC2 container:

```bash
sudo docker exec -it staging-app python scripts/create_admin.py
```

Choose a unique password meeting the app's password policy. The script refuses to create a second administrator if one already exists. No default admin password is shipped.

## Staging persistence and secret handling

Ansible creates `/opt/ssdlc-app/instance` on EC2 and mounts it at `/app/instance`, preserving the SQLite database across container replacements. On first deployment it also generates `/opt/ssdlc-app/app.env` with a random `SECRET_KEY` and restricts the file to root read/write. The key remains stable between deployments.

The current staging endpoint is HTTP on port 8081, so the staging configuration has `SESSION_COOKIE_SECURE=False`. This is appropriate only for the existing HTTP staging setup. Do not use this setting for a public production deployment; enable HTTPS and use the `production` Flask config, which sets Secure cookies.

## Local development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
APP_ENV=development python run.py
pytest tests -v
```

Health check: `http://127.0.0.1:5000/health`.
