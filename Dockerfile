FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    APP_ENV=staging

RUN groupadd --system --gid 10001 appuser \
    && useradd --system --uid 10001 --gid appuser \
       --create-home --home-dir /home/appuser appuser

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.txt \
    && python -m pip check

COPY app/ ./app/
COPY templates/ ./templates/
COPY scripts/ ./scripts/
COPY run.py wsgi.py ./

RUN mkdir -p /app/instance \
    && chown -R 10001:10001 /app

USER 10001:10001
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3).read()"]

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--timeout", "60", "wsgi:application"]
