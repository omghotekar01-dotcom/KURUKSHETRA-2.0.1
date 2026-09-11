FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TRUSTKERNEL_DB_PATH=/var/lib/trustkernel/trustkernel.db

WORKDIR /app

COPY backend/requirements.txt /app/backend/requirements.txt
RUN python -m pip install --upgrade pip && python -m pip install -r /app/backend/requirements.txt

COPY backend /app/backend
COPY frontend /app/frontend
COPY docs /app/docs

RUN mkdir -p /var/lib/trustkernel

WORKDIR /app/backend
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1

CMD ["python", "-m", "uvicorn", "app.bootstrap:app", "--host", "0.0.0.0", "--port", "8000"]
