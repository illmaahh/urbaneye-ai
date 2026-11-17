FROM python:3.12-slim
ENV HOST=0.0.0.0 \
    PORT=8000 \
    COOKIE_SECURE=1 \
    URBANEYE_DATA_DIR=/data \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
COPY index.html server.py ./
RUN mkdir -p /data
EXPOSE 8000
CMD ["python", "server.py"]
