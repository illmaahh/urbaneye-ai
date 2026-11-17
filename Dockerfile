FROM python:3.12-slim
ENV HOST=0.0.0.0 \
    PORT=8000 \
    COOKIE_SECURE=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY index.html server.py ./
EXPOSE 8000
CMD ["python", "server.py"]
