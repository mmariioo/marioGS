FROM python:3.12-slim

# Evitar archivos .pyc y buffering de stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Copiar solo requirements primero (aprovecha caché de capas Docker)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto del código
COPY . .

# Crear carpeta de datos para la BD SQLite
RUN mkdir -p /app/data

EXPOSE 3000

CMD ["python", "app.py"]