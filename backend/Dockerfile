FROM python:3.12-slim

# Setze Umgebungsvariablen
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Erstelle ein Arbeitsverzeichnis
WORKDIR /app

# Installiere System-Abhängigkeiten
RUN apt-get update && apt-get install -y \
    libpq-dev gcc \
    --no-install-recommends && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Installiere Abhängigkeiten über requirements.txt
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Kopiere den Django-Code in das Container-Image
COPY . /app/

# Port, auf dem die App laufen wird
EXPOSE 8000

# RUN python manage.py collectstatic --noinput

# Befehl zum Starten von Gunicorn als WSGI-Server für die Django-App
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "backend.wsgi:application", "--workers", "3"]
