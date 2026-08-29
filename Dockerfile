FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       gcc \
       libglib2.0-0 \
       libx11-6 \
       libxext6 \
       libxrender1 \
       libfontconfig1 \
       libfreetype6 \
       libjpeg62-turbo \
       libpng16-16 \
       ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY bot.py .

CMD ["python", "bot.py"]
