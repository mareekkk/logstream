FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/

# Create non-root user
RUN groupadd -r logstream && useradd -r -g logstream logstream

# Create data directory owned by logstream user
RUN mkdir -p /data && chown -R logstream:logstream /data /app

USER logstream

ENV PYTHONPATH=/app

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8210/health')" || exit 1

EXPOSE 8210

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8210"]
