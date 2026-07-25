FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && rm requirements.txt

COPY src/ src/

# Non-root, no shell, no home writes needed at runtime.
RUN useradd -m --uid 1000 svcuser && chown -R svcuser:svcuser /app
USER svcuser

# Each service overrides `command` (compose) / `args` (k8s) with its uvicorn target.
# Default is a no-op that fails loudly if not overridden.
CMD ["python", "-c", "import sys; sys.exit('No service command specified')"]
