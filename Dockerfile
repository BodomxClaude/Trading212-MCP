# Stage 1: test — run full suite; build fails if tests fail
FROM python:3.14-slim AS test
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir ".[dev]"
RUN pytest

# Stage 2: runtime — production image, no test deps
FROM python:3.14-slim AS runtime
WORKDIR /app

# Install only production deps from pyproject.toml [project.dependencies]
COPY pyproject.toml README.md ./
COPY server.py client.py ratelimit.py auth.py ./
COPY tools/ tools/
RUN pip install --no-cache-dir .

# Non-root user
RUN useradd -r -s /bin/false appuser
USER appuser

# Config: mount at /config/config.json
# or set TRADING212_API_KEY / TRADING212_API_SECRET / TRADING212_LIVE env vars
VOLUME ["/config"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()"

ENTRYPOINT ["python", "server.py"]
