# Slim single-stage image. Reviewer runs `docker compose run tripwire demo`
# and gets a working artifact with no .env required.
FROM python:3.12-slim

WORKDIR /app

# Install dependencies first so layer caches well across code edits.
COPY pyproject.toml ./
RUN pip install --no-cache-dir httpx

# Copy the project and install editable so the CLI is on PATH.
COPY tripwire ./tripwire
RUN pip install --no-cache-dir .

# State + reports live under /data, which compose bind-mounts from the host
# so SQLite + report-*.html survive container restarts.
RUN mkdir -p /data/reports
ENV TRIPWIRE_STATE_DB=/data/tripwire.sqlite \
    TRIPWIRE_REPORT_DIR=/data/reports

ENTRYPOINT ["python", "-m", "tripwire"]
CMD ["demo", "--state-db", "/data/tripwire.sqlite", "--report-dir", "/data/reports"]
