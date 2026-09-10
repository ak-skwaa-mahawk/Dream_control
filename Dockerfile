# syntax=docker/dockerfile:1.7
FROM python:3.12-slim-bookworm AS base

# Security & environment hardening
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONWARNINGS="error::ResourceWarning" \
    WARDEN_BACKEND=host

# Minimal runtime dependencies for sandboxing and inspection
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    ca-certificates \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root runner user
RUN groupadd -g 10001 dreamrunner && \
    useradd -u 10001 -g dreamrunner -m -s /bin/bash -d /home/dreamrunner dreamrunner

WORKDIR /app

# Copy project tree
COPY --chown=root:root core/ ./core/
COPY --chown=root:root harnesses/ ./harnesses/
COPY --chown=root:root tests/ ./tests/
COPY --chown=root:root entrypoint.sh ./entrypoint.sh

# Establish secure workspace directories with strict ownership
RUN mkdir -p /var/dream/workspace /var/dream/data /var/dream/seeds && \
    chmod +x ./entrypoint.sh && \
    chown -R dreamrunner:dreamrunner /var/dream

# Default read-only harness permissions
RUN chmod -R 0555 /app/harnesses

USER dreamrunner:dreamrunner

VOLUME ["/var/dream/workspace", "/var/dream/data", "/var/dream/seeds"]

ENTRYPOINT ["/usr/bin/tini", "--", "./entrypoint.sh"]
CMD ["daemon"]
