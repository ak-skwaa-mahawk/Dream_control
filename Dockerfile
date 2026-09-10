FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    util-linux \
    libc6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV PATH="/usr/local/bin:/usr/bin:/bin" \
    LANG="C.UTF-8" \
    LC_ALL="C.UTF-8" \
    PYTHONHASHSEED="0" \
    PYTHONUNBUFFERED="1"

COPY pyproject.toml ./
RUN pip install --no-cache-dir .

COPY . .

RUN chmod 700 /app/core && chmod -R 755 /app/harnesses && chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
