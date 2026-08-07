# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Two stages: build wheels with a toolchain, run with none. The final image
# has no compiler, no package manager cache and no build inputs, so a process
# that gets code execution has very little to work with.

# --- build ----------------------------------------------------------------
FROM python:3.12-slim-bookworm AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# gcc and the libffi headers are needed to build cryptography/argon2 wheels on
# architectures without a prebuilt wheel. They stay in this stage only.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libffi-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
 && /opt/venv/bin/pip install . \
 && /opt/venv/bin/pip install "gunicorn>=22" "psycopg[binary]>=3.1"

# --- runtime --------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

# Security updates only; no new packages. Keeping the runtime free of curl,
# wget and a shell-friendly toolchain removes the usual post-exploitation
# conveniences.
RUN apt-get update \
 && apt-get upgrade -y \
 && rm -rf /var/lib/apt/lists/*

# Unprivileged, no login shell, no home directory to write into.
RUN groupadd --system --gid 10001 ehealth \
 && useradd --system --uid 10001 --gid ehealth --shell /usr/sbin/nologin \
            --no-create-home ehealth

COPY --from=build /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # No .pyc writes means the image can run with a read-only root filesystem.
    PYTHONHASHSEED=random

# Build provenance, stamped by the pipeline. The running instance reports it
# at /version and writes it into every audit entry.
ARG GIT_REVISION=unknown
ARG BUILD_TIMESTAMP
ENV EHEALTH_GIT_REVISION=${GIT_REVISION} \
    EHEALTH_BUILD_TIMESTAMP=${BUILD_TIMESTAMP}

LABEL org.opencontainers.image.title="swiss-ehealth" \
      org.opencontainers.image.description="Swiss e-health patient dossier" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.revision="${GIT_REVISION}" \
      org.opencontainers.image.source="https://github.com/lucadesimoni/swiss-ehealth"

USER 10001:10001
WORKDIR /srv
EXPOSE 8000

# No shell form: the process is PID 1 with no shell interposed, so signals
# reach it and there is no shell in the process tree to abuse.
ENTRYPOINT ["gunicorn", "ehealth.main:app"]
CMD ["--worker-class", "uvicorn.workers.UvicornWorker", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--timeout", "30", \
     "--graceful-timeout", "30", \
     "--max-requests", "2000", \
     "--max-requests-jitter", "200", \
     "--forwarded-allow-ips", "*", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
