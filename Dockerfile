ARG PYTHON_IMAGE=python:3.13.18-alpine3.24@sha256:7984cf56ceaddebe4fefeb75d64000b9f45d8b77b11a09b24524da6cdc3af0c8
FROM ${PYTHON_IMAGE} AS builder
ENV PIP_DEFAULT_TIMEOUT=60 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.lock ./
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.lock
COPY pyproject.toml ./
COPY app ./app
COPY scripts ./scripts
COPY sdk/python/src/xarionix_sdk ./sdk/python/src/xarionix_sdk
RUN /opt/venv/bin/pip install --no-deps . && /opt/venv/bin/python -m pip uninstall --yes pip

FROM ${PYTHON_IMAGE} AS base-runtime
ARG VERSION=0.1.0
ARG VCS_REF=unknown
ARG SOURCE_URL=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="Xarionix Core" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.created="${BUILD_DATE}"
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Runtime does not need package installers or their vendored dependency trees.
# This explicit image-only directory is CPython's bundled pip bootstrap, not user data.
RUN python -m pip uninstall --yes pip && rm -rf /usr/local/lib/python3.13/ensurepip \
    && addgroup -S -g 10001 xarionix && adduser -S -D -H -u 10001 -G xarionix xarionix \
    && mkdir -p /var/lib/xarionix/packages \
    && chown 10001:10001 /var/lib/xarionix/packages && chmod 700 /var/lib/xarionix/packages
WORKDIR /srv/core
COPY --from=builder /opt/venv /opt/venv
COPY --chown=10001:10001 app ./app
COPY --chown=10001:10001 scripts ./scripts
COPY --chown=10001:10001 migrations ./migrations
COPY --chown=10001:10001 alembic.ini ./
# COPY preserves restrictive checkout modes (native CI uses umask 0077).
# Only public application code is normalized; CAS/data/secrets remain private.
# The Agent has a different UID and must be able to import this same code.
RUN chmod -R u=rwX,go=rX app scripts migrations && chmod 644 alembic.ini
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--no-server-header", "--no-proxy-headers"]

# Separate service target. No Core/installer DB configuration is supplied to this image.
FROM base-runtime AS deployment-agent
USER 0:0
RUN addgroup -S -g 1000 deployment && adduser -S -D -H -u 1000 -G deployment deployment \
    && mkdir -p /var/lib/xarionix/deployment \
    && chown 1000:1000 /var/lib/xarionix/deployment && chmod 700 /var/lib/xarionix/deployment
LABEL org.opencontainers.image.title="Xarionix Deployment Agent"
USER 1000:1000
CMD ["python", "-m", "scripts.deployment_agent"]

# Separate data-plane service and OIDC principal; it never consumes deployment jobs.
FROM deployment-agent AS gateway-agent
LABEL org.opencontainers.image.title="Xarionix Module Gateway Agent"
CMD ["python", "-m", "scripts.gateway_agent"]

# Preserve the default production build as Core, not the Deployment Agent target.
FROM base-runtime AS runtime
