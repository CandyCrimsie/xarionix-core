FROM python:3.13.18-alpine3.24@sha256:7984cf56ceaddebe4fefeb75d64000b9f45d8b77b11a09b24524da6cdc3af0c8
ARG HELLO_VERSION=1.0.0
ARG HELLO_READY=true
ENV HELLO_VERSION=${HELLO_VERSION} HELLO_READY=${HELLO_READY} PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN python -m pip uninstall --yes pip && rm -rf /usr/local/lib/python3.13/ensurepip \
    && addgroup -S -g 10001 hello && adduser -S -D -H -u 10001 -G hello hello
WORKDIR /app
COPY --chown=10001:10001 --chmod=0644 hello.py ./hello.py
USER 10001:10001
CMD ["/usr/local/bin/python", "-I", "/app/hello.py"]
