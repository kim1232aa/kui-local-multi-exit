FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl iproute2 openvpn \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY vps /app/vps
COPY index.html /app/web/index.html

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    KUI_WORKSPACE=/opt/kui-local \
    KUI_DATABASE=/opt/kui-local/state.db \
    KUI_WEB_ROOT=/app/web \
    KUI_MANAGEMENT_HOST=0.0.0.0 \
    KUI_MANAGEMENT_PORT=8080

VOLUME ["/opt/kui-local"]
EXPOSE 8080 7920-7931
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

CMD ["python3", "-m", "vps.entrypoint"]
