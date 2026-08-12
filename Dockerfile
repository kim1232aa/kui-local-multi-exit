FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl iproute2 openvpn \
    && rm -rf /var/lib/apt/lists/*

# Install the matching sing-box release for bridge checks and Reality.
ARG TARGETARCH
ARG SING_BOX_VERSION=1.13.14
RUN case "$TARGETARCH" in amd64|arm64) ;; *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; esac \
    && curl -fsSL -o /tmp/sing-box.tar.gz \
        "https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-${TARGETARCH}.tar.gz" \
    && tar -xzf /tmp/sing-box.tar.gz -C /tmp \
    && mv "/tmp/sing-box-${SING_BOX_VERSION}-linux-${TARGETARCH}/sing-box" /usr/local/bin/sing-box \
    && chmod +x /usr/local/bin/sing-box \
    && ln -sf /usr/local/bin/sing-box /usr/local/bin/kui-sing-box \
    && rm -rf /tmp/sing-box.tar.gz "/tmp/sing-box-${SING_BOX_VERSION}-linux-${TARGETARCH}"

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
EXPOSE 8080 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

CMD ["python3", "-m", "vps.entrypoint"]
