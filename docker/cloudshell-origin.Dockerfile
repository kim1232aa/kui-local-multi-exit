FROM ghcr.io/xtls/xray-core:latest AS xray

FROM python:3.12-slim-bookworm
COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
COPY vps/cloudshell_origin.py /app/cloudshell_origin.py

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    KUI_CLOUDSHELL_SECRETS=/run/secrets \
    KUI_CLOUDSHELL_DATA=/kui-data \
    KUI_CLOUDSHELL_RUNTIME=/run/origin \
    KUI_XRAY_BIN=/usr/local/bin/xray

CMD ["python3", "/app/cloudshell_origin.py"]
