FROM registry.access.redhat.com/ubi9/ubi-minimal:9.3
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG USER_ID=10001
ARG VERSION=0.1.0
ARG VCS_REF
ARG BUILD_DATE

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/appuser

LABEL org.opencontainers.image.title="mcp-security-suite-report" \
      org.opencontainers.image.description="MCP server aggregating supply chain security reports" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/lewisbuilds/mcp-supply-chain-security"

RUN microdnf install -y python3.12 python3.12-pip shadow-utils && \
  microdnf clean all && \
  useradd -r -u ${USER_ID} -m -g root appuser

WORKDIR /app
COPY --chown=appuser:appuser requirements.txt ./
RUN python3.12 -m pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appuser app.py ./
USER ${USER_ID}

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python3.12 -c "print('OK')" || exit 1

ENTRYPOINT ["python3.12", "app.py"]
