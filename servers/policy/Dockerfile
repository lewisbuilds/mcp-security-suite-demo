FROM registry.access.redhat.com/ubi9/ubi-minimal:9.3 AS tools
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG OPA_VERSION=v0.58.0
ARG OPA_BIN_SHA256
# curl and sha256sum present already. No tar needed for static binary. Install nothing.
RUN mkdir -p /opt/tools \
  && curl -sSL -o /opt/tools/opa https://openpolicyagent.org/downloads/${OPA_VERSION}/opa_linux_amd64_static \
  && if [ -n "${OPA_BIN_SHA256}" ]; then echo "${OPA_BIN_SHA256}  /opt/tools/opa" | sha256sum -c -; else echo "WARNING: Skipping OPA checksum verification (OPA_BIN_SHA256 unset)" >&2; fi \
  && chmod +x /opt/tools/opa

# --- Runtime image ---
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.3
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG USER_ID=10001
ARG VERSION=0.1.0
ARG VCS_REF
ARG BUILD_DATE

ENV PYTHONDONTWRITEBYTECODE=1 \
  PYTHONUNBUFFERED=1 \
  HOME=/home/appuser

LABEL org.opencontainers.image.title="mcp-security-suite-policy" \
    org.opencontainers.image.description="MCP server providing policy evaluation with OPA/Rego" \
    org.opencontainers.image.version="${VERSION}" \
    org.opencontainers.image.created="${BUILD_DATE}" \
    org.opencontainers.image.revision="${VCS_REF}" \
    org.opencontainers.image.source="https://github.com/lewisbuilds/mcp-supply-chain-security"

RUN microdnf install -y python3.12 python3.12-pip shadow-utils && \
  microdnf clean all && \
  useradd -r -u ${USER_ID} -m -g root appuser

# Copy OPA from tools stage
COPY --from=tools /opt/tools/opa /usr/local/bin/opa

WORKDIR /app
COPY --chown=appuser:appuser requirements.txt ./
RUN python3.12 -m pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appuser app.py policy.rego ./
USER ${USER_ID}

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python3.12 /app/app.py --health || exit 1

ENTRYPOINT ["python3.12", "app.py"]
