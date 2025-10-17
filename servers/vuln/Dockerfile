FROM registry.access.redhat.com/ubi9/ubi-minimal:9.3 AS tools
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG TRIVY_VERSION=v0.47.0
ARG TRIVY_TAR_SHA256
# curl and sha256sum already provided (curl-minimal + coreutils-single). Only add tar/gzip.
RUN microdnf install -y tar gzip \
    && microdnf clean all \
    && mkdir -p /opt/tools/bin \
    && curl -sSfL -o /tmp/trivy.tgz https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION#v}_Linux-64bit.tar.gz \
    && if [ -n "${TRIVY_TAR_SHA256}" ]; then echo "${TRIVY_TAR_SHA256}  /tmp/trivy.tgz" | sha256sum -c -; else echo "WARNING: Skipping Trivy checksum verification (TRIVY_TAR_SHA256 unset)" >&2; fi \
    && tar -xzf /tmp/trivy.tgz -C /opt/tools/bin trivy \
    && rm /tmp/trivy.tgz

# --- Runtime image ---
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.3
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG USER_ID=10001
ARG VERSION=0.1.0
ARG VCS_REF
ARG BUILD_DATE

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/appuser \
    PATH="/usr/local/bin:/opt/tools/bin:${PATH}"

LABEL org.opencontainers.image.title="mcp-security-suite-vuln" \
      org.opencontainers.image.description="MCP server providing vulnerability scanning using Trivy" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/lewisbuilds/mcp-supply-chain-security"

RUN microdnf install -y python3.12 python3.12-pip shadow-utils && \
    microdnf clean all && \
    useradd -r -u ${USER_ID} -m -g root appuser

# Copy Trivy from tools stage
COPY --from=tools /opt/tools/bin/trivy /usr/local/bin/trivy

WORKDIR /app
COPY --chown=appuser:appuser requirements.txt ./
RUN python3.12 -m pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appuser app.py ./
USER ${USER_ID}

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python3.12 -c "print('OK')" || exit 1

ENTRYPOINT ["python3.12", "app.py"]
