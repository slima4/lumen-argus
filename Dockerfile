# ---- build stage ----
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tools + deps first (cached unless pyproject.toml changes)
COPY packages/core/pyproject.toml packages/core/pyproject.toml
COPY packages/proxy/pyproject.toml packages/proxy/pyproject.toml
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev libre2-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source and install (only re-runs on code changes, gcc is cached)
# The [rules-analysis] extra pulls crossfire-rules[re2]>=0.2.0 from PyPI — single source of truth
COPY packages/core/lumen_argus_core/ packages/core/lumen_argus_core/
COPY packages/proxy/lumen_argus/ packages/proxy/lumen_argus/
RUN pip install --no-cache-dir --prefix=/install packages/core/ "packages/proxy/[rules-analysis]"

# ---- runtime stage ----
FROM python:3.12-slim

LABEL org.opencontainers.image.title="lumen-argus" \
      org.opencontainers.image.description="Transparent DLP proxy for AI coding tools" \
      org.opencontainers.image.url="https://github.com/lumen-argus/lumen-argus" \
      org.opencontainers.image.source="https://github.com/lumen-argus/lumen-argus" \
      org.opencontainers.image.licenses="MIT"

# RE2 shared library needed at runtime by google-re2
RUN apt-get update && apt-get install -y --no-install-recommends libre2-11 \
    && rm -rf /var/lib/apt/lists/*

# Copy only installed packages from builder — no pip, setuptools, or source
COPY --from=builder /install /usr/local

# Non-root user
RUN groupadd -r argus && useradd -r -g argus -m argus \
    && mkdir -p /home/argus/.lumen-argus \
    && chown -R argus:argus /home/argus/.lumen-argus

USER argus
WORKDIR /home/argus

EXPOSE 8080 8081

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')" || exit 1

ENTRYPOINT ["lumen-argus"]
CMD ["serve", "--host", "0.0.0.0"]
