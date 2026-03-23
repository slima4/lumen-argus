# ---- build stage ----
FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY lumen_argus/ lumen_argus/

# gcc needed to build pyahocorasick C extension (not in slim image)
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && pip install --no-cache-dir --prefix=/install . \
    && apt-get purge -y gcc libc6-dev && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# ---- runtime stage ----
FROM python:3.12-slim

LABEL org.opencontainers.image.title="lumen-argus" \
      org.opencontainers.image.description="Transparent DLP proxy for AI coding tools" \
      org.opencontainers.image.url="https://github.com/slima4/lumen-argus" \
      org.opencontainers.image.source="https://github.com/slima4/lumen-argus" \
      org.opencontainers.image.licenses="MIT"

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
