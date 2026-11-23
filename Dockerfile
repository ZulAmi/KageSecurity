# syntax=docker/dockerfile:1

# ---- 1. Go template engine -----------------------------------------------------
FROM golang:1.27-bookworm AS engine
WORKDIR /src/engine
COPY engine/go.mod engine/go.sum ./
RUN go mod download
COPY engine/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kagesec-engine .

# ---- 2. Python wheel (bundles the engine binary) -------------------------------
FROM python:3.12-slim-bookworm AS build
WORKDIR /src
RUN pip install --no-cache-dir build
COPY pyproject.toml setup.py README.md LICENSE ./
COPY cli/ cli/
COPY scanner/ scanner/
COPY --from=engine /out/kagesec-engine scanner/_bin/kagesec-engine
RUN python -m build --wheel --outdir /dist

# ---- 3. Runtime ----------------------------------------------------------------
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="KageSec" \
      org.opencontainers.image.description="AI-assisted DAST scanner" \
      org.opencontainers.image.source="https://github.com/ZulAmi/KageSecurity" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # Shared browser location so the non-root user can use the Chromium installed as root
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

COPY --from=build /dist/ /tmp/dist/
RUN set -eux; \
    # Playwright's bundled Node driver needs libatomic before it can install anything
    apt-get update; \
    apt-get install -y --no-install-recommends libatomic1; \
    wheel="$(ls /tmp/dist/kagesec-*.whl)"; \
    pip install "${wheel}[all]"; \
    playwright install --with-deps chromium; \
    rm -rf /tmp/dist /var/lib/apt/lists/*; \
    useradd --create-home --uid 10001 --shell /usr/sbin/nologin kagesec; \
    mkdir -p /work; \
    # Writable by any UID so `docker run --user "$(id -u):$(id -g)"` works with bind mounts
    chmod 1777 /work /home/kagesec

ENV HOME=/home/kagesec
USER 10001
WORKDIR /work
ENTRYPOINT ["kagesec"]
CMD ["--help"]
