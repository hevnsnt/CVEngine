# CVEngine application image (web, celery, celery-beat).
# Based on the Ubuntu LTS; Python from the distribution. The server runs no scan tool: every probe runs on a Sentinel (the built-in scanner
# container or an external one). What stays is nuclei, whose template set the server keeps current (the update_nuclei_templates task) and
# reads to write and check templates. It is built in a throwaway stage, so the Go toolchain is not part of the image.

# Versions are pinned so builds are reproducible. nuclei is pinned to the version the CI smoke test uses and bumped on purpose, after
# scripts/check_tool_versions.py says a newer one exists: see "Pinned tools" in docs/UPDATES.md. Its TEMPLATES are not pinned: they refresh at runtime.
ARG GOVERSION=1.27.3
ARG GO_SHA256_AMD64=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40
ARG GO_SHA256_ARM64=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49
ARG NUCLEI_VERSION=3.11.1

# Build stage: the Go toolchain (checksum verified) compiles nuclei; only the binary is copied on.
FROM ubuntu:26.04 AS nuclei-build
ARG GOVERSION
ARG GO_SHA256_AMD64
ARG GO_SHA256_ARM64
ARG NUCLEI_VERSION
ENV DEBIAN_FRONTEND="noninteractive" GOROOT="/usr/local/go" GOPATH="/root/go" GO111MODULE=on
ENV PATH="${PATH}:/usr/local/go/bin"
RUN apt-get update -y && apt-get install -y --no-install-recommends ca-certificates curl git gcc libc6-dev && rm -rf /var/lib/apt/lists/*
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" = "arm64" ]; then GO_SHA="${GO_SHA256_ARM64}"; else GO_SHA="${GO_SHA256_AMD64}"; fi \
    && curl -fsSLo /tmp/go.tgz https://go.dev/dl/go${GOVERSION}.linux-${ARCH}.tar.gz \
    && echo "${GO_SHA}  /tmp/go.tgz" | sha256sum -c - \
    && tar -xzC /usr/local -f /tmp/go.tgz \
    && rm /tmp/go.tgz
RUN GOBIN=/out go install -ldflags="-s -w" -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v${NUCLEI_VERSION}

FROM ubuntu:26.04

RUN ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" != "arm64" ] && [ "${ARCH}" != "amd64" ]; then \
      echo "CVEngine supports amd64 and arm64, found: ${ARCH}" \
      && exit 1; \
    fi

# Labels and credits (CVEngine is a fork of reNgine by Yogesh Ojha, GPL-3.0)
LABEL \
    name="CVEngine" \
    description="AI-first vulnerability management: discovery, inventory, live CVE correlation and automated testing." \
    org.opencontainers.image.source="https://github.com/hevnsnt/CVEngine" \
    org.opencontainers.image.licenses="GPL-3.0-only"

# Environment Variables
ENV DEBIAN_FRONTEND="noninteractive" \
    DATABASE="postgres" \
    TZ="UTC"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/venv/bin:${PATH}"

# System packages. tzdata matters: without zone data Python's zoneinfo (Django's time zones) cannot find "UTC".
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    fonts-dejavu-core \
    gcc \
    git \
    libharfbuzz-subset0 \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpq-dev \
    libssl-dev \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    tzdata && \
    rm -rf /var/lib/apt/lists/*

# Legacy GeoIP lookups (geoiplookup); the package is not in every release, so its absence is not fatal.
RUN apt-get update -y && (apt-get install -y --no-install-recommends geoip-bin geoip-database || echo "geoip packages not available: IP geolocation is skipped") && \
    rm -rf /var/lib/apt/lists/*

# nuclei, from the build stage
COPY --from=nuclei-build /out/nuclei /usr/local/bin/nuclei

# Make directory for app
WORKDIR /usr/src/app

# Update Nuclei and Nuclei-Templates (refreshed daily at runtime by the update_nuclei_templates task)
RUN nuclei -update-templates

# Application dependencies in a virtual environment (the distribution Python is externally managed)
RUN python3 -m venv /opt/venv
COPY ./requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r /tmp/requirements.txt

# The Sentinel library (scan policy, parsers, the result contract the server reads) at the NEWEST build of SENTINEL_REF (default main), resolved to a commit when the
# image is built. web/requirements.txt pins a known-good floor commit, which CI and a plain pip install use; this installs the newest over it, so a server built today reads
# the contract of today's Sentinel. SENTINEL_SHA (docker-compose.yml, from scripts/sentinel-ref.sh) is that commit, passed in so Docker rebuilds the layer when main
# moved; empty, it is resolved here. pip records the installed commit (direct_url.json), which the About page and the Sentinels page read (agentapi/sentinel_source.py).
ARG SENTINEL_REPO=https://github.com/hevnsnt/cvENGINE-sentinel
ARG SENTINEL_REF=main
ARG SENTINEL_SHA=
RUN set -eu; sha="$SENTINEL_SHA"; \
    if [ -z "$sha" ]; then sha=$(printf '%s' "$SENTINEL_REF" | grep -E '^[0-9a-f]{40}$' || git ls-remote "$SENTINEL_REPO" "refs/heads/$SENTINEL_REF" "refs/tags/$SENTINEL_REF^{}" "refs/tags/$SENTINEL_REF" | awk '{print $1}' | head -n 1); fi; \
    printf '%s' "$sha" | grep -Eq '^[0-9a-f]{40}$' || { echo "could not resolve SENTINEL_REF=$SENTINEL_REF to a commit of $SENTINEL_REPO" >&2; exit 1; }; \
    pip install --no-cache-dir "cvengine-scanner @ git+${SENTINEL_REPO}@${sha}" \
    && python -c "import json,importlib.metadata as m; print('Sentinel library', json.loads(m.distribution('cvengine-scanner').read_text('direct_url.json'))['vcs_info']['commit_id'])"
# what the image was asked for (the commit it holds is in the package's direct_url.json: `docker run --rm cvengine/web:latest python -c ...`, and on the About page)
LABEL com.cvengine.sentinel.ref="${SENTINEL_REF}" \
      com.cvengine.sentinel.sha="${SENTINEL_SHA}"

# Copy source code
COPY . /usr/src/app/
