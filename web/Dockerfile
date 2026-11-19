# CVEngine application image (web, celery, celery-beat).
# Based on the Ubuntu LTS; Python from the distribution. The server runs no scan tool and ships none, nor any template set: every probe, template
# run and template check runs on a Sentinel (the built-in scanner container or an external one), and what the server knows about the templates comes
# from the template index of the Sentinel library it installs (cvengine_scanner.template_index). tests/test_no_local_tools.py fails a build that adds
# a scan tool back.

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


# Make directory for app
WORKDIR /usr/src/app

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
