# CVEngine application image (web, celery, celery-beat).
# Based on the Ubuntu LTS for the system libraries; Python is a pinned CPython build (see the python stage below), not the distribution's. The server runs no scan tool and ships none, nor any template set: every probe, template
# run and template check runs on a Sentinel (the built-in scanner container or an external one), and what the server knows about the templates comes
# from the template index of the Sentinel library it installs (cvengine_scanner.template_index). tests/test_no_local_tools.py fails a build that adds
# a scan tool back.

# Python. Ubuntu 26.04 ships only CPython 3.14.4, and 3.14.0 to 3.14.4 carry the incremental cyclic garbage collector that CPython reverted in 3.14.5
# (python.org, Python 3.14.5 release notes): under the gevent pool of the celery workers it crashed the process with "Fatal Python error: Segmentation
# fault" inside the collector. This stage installs the pinned CPython (a python-build-standalone build, fetched and checksum verified by uv, for amd64 and
# arm64 alike) into /opt/python, which the image stage copies; uv itself stays out of the image. tests/test_image_python.py refuses a known bad version here.
ARG PYTHON_VERSION=3.14.10
FROM ghcr.io/astral-sh/uv:0.13.9 AS uv
FROM ubuntu:26.04 AS python
ARG PYTHON_VERSION
COPY --from=uv /uv /usr/local/bin/uv
RUN set -eu; \
    UV_PYTHON_INSTALL_DIR=/tmp/uv-python uv python install --no-bin "$PYTHON_VERSION"; \
    mv "$(dirname "$(dirname "$(UV_PYTHON_INSTALL_DIR=/tmp/uv-python uv python find --no-project --managed-python "$PYTHON_VERSION")")")" /opt/python; \
    rm -f /opt/python/lib/python*/EXTERNALLY-MANAGED; \
    /opt/python/bin/python3 -c "import sys; v = sys.version_info[:3]; print('Python', sys.version); sys.exit(1 if v[:2] == (3, 14) and v[2] <= 4 else 0)"

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
    tzdata && \
    rm -rf /var/lib/apt/lists/*


# Make directory for app
WORKDIR /usr/src/app

# Application dependencies in a virtual environment on the pinned Python (the python stage); the image carries no distribution Python
COPY --from=python /opt/python /opt/python
RUN /opt/python/bin/python3 -m venv /opt/venv \
    && python -c "import sys; v = sys.version_info[:3]; sys.exit(1 if v[:2] == (3, 14) and v[2] <= 4 else 0)"
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
