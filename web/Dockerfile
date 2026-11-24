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
FROM ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d AS uv
FROM ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db AS python
ARG PYTHON_VERSION
COPY --from=uv /uv /usr/local/bin/uv
RUN set -eu; \
    UV_PYTHON_INSTALL_DIR=/tmp/uv-python uv python install --no-bin "$PYTHON_VERSION"; \
    mv "$(dirname "$(dirname "$(UV_PYTHON_INSTALL_DIR=/tmp/uv-python uv python find --no-project --managed-python "$PYTHON_VERSION")")")" /opt/python; \
    rm -f /opt/python/lib/python*/EXTERNALLY-MANAGED; \
    /opt/python/bin/python3 -c "import sys; v = sys.version_info[:3]; print('Python', sys.version); sys.exit(1 if v[:2] == (3, 14) and v[2] <= 4 else 0)"

FROM ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db

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

# The Sentinel library (scan policy, parsers, the result contract the server reads) is installed by the requirements above at EXACTLY the commit
# web/requirements.txt pins, and nothing installs another over it: no branch name is resolved at build time, so the image holds the commit a reviewed
# pull request chose. scanner.lock.json names the same commit (and the built-in scanner image published from it); `python3 scripts/scanner_lock.py bump`
# moves both together (docs/UPDATES.md, "The Sentinel library in the server image"). pip records the installed commit (direct_url.json), which the build
# prints, the About page and the Sentinels page read (agentapi/sentinel_source.py), and tests/test_sentinel_source.py checks against the pin.
RUN python -c "import json,importlib.metadata as m; print('Sentinel library', json.loads(m.distribution('cvengine-scanner').read_text('direct_url.json'))['vcs_info']['commit_id'])"

# whatportis (the port name lookup) truncates its table instead of purging it (https://github.com/yogeshojha/rengine/issues/984). Patched here, at build
# time, because the installed packages belong to root and the workers do not run as root (below).
RUN sed -i 's/purge()/truncate()/g' "$(python -c "import os, whatportis; print(os.path.join(os.path.dirname(whatportis.__file__), 'cli.py'))")"

# The unprivileged account web, celery, celery-beat and the one-off migrate service run as (docs/DEPLOYMENT.md, "Who the containers run as"). The
# uid is fixed, 10002, the AI reviewer container's: the server writes the reviewer's token, and a file it creates is then the reviewer's own with no
# chown and no capability. Its supplementary group 101 is the nginx group of the proxy image: the scan results folder is root's or this account's
# and group 101, mode 0750, so only this account and the proxy (which serves /protected_media/ from it) can enter it. The application source and the
# installed packages stay root's and read only to it. Only the paths it must write are its own: HOME (with ~/.config, where the CVE seed folder is,
# a volume, and ~/logs, where errors.log, db.log and celery.log go: CVENGINE_LOG_DIR, reNgine/settings.py), the generated templates folder, the scan results and the static files folder (volumes; the ownership service of docker-compose.yml
# hands existing ones over once). /root itself becomes traversable (0711) because the generated templates volume keeps its historical path below
# it: rows in the database record that path.
ENV HOME=/home/cvengine \
    CVENGINE_LOG_DIR=/home/cvengine/logs
RUN groupadd --gid 10002 cvengine \
    && groupadd --gid 101 cvengine-proxy \
    && useradd --uid 10002 --gid 10002 --groups cvengine-proxy --home-dir /home/cvengine --create-home --shell /usr/sbin/nologin cvengine \
    && mkdir -p /home/cvengine/.config /home/cvengine/logs /root/cvengine-generated-templates /usr/src/scan_results /usr/src/app/staticfiles \
    && chown cvengine:cvengine /home/cvengine/.config /home/cvengine/logs /root/cvengine-generated-templates /usr/src/app/staticfiles \
    && chown cvengine:cvengine-proxy /usr/src/scan_results && chmod 0750 /usr/src/scan_results \
    && chmod 0711 /root

# Copy source code (root's, read only to the application account). The entrypoints run as the account below.
COPY . /usr/src/app/
# COPY keeps the modes the checkout has, and a host whose umask is 027 checks files out unreadable to others: the source is made readable (and never
# writable) to every account here, touching only the files that need it, so a checkout with ordinary modes adds nothing to this layer. The one-off
# ownership service (docker-compose.yml) runs ownership.sh as root with CHOWN, FOWNER and DAC_OVERRIDE only; everything else runs as cvengine.
RUN find /usr/src/app -path /usr/src/app/staticfiles -prune -o \( -perm /0022 -o \( -type d ! -perm -0555 \) -o \( -type f ! -perm -0444 \) \) \
        -exec chmod a+rX,go-w {} + \
    && chmod 0755 /usr/src/app/ownership.sh
USER 10002:10002
