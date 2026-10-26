# CVEngine application image (web, celery, celery-beat).
# Based on the Ubuntu LTS; Python from the distribution, Go and nmap built from pinned, checksummed releases.
FROM ubuntu:26.04

# Versions are pinned so builds are reproducible; the security tools below track their latest release at build time.
ARG GOVERSION=1.27.3
ARG GO_SHA256_AMD64=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40
ARG GO_SHA256_ARM64=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49
ARG NMAPVERSION=7.992
ARG NMAP_SHA256=0c12660eddbf7eabeff6996cb0c044a4eadf2bb0c6fbcb340d6cf72b1caee402

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
ENV GOROOT="/usr/local/go"
ENV GOPATH="/root/go"
ENV PATH="/opt/venv/bin:${PATH}:${GOROOT}/bin:${GOPATH}/bin"

# System packages. tzdata matters: without zone data Python's zoneinfo (used by bbot) cannot find "UTC".
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
    build-essential \
    bzip2 \
    ca-certificates \
    cargo \
    cmake \
    curl \
    gcc \
    git \
    jq \
    libharfbuzz-subset0 \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpcap-dev \
    libpq-dev \
    libssl-dev \
    netcat-openbsd \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    rustc \
    tzdata \
    wget && \
    rm -rf /var/lib/apt/lists/*

# Legacy GeoIP lookups (geoiplookup); the package is not in every release, so its absence is not fatal.
RUN apt-get update -y && (apt-get install -y --no-install-recommends geoip-bin geoip-database || echo "geoip packages not available: IP geolocation is skipped") && \
    rm -rf /var/lib/apt/lists/*

# Go toolchain, checksum verified
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" = "arm64" ]; then GO_SHA="${GO_SHA256_ARM64}"; else GO_SHA="${GO_SHA256_AMD64}"; fi \
    && curl -fsSLo /tmp/go.tgz https://go.dev/dl/go${GOVERSION}.linux-${ARCH}.tar.gz \
    && echo "${GO_SHA}  /tmp/go.tgz" | sha256sum -c - \
    && tar -xzC /usr/local -f /tmp/go.tgz \
    && rm /tmp/go.tgz

# nmap, built from the current release (the distribution package lags by years), checksum verified
RUN set -e; cd /tmp \
    && curl -fsSLO https://nmap.org/dist/nmap-${NMAPVERSION}.tar.bz2 \
    && echo "${NMAP_SHA256}  nmap-${NMAPVERSION}.tar.bz2" | sha256sum -c - \
    && tar xjf nmap-${NMAPVERSION}.tar.bz2 \
    && cd nmap-${NMAPVERSION} \
    && ./configure --prefix=/usr/local --without-zenmap --without-ndiff --without-nmap-update \
    && make -j"$(nproc)" \
    && make install \
    && cd / && rm -rf /tmp/nmap-${NMAPVERSION}*  \
    && nmap --version | head -2

# Make directory for app
WORKDIR /usr/src/app

ENV GO111MODULE=on
RUN printf "\
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n\
    github.com/projectdiscovery/naabu/v2/cmd/naabu@latest\n" | \
    xargs -L1 go install -ldflags="-s -w" -v && \
    rm -rf /go/pkg/* && rm -rf /root/.cache/go-build

# Update Nuclei and Nuclei-Templates (refreshed daily at runtime by the update_nuclei_templates task)
RUN nuclei -update-templates

# Application dependencies in a virtual environment (the distribution Python is externally managed)
RUN python3 -m venv /opt/venv
COPY ./requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r /tmp/requirements.txt

# bbot (isolated venv so its dependency pins cannot clash with the application's)
RUN python3 -m venv /opt/bbot-venv && \
    /opt/bbot-venv/bin/pip install --no-cache-dir bbot tzdata && \
    ln -s /opt/bbot-venv/bin/bbot /usr/local/bin/bbot
# Fail the build when this bbot no longer reads the way cvENGINE passes it API keys (a preset file listed after the named presets,
# which must still load every module of the default scan). bbot 3.x rejects a config file after -c and ignores all but the last -p,
# and both used to make scans quietly find nothing; this check is offline and runs no scan.
RUN printf 'config:\n  modules:\n    shodan_dns:\n      api_key: build-check\n' > /tmp/keys.yml && \
    bbot -t example.com -p subdomain-enum web /tmp/keys.yml -rf safe --force --dry-run -v 2>&1 | tee /tmp/bbot-check.txt | \
        grep -q 'Loading [0-9]* scan modules:.*shodan_dns' && \
    bbot -t example.com -p subdomain-enum /tmp/keys.yml --current-preset 2>&1 | grep -q 'api_key: build-check' && \
    ! grep -q 'Error parsing' /tmp/bbot-check.txt && rm -f /tmp/keys.yml /tmp/bbot-check.txt

# WPScan, run only against WordPress sites a scan has already fingerprinted (see docs/CONFIGURATION.md for its licence).
# Pinned; its vulnerability metadata is fetched now and refreshed by WPScan itself while it runs.
ARG WPSCAN_VERSION=4.1.0
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends ruby ruby-dev libcurl4-openssl-dev libxml2-dev libxslt1-dev libffi-dev zlib1g-dev && \
    gem install wpscan -v ${WPSCAN_VERSION} --no-document && \
    (wpscan --update --no-banner || echo "WPScan database not fetched at build time; it updates on first use") && \
    rm -rf /var/lib/apt/lists/* /root/.gem/cache

# Copy source code
COPY . /usr/src/app/
