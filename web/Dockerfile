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
    github.com/jaeles-project/gospider@latest\n\
    github.com/tomnomnom/gf@latest\n\
    github.com/tomnomnom/unfurl@latest\n\
    github.com/tomnomnom/waybackurls@latest\n\
    github.com/projectdiscovery/httpx/cmd/httpx@latest\n\
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n\
    github.com/projectdiscovery/chaos-client/cmd/chaos@latest\n\
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n\
    github.com/projectdiscovery/naabu/v2/cmd/naabu@latest\n\
    github.com/hakluke/hakrawler@latest\n\
    github.com/lc/gau/v2/cmd/gau@latest\n\
    github.com/ffuf/ffuf@latest\n\
    github.com/projectdiscovery/tlsx/cmd/tlsx@latest\n\
    github.com/hahwul/dalfox/v2@latest\n\
    github.com/projectdiscovery/katana/cmd/katana@latest\n\
    github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest\n\
    github.com/sa7mon/s3scanner@latest\n" | \
    xargs -L1 go install -ldflags="-s -w" -v && \
    rm -rf /go/pkg/* && rm -rf /root/.cache/go-build

# Update Nuclei and Nuclei-Templates (refreshed daily at runtime by the update_nuclei_templates task)
RUN nuclei -update-templates

# update chaos
RUN chaos -update

# Application dependencies in a virtual environment (the distribution Python is externally managed)
RUN python3 -m venv /opt/venv
COPY ./requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r /tmp/requirements.txt

# bbot (isolated venv so its dependency pins cannot clash with the application's)
RUN python3 -m venv /opt/bbot-venv && \
    /opt/bbot-venv/bin/pip install --no-cache-dir bbot tzdata && \
    ln -s /opt/bbot-venv/bin/bbot /usr/local/bin/bbot

# Copy source code
COPY . /usr/src/app/
