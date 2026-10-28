# CVEngine application image (web, celery, celery-beat).
# Based on the Ubuntu LTS; Python from the distribution, Go and nmap taken from pinned, checksummed releases.
FROM ubuntu:26.04

# Versions are pinned so builds are reproducible; the security tools below track their latest release at build time.
ARG GOVERSION=1.27.3
ARG GO_SHA256_AMD64=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40
ARG GO_SHA256_ARM64=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49
ARG NMAPVERSION=7.993
# Scanner tools, pinned to versions that were built and tested together (the CI smoke test uses the same nuclei). A tool is bumped on
# purpose, after scripts/check_tool_versions.py says a newer one exists: see "Pinned tools" in docs/UPDATES.md. Nuclei's TEMPLATES are not
# pinned: they refresh at runtime.
ARG NUCLEI_VERSION=3.11.1
ARG NAABU_VERSION=2.6.1
ARG BBOT_VERSION=3.0.2
ARG TZDATA_VERSION=2026.5
# nmap: amd64 installs the project's own x86_64 release RPM (its libraries are linked in statically), arm64 builds the source
# tarball, because nmap.org publishes no arm64 binary. Both checksums are published beside the files at nmap.org/dist/sigs/.
ARG NMAP_SHA256=270e55f04915bfcecb5db8feb959d4c5ba86a48c094520a4f1c07571e1c79c59
ARG NMAP_RPM_SHA256_AMD64=997cb830c84a429aaa1d41708a1ebb9b1cc36e75d21801c9d359fe930a8c1f93

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
    fonts-dejavu-core \
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

# nmap, the current release (the distribution package lags by years), checksum verified. On amd64 the official release RPM is
# unpacked (no compile: minutes saved on every uncached build and the binary is the one the nmap project ships); on arm64 there is no
# official binary, so the release tarball is compiled. Either way it lives under /usr/local, where nmap_scan.py looks for its data.
RUN set -e; cd /tmp \
    && if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        curl -fsSLO https://nmap.org/dist/nmap-${NMAPVERSION}-1.x86_64.rpm \
        && echo "${NMAP_RPM_SHA256_AMD64}  nmap-${NMAPVERSION}-1.x86_64.rpm" | sha256sum -c - \
        && apt-get update -y && apt-get install -y --no-install-recommends libarchive-tools \
        && mkdir nmap-rpm && bsdtar -xf nmap-${NMAPVERSION}-1.x86_64.rpm -C nmap-rpm \
        && install -D -m 0755 nmap-rpm/usr/bin/nmap /usr/local/bin/nmap \
        && mkdir -p /usr/local/share && cp -r nmap-rpm/usr/share/nmap /usr/local/share/nmap \
        && apt-get purge -y libarchive-tools && rm -rf /var/lib/apt/lists/* nmap-rpm nmap-${NMAPVERSION}-1.x86_64.rpm; \
    else \
        curl -fsSLO https://nmap.org/dist/nmap-${NMAPVERSION}.tar.bz2 \
        && echo "${NMAP_SHA256}  nmap-${NMAPVERSION}.tar.bz2" | sha256sum -c - \
        && tar xjf nmap-${NMAPVERSION}.tar.bz2 \
        && cd nmap-${NMAPVERSION} \
        && ./configure --prefix=/usr/local --without-zenmap --without-ndiff --without-nmap-update \
        && make -j"$(nproc)" \
        && make install \
        && cd / && rm -rf /tmp/nmap-${NMAPVERSION}*; \
    fi \
    && nmap --version | head -2
# The packaged binary looks for its data under /usr/share/nmap; the compiled one under /usr/local/share/nmap. One variable fixes both.
ENV NMAPDIR=/usr/local/share/nmap
# the scripts and data are found on both architectures, not only the version string
RUN nmap --script-help ssl-cert | grep -q '^ssl-cert' && test -s "$NMAPDIR/nmap-service-probes"

# Make directory for app
WORKDIR /usr/src/app

ENV GO111MODULE=on
RUN printf "\
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v${NUCLEI_VERSION}\n\
    github.com/projectdiscovery/naabu/v2/cmd/naabu@v${NAABU_VERSION}\n" | \
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
    /opt/bbot-venv/bin/pip install --no-cache-dir bbot==${BBOT_VERSION} tzdata==${TZDATA_VERSION} && \
    ln -s /opt/bbot-venv/bin/bbot /usr/local/bin/bbot
# Fail the build when this bbot no longer reads the way cvENGINE passes it API keys (a preset file listed after the named presets,
# which must still load every module of the default scan). bbot 3.x rejects a config file after -c and ignores all but the last -p,
# and both used to make scans quietly find nothing. It runs no scan, but bbot installs the dependencies of the modules it loads before the dry run
# stops, so this is also what bakes gowitness and its Chromium into the image (screenshots need them) instead of fetching them in a running worker.
RUN printf 'config:\n  modules:\n    shodan_dns:\n      api_key: build-check\n' > /tmp/keys.yml && \
    bbot -t example.com -p subdomain-enum web web-screenshots /tmp/keys.yml -rf safe --force --dry-run -v 2>&1 | tee /tmp/bbot-check.txt | \
        grep -q 'Loading [0-9]* scan modules:.*shodan_dns' && \
    grep -q 'gowitness' /tmp/bbot-check.txt && \
    bbot -t example.com -p subdomain-enum /tmp/keys.yml --current-preset 2>&1 | grep -q 'api_key: build-check' && \
    ! grep -q 'Error parsing' /tmp/bbot-check.txt && rm -f /tmp/keys.yml /tmp/bbot-check.txt

# WPScan, run against every host that shows any sign of WordPress, quick pass in the scan and a thorough pass in the background (see docs/CONFIGURATION.md for its licence).
# Pinned; its vulnerability metadata is fetched now and refreshed by WPScan itself while it runs.
ARG WPSCAN_VERSION=4.1.0
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends ruby ruby-dev libcurl4-openssl-dev libxml2-dev libxslt1-dev libffi-dev zlib1g-dev && \
    gem install wpscan -v ${WPSCAN_VERSION} --no-document && \
    (wpscan --update --no-banner || echo "WPScan database not fetched at build time; it updates on first use") && \
    rm -rf /var/lib/apt/lists/* /root/.gem/cache

# testssl.sh (GPLv2, run as a separate program) audits the TLS configuration of every TLS port: protocols, ciphers, forward secrecy and the named
# TLS vulnerabilities (see cveFeed/testssl_scan.py). Pinned tarball with its checksum, never a branch. It needs dig (--nodns none still checks
# for it), hexdump and ps; the x86_64 tarball bundles an openssl that still speaks SSLv2/SSLv3 and export ciphers (arm64 uses the system openssl).
ARG TESTSSL_VERSION=3.2.3
ARG TESTSSL_SHA256=1c4bb10185a67592164eb870c717b8bdd03f290c8d68f9a8c658335ff5ac8b91
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends bind9-dnsutils bsdextrautils procps && \
    curl -fsSL -o /tmp/testssl.tar.gz "https://testssl.sh/testssl.sh-${TESTSSL_VERSION}.tar.gz" && \
    echo "${TESTSSL_SHA256}  /tmp/testssl.tar.gz" | sha256sum -c - && \
    mkdir -p /opt/testssl && tar -xzf /tmp/testssl.tar.gz -C /opt/testssl --strip-components=1 && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh && \
    rm -f /tmp/testssl.tar.gz && rm -rf /var/lib/apt/lists/* && \
    testssl.sh --version 2>&1 | grep -q "${TESTSSL_VERSION}"

# Copy source code
COPY . /usr/src/app/
