# The Sentinel client: a small, standalone image with nmap, naabu, nuclei and the client daemon, nothing else.
# Pinned to the exact same tool versions web/Dockerfile pins (scripts/check_tool_versions.py checks both; keep them
# equal on purpose, see docs/UPDATES.md "Pinned tools"), so a Sentinel's results are never skewed by running a
# different nmap/naabu/nuclei than the instance it reports to would have run locally.
FROM ubuntu:26.04

ARG GOVERSION=1.27.3
ARG GO_SHA256_AMD64=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40
ARG GO_SHA256_ARM64=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49
ARG NMAPVERSION=7.993
ARG NUCLEI_VERSION=3.11.1
ARG NAABU_VERSION=2.6.1
# nmap: amd64 installs the project's own x86_64 release RPM (its libraries are linked in statically), arm64 builds the
# source tarball, because nmap.org publishes no arm64 binary. Both checksums are published beside the files at
# nmap.org/dist/sigs/ (identical to web/Dockerfile's own pins).
ARG NMAP_SHA256=270e55f04915bfcecb5db8feb959d4c5ba86a48c094520a4f1c07571e1c79c59
ARG NMAP_RPM_SHA256_AMD64=997cb830c84a429aaa1d41708a1ebb9b1cc36e75d21801c9d359fe930a8c1f93

LABEL \
    name="CVEngine Sentinel" \
    description="Downloadable scan-stage agent for CVEngine: runs nmap, naabu and nuclei work on your own network and reports typed results back." \
    org.opencontainers.image.source="https://github.com/hevnsnt/CVEngine" \
    org.opencontainers.image.licenses="GPL-3.0-only"

ENV DEBIAN_FRONTEND="noninteractive" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GOROOT="/usr/local/go" \
    GOPATH="/root/go"
ENV PATH="/opt/venv/bin:${PATH}:${GOROOT}/bin:${GOPATH}/bin"

RUN ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" != "arm64" ] && [ "${ARCH}" != "amd64" ]; then \
      echo "the Sentinel image supports amd64 and arm64, found: ${ARCH}" \
      && exit 1; \
    fi

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
    build-essential \
    bzip2 \
    ca-certificates \
    curl \
    python3 \
    python3-venv \
    tzdata \
    wget && \
    rm -rf /var/lib/apt/lists/*

# Go toolchain, checksum verified (build-time only: nuclei and naabu are installed as static binaries below)
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" = "arm64" ]; then GO_SHA="${GO_SHA256_ARM64}"; else GO_SHA="${GO_SHA256_AMD64}"; fi \
    && curl -fsSLo /tmp/go.tgz https://go.dev/dl/go${GOVERSION}.linux-${ARCH}.tar.gz \
    && echo "${GO_SHA}  /tmp/go.tgz" | sha256sum -c - \
    && tar -xzC /usr/local -f /tmp/go.tgz \
    && rm /tmp/go.tgz

# nmap, checksum verified, same pin and install method as web/Dockerfile (see its own comment for why the two paths).
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
ENV NMAPDIR=/usr/local/share/nmap
RUN test -s "$NMAPDIR/nmap-service-probes"

ENV GO111MODULE=on
RUN printf "\
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v${NUCLEI_VERSION}\n\
    github.com/projectdiscovery/naabu/v2/cmd/naabu@v${NAABU_VERSION}\n" | \
    xargs -L1 go install -ldflags="-s -w" -v && \
    rm -rf /go/pkg/* && rm -rf /root/.cache/go-build

# Nuclei's templates are refreshed once at build time and again on every container start (see docker-entrypoint.sh),
# same as the main image: they are not pinned by design (docs/UPDATES.md).
RUN nuclei -update-templates

WORKDIR /opt/sentinel

RUN python3 -m venv /opt/venv
COPY requirements.txt /opt/sentinel/requirements.txt
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r /opt/sentinel/requirements.txt

COPY client /opt/sentinel/client
COPY docker-entrypoint.sh /opt/sentinel/docker-entrypoint.sh
RUN chmod +x /opt/sentinel/docker-entrypoint.sh

ENTRYPOINT ["/opt/sentinel/docker-entrypoint.sh"]
CMD ["python3", "-m", "client"]
