# AegisRecon container image
#
# Uses a slim Debian base for maximum compatibility and a small footprint,
# matching the supported distribution family (Debian/Ubuntu/Kali/Parrot).
# ProjectDiscovery binaries (httpx/subfinder/naabu) can be layered in via the
# `go install` steps if active probing is needed.

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    AEGISRECON_DATA_DIR=/var/lib/aegisrecon

WORKDIR /opt/aegisrecon

# Runtime dependencies for DNS + subprocess tooling
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        dnsutils curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install the package
COPY pyproject.toml README.md LICENSE ./
COPY aegisrecon ./aegisrecon
RUN pip install .

# Runtime state volume
VOLUME ["/var/lib/aegisrecon"]
ENV PATH="/opt/aegisrecon/.venv/bin:$PATH"

# Default entrypoint
ENTRYPOINT ["aegisrecon"]
CMD ["--help"]