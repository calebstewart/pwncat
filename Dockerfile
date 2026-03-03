FROM python:3.9-slim AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libssl-dev \
    cargo \
    && rm -rf /var/lib/apt/lists/*

COPY . /opt/pwncat

RUN python -m pip install -U pip setuptools wheel setuptools_rust
RUN cd /opt/pwncat && pip install .


FROM python:3.9-slim AS final

# Install runtime deps only
RUN apt-get update && apt-get install -y \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Copy entire python installation (safe because base image is identical)
COPY --from=builder /usr/local /usr/local

RUN pwncat-cs --download-plugins

WORKDIR /work
ENTRYPOINT ["pwncat-cs"]
