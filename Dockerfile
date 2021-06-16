FROM alpine:latest as builder

# Install python3 and development files
RUN set -eux \
	&& apk add --no-cache \
		alpine-sdk \
		libffi-dev \
		linux-headers \
		openssl-dev \
		python3 \
		python3-dev \
		musl-dev \
		cargo

# Install pip
RUN set -eux \
	&& python3 -m ensurepip

# Copy pwncat source
COPY . /pwncat

# Setup virtual environment
RUN set -eux \
	&& python3 -m venv /opt/pwncat \
	&& /opt/pwncat/bin/python3 -m pip install -U pip setuptools wheel setuptools_rust

# Setup pwncat
RUN set -eux \
	&& cd /pwncat \
	&& /opt/pwncat/bin/python setup.py install

# Cleanup
RUN set -eux \
	&& find /opt/pwncat/lib -type f -name '*.pyc' -print0 | xargs -0 -n1 rm -rf || true \
	&& find /opt/pwncat/lib -type d -name '__pycache__' -print0 | xargs -0 -n1 rm -rf || true


FROM alpine:latest as final

RUN set -eux \
	&& apk add --no-cache \
		python3 libstdc++ \
	&& find /usr/lib -type f -name '*.pyc' -print0 | xargs -0 -n1 rm -rf || true \
	&& find /usr/lib -type d -name '__pycache__' -print0 | xargs -0 -n1 rm -rf || true \
	&& mkdir /work

COPY --from=builder /opt/pwncat /opt/pwncat

RUN /opt/pwncat/bin/python -m pwncat --download-plugins

# Set working directory
WORKDIR /work
ENTRYPOINT ["/opt/pwncat/bin/pwncat"]
