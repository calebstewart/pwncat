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

# Ensure pip is up to date
RUN set -eux \
	&& python3 -m pip install -U pip setuptools wheel setuptools_rust

# Copy pwncat source
COPY . /pwncat

# Setup pwncat
RUN set -eux \
	&& cd /pwncat \
	&& python3 setup.py install

# Cleanup
RUN set -eux \
	&& find /usr/lib -type f -name '*.pyc' -print0 | xargs -0 -n1 rm -rf || true \
	&& find /usr/lib -type d -name '__pycache__' -print0 | xargs -0 -n1 rm -rf || true


FROM alpine:latest as final

RUN set -eux \
	&& apk add --no-cache \
		python3 libstdc++ \
	&& find /usr/lib -type f -name '*.pyc' -print0 | xargs -0 -n1 rm -rf || true \
	&& find /usr/lib -type d -name '__pycache__' -print0 | xargs -0 -n1 rm -rf || true \
	&& mkdir /work

COPY --from=builder /usr/bin/pwncat /usr/bin/pwncat
COPY --from=builder /usr/lib/python3.8 /usr/lib/python3.8

RUN python3 -m pwncat --download-plugins

# Set working directory
WORKDIR /work
ENTRYPOINT ["/usr/bin/pwncat"]
