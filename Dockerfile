FROM python:3.9-alpine as builder

# Install python3 and development files
RUN set -eux \
	&& apk add --no-cache \
		alpine-sdk \
		libffi-dev \
		linux-headers \
		openssl-dev \
		musl-dev \
		cargo \
		libstdc++

# Copy pwncat source
COPY . /opt/pwncat

# Setup virtual environment
RUN set -eux \
	&& python -m pip install -U pip setuptools wheel setuptools_rust

# Setup pwncat
RUN set -eux \
	&& cd /opt/pwncat \
	&& python setup.py install

FROM python:3.9-alpine as final

# Add libstdc++ and create the working directory
RUN set -eux \
	&& apk add --no-cache libstdc++ \
	&& mkdir /work

# Copy installed packages from builder image
COPY --from=builder /usr/local/lib/python3.9 /usr/local/lib/python3.9
COPY --from=builder /usr/local/bin/pwncat /usr/local/bin/pwncat

# Ensure we have the pwncat plugins downloaded
RUN python -m pwncat --download-plugins

# Set working directory
WORKDIR /work

# Entrypoint is pwncat itself
ENTRYPOINT ["python", "-m", "pwncat"]
