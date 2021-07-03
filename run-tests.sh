#!/bin/sh
## Run pytest for pwncat. This script will start up the needed
## containers locally and then kick off pytest, pointing at the
## containers.

echo "[!] we can only test centos and ubuntu locally"

CENTOS_CONTAINER=$(podman run --rm -d -p :22 -p :4444 -p :9999 -t calebjstewart/pwncat-testing:centos)
echo "[+] started centos container: $CENTOS_CONTAINER"
UBUNTU_CONTAINER=$(podman run --rm -d -p :22 -p :4444 -p :9999 -t calebjstewart/pwncat-testing:ubuntu)
echo "[+] started centos container: $UBUNTU_CONTAINER"

CENTOS_BIND_PORT=$(podman inspect "$CENTOS_CONTAINER" | jq -r '.[0].HostConfig.PortBindings["4444/tcp"][0].HostPort')
UBUNTU_BIND_PORT=$(podman inspect "$UBUNTU_CONTAINER" | jq -r '.[0].HostConfig.PortBindings["4444/tcp"][0].HostPort')

echo "[+] centos bind port: $CENTOS_BIND_PORT"
echo "[+] ubuntu bind port: $UBUNTU_BIND_PORT"

CENTOS_HOST="127.0.0.1" CENTOS_BIND_PORT=$CENTOS_BIND_PORT UBUNTU_HOST="127.0.0.1" UBUNTU_BIND_PORT=$UBUNTU_BIND_PORT \
    pytest $@

podman container kill "$CENTOS_CONTAINER"""
echo "[+] killed centos container"
podman container kill "$UBUNTU_CONTAINER"
echo "[+] killed ubuntu container"
