# Development image: toolchain only. The source tree is mounted at /src.
FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build libpcap-dev libgtest-dev python3 tcpdump \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
