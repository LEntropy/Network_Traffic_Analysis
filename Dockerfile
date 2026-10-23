# Build stage: compiles the agent and runs the unit tests.
FROM ubuntu:24.04 AS build
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build libpcap-dev libgtest-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /build \
 && ctest --test-dir /build --output-on-failure

# Runtime stage: just the binary and libpcap.
FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libpcap0.8t64 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/netaudit-agent /usr/local/bin/netaudit-agent
ENTRYPOINT ["netaudit-agent"]
