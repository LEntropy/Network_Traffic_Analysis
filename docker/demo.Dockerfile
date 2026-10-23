# Interactive demo: the agent, an HTTP test server and the web test client in one
# container. Build from the repository root:
#   docker build -t netaudit-demo -f docker/demo.Dockerfile .
FROM ubuntu:24.04 AS build
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build libpcap-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt .
COPY include include
COPY src src
RUN cmake -S . -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release -DNETAUDIT_BUILD_TESTS=OFF \
 && cmake --build /build

FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      libpcap0.8t64 python3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/netaudit-agent /usr/local/bin/netaudit-agent
COPY demo /demo
RUN sed -i 's/\r$//' /demo/entrypoint.sh && chmod +x /demo/entrypoint.sh
EXPOSE 8000
ENTRYPOINT ["/demo/entrypoint.sh"]
