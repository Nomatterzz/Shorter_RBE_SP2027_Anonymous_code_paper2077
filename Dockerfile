FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build libssl-dev libboost-dev python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /artifact
COPY . .
RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build -j2
RUN useradd --create-home artifact && chown -R artifact:artifact /artifact
USER artifact
CMD ["python3", "scripts/reproduce.py", "--binary-dir", "build", "--out-dir", "results/local"]
