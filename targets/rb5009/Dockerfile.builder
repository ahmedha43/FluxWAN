# Dockerfile for Cross-Compiling & Emulating FluxWAN for MikroTik RB5009 (ARM64 - Marvell Armada 7040)
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu \
    libc6-dev-arm64-cross \
    clang \
    llvm \
    libbpf-dev \
    libelf-dev \
    u-boot-tools \
    device-tree-compiler \
    mtd-utils \
    squashfs-tools \
    cpio \
    gzip \
    bc \
    bison \
    flex \
    libssl-dev \
    wget \
    tar \
    curl \
    ca-certificates \
    git \
    python3 \
    qemu-system-arm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

CMD ["bash", "targets/rb5009/build.sh"]