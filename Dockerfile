FROM debian:12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    python3 \
    qemu-system-x86 \
    mtools \
    bash \
    xorriso \
    squashfs-tools \
    syslinux \
    syslinux-common \
    isolinux \
    dosfstools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN python3 scripts/embed_ui.py
RUN make || gcc -O2 -Iinclude src/*.c -o fluxwan -lpthread

# Final Runtime Image
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iptables \
    conntrack \
    ethtool \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/fluxwan

COPY --from=builder /app/fluxwan /opt/fluxwan/fluxwan
COPY --from=builder /app/config /opt/fluxwan/config
COPY --from=builder /app/bpf /opt/fluxwan/bpf

EXPOSE 8080 67/udp

CMD ["/opt/fluxwan/fluxwan", "/opt/fluxwan/config/fluxwan.json"]
