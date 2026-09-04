# Dockerfile for building FluxWAN Embedded Network Appliance
FROM alpine:3.19

RUN apk update && apk add --no-cache \
    bash \
    build-base \
    gcc \
    musl-dev \
    make \
    clang \
    llvm \
    libbpf-dev \
    linux-headers \
    python3 \
    xorriso \
    syslinux \
    mtools \
    grub-bios \
    grub-efi \
    grub \
    squashfs-tools \
    wget \
    tar \
    gzip \
    dosfstools \
    e2fsprogs \
    parted \
    qemu-img \
    qemu-system-x86_64 \
    dialog \
    newt \
    ca-certificates \
    iproute2 \
    iptables \
    conntrack-tools \
    ethtool \
    util-linux

WORKDIR /workspace

CMD ["bash", "scripts/build_appliance.sh"]
