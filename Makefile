TARGET ?= fluxwan
CC ?= gcc
CLANG ?= clang
CFLAGS ?= -O2 -Wall -Wextra -std=c11 -Iinclude -D_GNU_SOURCE
LDFLAGS ?= -pthread

BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -target bpf -Iinclude

SRCS = src/main.c \
       src/config.c \
       src/netlink_manager.c \
       src/bpf_loader.c \
       src/prober.c \
       src/wan_manager.c \
       src/pppoe_manager.c \
       src/sticky.c \
       src/web_server.c \
       src/net_discovery.c \
       src/net_apply.c \
       src/dhcp_server.c \
       src/dns64_daemon.c

OBJS = $(SRCS:.c=.o)
BPF_OBJ = bpf/xdp_router.bpf.o

LAB_SRCS = tests/lab_runner.c \
           src/config.c \
           src/netlink_manager.c \
           src/bpf_loader.c \
           src/prober.c \
           src/wan_manager.c \
           src/pppoe_manager.c \
           src/sticky.c \
           src/net_discovery.c \
           src/net_apply.c \
           src/dhcp_server.c \
           src/dns64_daemon.c

LAB_OBJS = $(LAB_SRCS:.c=.o)
LAB_TARGET = fluxwan_lab

all: ui bpf $(TARGET) $(LAB_TARGET)

ui:
	@py scripts/embed_ui.py || python3 scripts/embed_ui.py

bpf: $(BPF_OBJ)

$(BPF_OBJ): bpf/xdp_router.bpf.c
	@mkdir -p bpf
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@ || echo "BPF compilation skipped (clang bpf target required for kernel bytecode)"

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(LAB_TARGET): $(LAB_OBJS)
	$(CC) $(LAB_OBJS) -o $@ $(LDFLAGS) -lm

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(LAB_OBJS) $(TARGET) $(LAB_TARGET) bpf/*.o include/ui_assets.h

real-lab: $(TARGET)
	@echo "Running Real Linux Network Lab (requires root)..."
	sudo bash tests/lab/run_real_network_lab.sh

asan: CFLAGS += -fsanitize=address,undefined -g
asan: LDFLAGS += -fsanitize=address,undefined
asan: clean all

valgrind: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(TARGET) config/fluxwan.json

appliance: iso

fluxwan-os: iso

iso:
	@echo "Building FluxWAN Embedded Standalone Bootable ISO..."
	bash scripts/build_iso_embedded.sh

iso-docker:
	@echo "Building FluxWAN ISO using isolated Docker builder container..."
	docker build -f iso/Dockerfile.builder -t fluxwan-iso-builder .
	docker run --rm --privileged -v $$(pwd):/workspace fluxwan-iso-builder bash scripts/build_iso_embedded.sh

.PHONY: all ui bpf clean lab real-lab asan valgrind iso iso-docker appliance fluxwan-os
