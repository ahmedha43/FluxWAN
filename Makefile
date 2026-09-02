TARGET ?= fluxwan
CC ?= gcc
CLANG ?= clang
CFLAGS ?= -O2 -Wall -Wextra -std=c11 -Iinclude -D_GNU_SOURCE -D_DEFAULT_SOURCE
LDFLAGS ?= -pthread

BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -target bpf -D__TARGET_ARCH_x86 -Iinclude -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu

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
BPF_OBJS = bpf/xdp_router.bpf.o bpf/xdp_nat46.bpf.o

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

# Test executables
TEST_WAN = test_wan_validator
TEST_PPPOE = test_pppoe_manager
TEST_NAT46 = test_live_nat46_translation
TEST_XDP = test_xdp_packet

all: ui bpf $(TARGET) $(LAB_TARGET)

ui:
	@py scripts/embed_ui.py || python3 scripts/embed_ui.py

bpf: $(BPF_OBJS)

bpf/%.bpf.o: bpf/%.bpf.c
	@mkdir -p bpf
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	test -s $@

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(LAB_TARGET): $(LAB_OBJS)
	$(CC) $(LAB_OBJS) -o $@ $(LDFLAGS) -lm

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Unit & Functional Tests
$(TEST_WAN): tests/test_wan_validator.c src/config.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_PPPOE): tests/test_pppoe_manager.c src/pppoe_manager.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_NAT46): tests/test_live_nat46_translation.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_XDP): tests/xdp_packet_test.c src/config.c src/wan_manager.c src/netlink_manager.c src/bpf_loader.c src/prober.c src/sticky.c src/net_discovery.c src/pppoe_manager.c src/dhcp_server.c src/net_apply.c src/dns64_daemon.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -lm

test: $(TEST_WAN) $(TEST_PPPOE) $(TEST_NAT46) $(TEST_XDP) $(LAB_TARGET)
	@echo "================================================================"
	@echo "   Running FluxWAN Automated Test Suites                        "
	@echo "================================================================"
	./$(TEST_WAN)
	@echo ""
	./$(TEST_PPPOE)
	@echo ""
	./$(TEST_NAT46)
	@echo ""
	./$(TEST_XDP)
	@echo ""
	./$(LAB_TARGET)
	@echo ""
	@echo "================================================================"
	@echo "   [✓] ALL TESTS COMPLETED SUCCESSFULLY!                        "
	@echo "================================================================"

clean:
	rm -f $(OBJS) $(LAB_OBJS) $(TARGET) $(LAB_TARGET) $(TEST_WAN) $(TEST_PPPOE) $(TEST_NAT46) $(TEST_XDP) bpf/*.o include/ui_assets.h

real-lab: $(TARGET)
	@echo "Running Real Linux Network Lab (requires root)..."
	sudo bash tests/lab/run_real_network_lab.sh

asan: CFLAGS += -fsanitize=address,undefined -g
asan: LDFLAGS += -fsanitize=address,undefined
asan: clean all

valgrind: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(TARGET) config/fluxwan.json

appliance:
	./build.sh all

rb5009:
	bash targets/rb5009/build.sh

.PHONY: all ui bpf clean lab real-lab asan valgrind test appliance rb5009