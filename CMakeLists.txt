cmake_minimum_required(VERSION 3.10)
project(FluxWAN C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(include .)

add_definitions(-D_GNU_SOURCE -D_DEFAULT_SOURCE)

# Shared Core Library Sources (excluding main.c)
set(CORE_LIB_SOURCES 
    src/config.c 
    src/netlink_manager.c 
    src/bpf_loader.c 
    src/prober.c 
    src/wan_manager.c 
    src/pppoe_manager.c
    src/sticky.c 
    src/web_server.c
    src/net_discovery.c
    src/net_apply.c
    src/dhcp_server.c
    src/dns64_daemon.c
)

# Main fluxwan daemon
add_executable(fluxwan src/main.c ${CORE_LIB_SOURCES})

# Lab Simulator
add_executable(fluxwan_lab tests/lab_runner.c ${CORE_LIB_SOURCES})

# Test Executables
add_executable(test_wan_validator tests/test_wan_validator.c src/config.c)
add_executable(test_pppoe_manager tests/test_pppoe_manager.c src/pppoe_manager.c)
add_executable(test_live_nat46_translation tests/test_live_nat46_translation.c)
add_executable(test_xdp_packet tests/xdp_packet_test.c ${CORE_LIB_SOURCES})

# Compiler & Linker Settings
if(MSVC)
    target_compile_options(fluxwan PRIVATE /W4 /D_CRT_SECURE_NO_WARNINGS)
    target_link_libraries(fluxwan PRIVATE Ws2_32.lib Iphlpapi.lib)
    target_compile_options(fluxwan_lab PRIVATE /W4 /D_CRT_SECURE_NO_WARNINGS)
    target_link_libraries(fluxwan_lab PRIVATE Ws2_32.lib Iphlpapi.lib)
else()
    target_compile_options(fluxwan PRIVATE -O2 -Wall -Wextra -pthread)
    target_link_libraries(fluxwan PRIVATE pthread)
    target_compile_options(fluxwan_lab PRIVATE -O2 -Wall -Wextra -pthread -lm)
    target_link_libraries(fluxwan_lab PRIVATE pthread m)
    target_link_libraries(test_wan_validator PRIVATE pthread)
    target_link_libraries(test_pppoe_manager PRIVATE pthread)
    target_link_libraries(test_live_nat46_translation PRIVATE pthread)
    target_link_libraries(test_xdp_packet PRIVATE pthread m)
endif()

enable_testing()
add_test(NAME WANValidator COMMAND test_wan_validator)
add_test(NAME PPPoEManager COMMAND test_pppoe_manager)
add_test(NAME NAT46Translation COMMAND test_live_nat46_translation)
add_test(NAME XDPPacketTest COMMAND test_xdp_packet)
add_test(NAME LabSimulation COMMAND fluxwan_lab)