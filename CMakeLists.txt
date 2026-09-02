cmake_minimum_required(VERSION 3.10)
project(FluxWAN C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(include)

file(GLOB SOURCES 
    src/main.c 
    src/config.c 
    src/netlink_manager.c 
    src/bpf_loader.c 
    src/prober.c 
    src/wan_manager.c 
    src/sticky.c 
    src/web_server.c
    src/net_discovery.c
    src/net_apply.c
    src/dhcp_server.c
)

add_executable(fluxwan ${SOURCES})

# Lab & Benchmark executable
set(LAB_SOURCES
    tests/lab_runner.c
    src/config.c
    src/netlink_manager.c
    src/bpf_loader.c
    src/prober.c
    src/wan_manager.c
    src/sticky.c
    src/net_discovery.c
    src/net_apply.c
    src/dhcp_server.c
)

add_executable(fluxwan_lab ${LAB_SOURCES})

# Target compiler flags
if(MSVC)
    target_compile_options(fluxwan PRIVATE /W4 /D_CRT_SECURE_NO_WARNINGS)
    target_link_libraries(fluxwan PRIVATE Ws2_32.lib Iphlpapi.lib)
    target_compile_options(fluxwan_lab PRIVATE /W4 /D_CRT_SECURE_NO_WARNINGS)
    target_link_libraries(fluxwan_lab PRIVATE Ws2_32.lib Iphlpapi.lib)
else()
    target_compile_options(fluxwan PRIVATE -Wall -Wextra -pthread)
    target_link_libraries(fluxwan PRIVATE pthread)
    target_compile_options(fluxwan_lab PRIVATE -Wall -Wextra -pthread -lm)
    target_link_libraries(fluxwan_lab PRIVATE pthread m)
endif()
