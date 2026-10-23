cmake_minimum_required(VERSION 3.16)
project(netaudit-agent VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(NETAUDIT_BUILD_TESTS "Build unit tests" ON)
option(NETAUDIT_SANITIZE "Build with AddressSanitizer and UBSan" OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow)
if(NETAUDIT_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

# Protocol pipeline. Has no libpcap dependency so it can be unit-tested with synthetic
# packets and reused by other front ends.
add_library(netaudit_core
  src/net.cpp
  src/packet.cpp
  src/reassembly.cpp
  src/log.cpp
  src/dispatcher.cpp
  src/http_parser.cpp
)
target_include_directories(netaudit_core PUBLIC include)

find_path(PCAP_INCLUDE_DIR pcap/pcap.h REQUIRED)
find_library(PCAP_LIBRARY pcap REQUIRED)

add_executable(netaudit-agent src/main.cpp src/pcap_source.cpp)
target_include_directories(netaudit-agent PRIVATE ${PCAP_INCLUDE_DIR})
target_link_libraries(netaudit-agent PRIVATE netaudit_core ${PCAP_LIBRARY})

install(TARGETS netaudit-agent RUNTIME DESTINATION bin)

if(NETAUDIT_BUILD_TESTS)
  enable_testing()
  find_package(GTest REQUIRED)
  add_executable(netaudit_tests
    tests/test_packet.cpp
    tests/test_reassembly.cpp
    tests/test_http.cpp
    tests/test_log.cpp
  )
  target_link_libraries(netaudit_tests PRIVATE netaudit_core GTest::gtest_main)
  include(GoogleTest)
  gtest_discover_tests(netaudit_tests)
endif()
