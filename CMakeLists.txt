cmake_minimum_required(VERSION 2.8)

project(latypus)

if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -g")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -g -std=c++11")
elseif(MSVC)
    # Disable warnings for implicit integer narrowing.
    set(CMAKE_C_FLAGS "/wd4267")
    set(CMAKE_CXX_FLAGS "/wd4267")
endif()

include_directories(src)
include_directories(third_party/boringssl/include)
include_directories(third_party/cppunit/include)

add_subdirectory(third_party/boringssl)
add_subdirectory(third_party/cppunit)

if(LINUX)
    add_definitions (-D_FILE_OFFSET_BITS=64)
endif()

add_library(
    latypus STATIC
    src/os.cc
    src/io.cc
    src/pollset.cc
    src/pollset_epoll.cc
    src/pollset_kqueue.cc
    src/pollset_poll.cc
    src/connection_ssl.cc
    src/connection_tcp.cc
    src/resolver.cc
    src/netdev.cc
    src/socket.cc
    src/url.cc
    src/cmdline_options.cc
    src/config.cc
    src/config_parser.cc
    src/config_cpu.cc
    src/log.cc
    src/log_thread.cc
    src/http_common.cc
    src/http_constants.cc
    src/http_date.cc
    src/http_parser.cc
    src/http_request.cc
    src/http_response.cc
    src/http_client.cc
    src/http_client_handler_file.cc
    src/http_server.cc
    src/http_server_handler_file.cc
    src/http_server_handler_func.cc
    src/http_server_handler_stats.cc
    src/protocol.cc
    src/protocol_engine.cc
    src/protocol_thread.cc
)

add_executable(neta app/neta.cc)
target_link_libraries(neta latypus pthread)

add_executable(netb app/netb.cc)
target_link_libraries(netb latypus pthread)

add_executable(netc app/netc.cc)
target_link_libraries(netc latypus pthread)

add_executable(netd app/netd.cc)
target_link_libraries(netd latypus pthread)

add_executable(openssl_async_echo_client tests/openssl_async_echo_client.cc)
target_link_libraries(openssl_async_echo_client ssl crypto)

add_executable(openssl_async_echo_server tests/openssl_async_echo_server.cc)
target_link_libraries(openssl_async_echo_server ssl crypto)

add_executable(test_config tests/test_config.cc)
target_link_libraries(test_config latypus pthread cppunit)

add_executable(test_cpu tests/test_cpu.cc)
target_link_libraries(test_cpu latypus pthread cppunit)

add_executable(test_http_date tests/test_http_date.cc)
target_link_libraries(test_http_date latypus pthread cppunit)

add_executable(test_http_request tests/test_http_request.cc)
target_link_libraries(test_http_request latypus pthread cppunit)

add_executable(test_http_response tests/test_http_response.cc)
target_link_libraries(test_http_response latypus pthread cppunit)

add_executable(test_openssl tests/test_openssl.cc)
target_link_libraries(test_openssl latypus pthread cppunit ssl crypto)

add_executable(test_queue tests/test_queue.cc)
target_link_libraries(test_queue latypus pthread cppunit)

add_executable(test_resolver tests/test_resolver.cc)
target_link_libraries(test_resolver latypus pthread cppunit)

add_executable(test_trie tests/test_trie.cc)
target_link_libraries(test_trie latypus pthread cppunit)

add_executable(test_io tests/test_io.cc)
target_link_libraries(test_io latypus pthread cppunit)

add_executable(test_netdev tests/test_netdev.cc)
target_link_libraries(test_netdev latypus pthread cppunit)

add_executable(test_url tests/test_url.cc)
target_link_libraries(test_url latypus pthread cppunit)

add_executable(test_url_map tests/test_url_map.cc)
target_link_libraries(test_url_map latypus pthread cppunit)
