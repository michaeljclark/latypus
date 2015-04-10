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
    src/cmdline_options.h
    src/cmdline_options.cc
    src/config.h
    src/config.cc
    src/config_cpu.h
    src/config_cpu.cc
    src/config_parser.h
    src/config_parser.cc
    src/connection.h
    src/connection.cc
    src/http_client.h
    src/http_client.cc
    src/http_client_handler_file.h
    src/http_client_handler_file.cc
    src/http_common.h
    src/http_common.cc
    src/http_constants.h
    src/http_constants.cc
    src/http_date.h
    src/http_date.cc
    src/http_parser.h
    src/http_parser.cc
    src/http_request.h
    src/http_request.cc
    src/http_response.h
    src/http_response.cc
    src/http_server.h
    src/http_server.cc
    src/http_server_handler_file.h
    src/http_server_handler_file.cc
    src/http_server_handler_func.h
    src/http_server_handler_func.cc
    src/http_server_handler_stats.h
    src/http_server_handler_stats.cc
    src/http_tls_shared.h
    src/http_tls_shared.cc
    src/io.h
    src/io.cc
    src/log.h
    src/log.cc
    src/log_thread.h
    src/log_thread.cc
    src/netdev.h
    src/netdev.cc
    src/pollset.h
    src/pollset.cc
    src/pollset_epoll.h
    src/pollset_epoll.cc
    src/pollset_kqueue.h
    src/pollset_kqueue.cc
    src/pollset_poll.h
    src/pollset_poll.cc
    src/protocol.h
    src/protocol.cc
    src/protocol_connection.h
    src/protocol_engine.h
    src/protocol_engine.cc
    src/protocol_thread.h
    src/protocol_thread.cc
    src/queue_atomic.h
    src/resolver.h
    src/resolver.cc
    src/socket.h
    src/socket.cc
    src/socket_tcp.h
    src/socket_tcp.cc
    src/socket_tls.h
    src/socket_tls.cc
    src/socket_udp.h
    src/socket_udp.cc
    src/socket_unix.h
    src/socket_unix.cc
    src/url.h
    src/url.cc
    src/trie.h
    src/os.h
    src/os.cc
)

find_program(RAGEL NAMES ragel PATHS /usr/bin /usr/local/bin)

add_custom_command(
DEPENDS ${PROJECT_SOURCE_DIR}/src/http_date.rl
OUTPUT ${PROJECT_SOURCE_DIR}/src/http_date.cc
COMMAND ${RAGEL} -o ${PROJECT_SOURCE_DIR}/src/http_date.cc ${PROJECT_SOURCE_DIR}/src/http_date.rl
)

add_custom_command(
DEPENDS ${PROJECT_SOURCE_DIR}/src/config_parser.rl
OUTPUT ${PROJECT_SOURCE_DIR}/src/config_parser.cc
COMMAND ${RAGEL} -o ${PROJECT_SOURCE_DIR}/src/config_parser.cc ${PROJECT_SOURCE_DIR}/src/config_parser.rl
)

add_custom_command(
DEPENDS ${PROJECT_SOURCE_DIR}/src/http_parser.rl
OUTPUT ${PROJECT_SOURCE_DIR}/src/http_parser.cc
COMMAND ${RAGEL} -o ${PROJECT_SOURCE_DIR}/src/http_parser.cc ${PROJECT_SOURCE_DIR}/src/http_parser.rl
)

add_custom_command(
DEPENDS ${PROJECT_SOURCE_DIR}/src/db_sql_parser.rl
OUTPUT ${PROJECT_SOURCE_DIR}/src/db_sql_parser.cc
COMMAND ${RAGEL} -o ${PROJECT_SOURCE_DIR}/src/db_sql_parser.cc ${PROJECT_SOURCE_DIR}/src/db_sql_parser.rl
)

add_executable(neta app/neta.cc)
target_link_libraries(neta latypus pthread ssl crypto)

add_executable(netb app/netb.cc)
target_link_libraries(netb latypus pthread ssl crypto)

add_executable(netc app/netc.cc)
target_link_libraries(netc latypus pthread ssl crypto)

add_executable(netd app/netd.cc)
target_link_libraries(netd latypus pthread ssl crypto)

add_executable(openssl_async_echo_client tests/openssl_async_echo_client.cc)
target_link_libraries(openssl_async_echo_client ssl crypto)

add_executable(openssl_async_echo_server tests/openssl_async_echo_server.cc)
target_link_libraries(openssl_async_echo_server ssl crypto)

add_executable(test_config tests/test_config.cc)
target_link_libraries(test_config latypus pthread cppunit ssl crypto)

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
