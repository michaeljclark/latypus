//
//  http_client_handler_file.cc
//

#include "plat_os.h"
#include "plat_net.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cerrno>
#include <csignal>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <functional>
#include <deque>
#include <map>
#include <atomic>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>

#include "io.h"
#include "url.h"
#include "log.h"
#include "socket.h"
#include "resolver.h"
#include "config_parser.h"
#include "config.h"
#include "pollset.h"
#include "protocol.h"
#include "connection.h"
#include "connection_tcp.h"
#include "protocol_thread.h"
#include "protocol_engine.h"
#include "protocol_connection.h"

#include "http_common.h"
#include "http_constants.h"
#include "http_parser.h"
#include "http_request.h"
#include "http_response.h"
#include "http_date.h"
#include "http_client.h"
#include "http_client_handler_file.h"


/* http_client_handler_file */

http_client_handler_file::http_client_handler_file() : file_resource(-1) {}

http_client_handler_file::http_client_handler_file(int fd) : file_resource(fd) {}

http_client_handler_file::~http_client_handler_file() {}

void http_client_handler_file::init()
{
    http_version = HTTPVersion11;
    status_code = HTTPStatusCodeNone;
    request_method = HTTPMethodNone;
    content_length = -1;
    total_read = 0;
}

bool http_client_handler_file::populate_request()
{
    // get request http version and request method
    http_version = http_constants::get_version_type(http_conn->request.get_http_version());
    request_method = http_constants::get_method_type(http_conn->request.get_request_method());
    
    // set request/response body
    switch (request_method) {
        case HTTPMethodPOST:
            http_conn->request_has_body = true;
            http_conn->response_has_body = true;
            break;
        case HTTPMethodHEAD:
            http_conn->request_has_body = false;
            http_conn->response_has_body = false;
            break;
        case HTTPMethodGET:
        default:
            http_conn->request_has_body = false;
            http_conn->response_has_body = true;
            break;
    }
    
    // TODO - add any additional request headers
    
    return true;
}

io_result http_client_handler_file::write_request_body()
{
    return io_result(0);
}

bool http_client_handler_file::handle_response()
{
    // set connection close
    http_version = http_constants::get_version_type(http_conn->response.get_http_version());
    status_code =(HTTPStatusCode)http_conn->response.get_status_code();
    const char* connection_str = http_conn->response.get_header_string(kHTTPHeaderConnection);
    bool connection_keepalive_present = (connection_str && strcasecmp(connection_str, kHTTPTokenKeepalive) == 0);
    bool connection_close_present = (connection_str && strcasecmp(connection_str, kHTTPTokenClose) == 0);
    switch (http_version) {
        case HTTPVersion10:
            http_conn->connection_close = !connection_keepalive_present;
            break;
        case HTTPVersion11:
            http_conn->connection_close = connection_close_present;
            break;
        default:
            http_conn->connection_close = true;
            break;
    }
    
    // get content length
    const char* content_length_str = http_conn->response.get_header_string(kHTTPHeaderContentLength);
    content_length = content_length_str ? strtoll(content_length_str, NULL, 10) : -1;
    total_read = 0;
    
    return true;
}

io_result http_client_handler_file::read_response_body()
{
    auto &buffer = http_conn->buffer;
    
    // handle body fragment in the buffer
    if (buffer.bytes_readable() > 0) {
        ssize_t bytes_readable = buffer.bytes_readable();
        if (file_resource.get_fd() >= 0) {
            io_result result = buffer.buffer_write(file_resource);
            if (result.has_error()) {
                log_error("http_client_handler_file: write: %s", strerror(result.error().errcode));
            } else if (result.size() != bytes_readable) {
                log_error("http_client_handler_file: short_write");
            }
        }
        total_read += bytes_readable;
        buffer.reset();
    }
    
    if (total_read == content_length) return io_result(0);
    
    // read data from socket
    // TODO - move buffer_read into http_client::handle_state_server_body
    io_result result = buffer.buffer_read(http_conn->conn);
    if (result.has_error()) {
        return io_result(io_error(errno));
    } else if (buffer.bytes_readable() > 0) {
        ssize_t bytes_readable = buffer.bytes_readable();
        if (file_resource.get_fd() >= 0) {
            io_result result = buffer.buffer_write(file_resource);
            if (result.has_error()) {
                log_error("http_client_handler_file: write: %s", strerror(result.error().errcode));
            } else if (result.size() != bytes_readable) {
                log_error("http_client_handler_file: short_write");
            }
        }
        total_read += bytes_readable;
        buffer.reset();
    }
    
    // return bytes available or -1 if content length not present
    if (content_length >= 0) {
        return io_result(content_length - total_read);
    } else {
        return io_result(-1);
    }
}

bool http_client_handler_file::end_request()
{
    return true;
}
