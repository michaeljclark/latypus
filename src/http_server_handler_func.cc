//
//  http_server_handler_func.cc
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
#include "http_server.h"
#include "http_server_handler_func.h"


/* http_server_handler_func */

http_server_handler_func::http_server_handler_func()
{
    response_buffer.resize(1024);
}

http_server_handler_func::~http_server_handler_func()
{
}

void http_server_handler_func::init()
{
    reader = nullptr;
    response_buffer.reset();
    extension.clear();
    mime_type.clear();
    status_text.clear();
    status_code = 0;
    content_length = 0;
    total_written = 0;
}

bool http_server_handler_func::handle_request()
{
    // get request http version and request method
    http_version = http_constants::get_version_type(http_conn->request.get_http_version());
    request_method = http_constants::get_method_type(http_conn->request.get_request_method());
    
    switch (request_method) {
        case HTTPMethodGET:
        case HTTPMethodHEAD:
            status_code = HTTPStatusCodeOK;
            break;
        default:
            status_code = HTTPStatusCodeMethodNotAllowed;
            break;
    }
    
    // create response
    status_text = http_constants::get_status_text(status_code);
    mime_type = "text/plain";
    const char* str = "Hello World\n";
    size_t len = strlen(str);
    response_buffer.set(str, len);
    content_length = len;
    reader = &response_buffer;
    
    if (delegate->get_debug_mask() & protocol_debug_handler) {
        log_debug("handle_request: status_code=%d status_text=%s "
                  "extension=%s mime_type=%s",
                  status_code, status_text.c_str(),
                  extension.c_str(), mime_type.c_str());
    }
    
    return true;
}

io_result http_server_handler_func::read_request_body()
{
    return io_result(0);
}

bool http_server_handler_func::populate_response()
{
    char date_buf[32];
    
    // set request body presence
    switch (request_method) {
        case HTTPMethodGET:
            http_conn->response_has_body = (status_code != HTTPStatusCodeNotModified);
            break;
        case HTTPMethodHEAD:
            http_conn->response_has_body = false;
            break;
        default:
            http_conn->response_has_body = true;
            break;
    }
    
    // set connection close
    const char* connection_str = http_conn->request.get_header_string(kHTTPHeaderConnection);
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
    
    // TODO - PUT/POST request has body
    http_conn->request_has_body = false;
    
    // set response headers
    http_conn->response.set_status_code(status_code);
    http_conn->response.set_reason_phrase(status_text);
    if (status_code != HTTPStatusCodeNotModified) {
        http_conn->response.set_header_field(kHTTPHeaderContentType, mime_type);
        http_conn->response.set_header_field(kHTTPHeaderContentLength, format_string("%lu", content_length));
    }
    if (status_code == HTTPStatusCodeOK || status_code == HTTPStatusCodeNotModified) {
        http_conn->response.set_header_field(kHTTPHeaderLastModified, last_modified.to_header_string(date_buf, sizeof(date_buf)));
    }
    switch (http_version) {
        case HTTPVersion10:
            if (connection_keepalive_present) {
                http_conn->response.set_header_field(kHTTPHeaderConnection, kHTTPTokenKeepalive);
            }
            break;
        case HTTPVersion11:
            http_conn->response.set_header_field(kHTTPHeaderConnection, http_conn->connection_close ? kHTTPTokenClose : kHTTPTokenKeepalive);
            break;
        default:
            http_conn->connection_close = true;
            break;
    }
    //http_conn->response.set_header_field(kHTTPHeaderAcceptRanges, "bytes");
    
    return true;
}

io_result http_server_handler_func::write_response_body()
{    
    auto &buffer = http_conn->buffer;
    
    // refill buffer
    if (reader && buffer.bytes_readable() == 0) {
        buffer.reset();
        io_result res = buffer.buffer_read(*reader);
        if (res.has_error()) return res;
    }
    
    // write buffer to socket
    // TODO - move buffer_write into http_server::handle_state_server_body
    if (buffer.bytes_readable() > 0) {
        io_result result = buffer.buffer_write(http_conn->conn);
        if (result.has_error()) {
            return result;
        }
        total_written += result.size();
    }
    
    // return bytes available
    return io_result(content_length - total_written);
}

bool http_server_handler_func::end_request()
{
    return true;
}
