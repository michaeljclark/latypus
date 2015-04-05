//
//  http_server_handler_file.cc
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
#include <iomanip>
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
#include "log_thread.h"
#include "trie.h"
#include "socket.h"
#include "resolver.h"
#include "config_parser.h"
#include "config.h"
#include "pollset.h"
#include "protocol.h"
#include "connection.h"
#include "connection.h"
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
#include "http_server_handler_file.h"


/* http_server_handler_file */

http_server_handler_file::http_server_handler_file()
{
    error_buffer.resize(1024);
}

http_server_handler_file::~http_server_handler_file()
{
    file_resource.close();
}

void http_server_handler_file::init_handler()
{
    http_server::register_handler<http_server_handler_file>("http_server_handler_file");
}

void http_server_handler_file::translate_path()
{
    // TODO - valid root path exists in config
    // TODO - unescape path
    auto cfg = delegate->get_config();
    auto root = cfg->root;
    const char* request_path = http_conn->request.get_request_path();
    // TODO - handle canonical unescaping of path
    // TODO - windows LFN http://support.microsoft.com/kb/142982 GetShortPathName
    // TODO - windows forks using : or ::$DATA (alternate name for main fork)
    // TODO - case insensitive filesystems
    if (root.length() > 0 && root[root.length() - 1] != '/' && request_path[0] != '/') {
        translated_path = cfg->root + "/" + request_path;
    } else {
        translated_path = cfg->root + request_path;
    }
}

int http_server_handler_file::open_resource(int oflag, int mask)
{
    open_path = translated_path;
    
    stat_err = io_file::stat(translated_path, stat_result);
    
    if (stat_err.errcode == EACCES) {
        return HTTPStatusCodeForbidden;
    } else if (stat_err.errcode == ENOENT) {
        return HTTPStatusCodeNotFound;
    } else if (stat_err.errcode != 0) {
        return HTTPStatusCodeInternalServerError;
    } else if (stat_result.st_mode & S_IFDIR) {
        // TODO - redirect if trailing slash is missing
        // TODO - handle directory listings
        bool found_index = false;
        auto cfg = delegate->get_config();
        for (auto index : cfg->index_files) {
            std::string index_path;
            if (translated_path.length() > 0 && translated_path[translated_path.length() - 1] == '/') {
                index_path = translated_path + index;
            } else {
                index_path = translated_path + "/" + index;
            }
            if (io_file::stat(index_path, stat_result).errcode == 0) {
                open_path = index_path;
                found_index = true;
                break;
            }
        }
        if (!found_index) {
            return HTTPStatusCodeForbidden;
        }
    } else if (!(stat_result.st_mode & S_IFREG)) {
        return HTTPStatusCodeForbidden;
    }
    
    open_err = file_resource.open(open_path, oflag, mask);
    
    if (open_err.errcode == EACCES) {
        return HTTPStatusCodeForbidden;
    } else if (open_err.errcode == ENOENT) {
        return HTTPStatusCodeNotFound;
    } else if (open_err.errcode != 0) {
        return HTTPStatusCodeInternalServerError;
    } else {
        last_modified = http_date((time_t)stat_result.st_mtime);
        return HTTPStatusCodeOK;
    }
}

size_t http_server_handler_file::create_error_response()
{
    char error_fmt[] =
        "<html>\r\n"
        "<head><title>%d %s</title></head>\r\n"
        "<body>\r\n"
        "<h1>%d %s</h1>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    error_buffer.reset();
    size_t error_len = snprintf(error_buffer.data(), error_buffer.size(), error_fmt,
                                status_code, status_text.c_str(),
                                status_code, status_text.c_str());
    error_buffer.set_length(error_len);
    mime_type = "text/html";
    return error_len;
}

void http_server_handler_file::init()
{
    open_path.clear();
    translated_path.clear();
    reader = nullptr;
    file_resource.close();
    error_buffer.reset();
    mime_type.clear();
    status_text.clear();
    open_err = 0;
    stat_err = 0;
    status_code = 0;
    content_length = 0;
    total_written = 0;
    last_modified = http_date();
    if_modified_since = http_date();
}

bool http_server_handler_file::handle_request()
{
    // get request http version and request method
    http_version = http_constants::get_version_type(http_conn->request.get_http_version());
    request_method = http_constants::get_method_type(http_conn->request.get_request_method());
    
    translate_path();
    
    switch (request_method) {
        case HTTPMethodGET:
        case HTTPMethodHEAD:
            status_code = open_resource(O_RDONLY, 0);
            break;
        default:
            status_code = HTTPStatusCodeMethodNotAllowed;
            break;
    }
    
    const char* if_modified_since_str;
    if (status_code == HTTPStatusCodeOK &&
        (if_modified_since_str = http_conn->request.get_header_string(kHTTPHeaderIfModifiedSince)))
    {
        if_modified_since = http_date(if_modified_since_str);
        if (last_modified.tod <= if_modified_since.tod) {
            status_code = HTTPStatusCodeNotModified;
        }
    }
    
    status_text = http_constants::get_status_text(status_code);
    if (status_code == HTTPStatusCodeOK) {
        auto ext_mime_type = delegate->get_config()->lookup_mime_type(open_path);
        mime_type = ext_mime_type.second;
        content_length = stat_result.st_size;
        reader = &file_resource;
    } else if (status_code == HTTPStatusCodeNotModified) {
        content_length = 0;
        reader = nullptr;
    } else {
        content_length = create_error_response();
        reader = &error_buffer;
    }
    
    if (delegate->get_debug_mask() & protocol_debug_handler) {
        log_debug("handle_request: status_code=%d status_text=%s "
                  "open_path=%s translated_path=%s mime_type=%s",
                  status_code, status_text.c_str(), open_path.c_str(),
                  translated_path.c_str(), mime_type.c_str());
    }
    
    return true;
}

io_result http_server_handler_file::read_request_body()
{
    return io_result(0);
}

bool http_server_handler_file::populate_response()
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
    
    return true;
}

io_result http_server_handler_file::write_response_body()
{    
    auto &buffer = http_conn->buffer;
    
    // refill buffer
    if (reader && buffer.bytes_readable() == 0) {
        buffer.reset();
        io_result res = buffer.buffer_read(*reader);
        if (res.has_error()) return res;
    }
    
    // write buffer to socket
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

bool http_server_handler_file::end_request()
{
    file_resource.close();
    return true;
}
