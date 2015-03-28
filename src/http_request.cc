//
//  http_request.cc
//

#include <cstring>
#include <sstream>
#include <algorithm>
#include <memory>
#include <string>
#include <vector>
#include <map>

#include "http_common.h"
#include "http_constants.h"
#include "http_parser.h"
#include "http_request.h"


/* http_request */

http_request::http_request() : buffer_offset(0)
{
    reset();
}

http_request::~http_request()
{
}

void http_request::reset()
{
    http_parser::reset();
#if ZERO_BUFFERS
    // We need to be sure we don't leak information if we skip zeroing buffer
    if (buffer) {
        memset(buffer, 0, buffer_size);
    }
#endif
    buffer_offset = 0;
    parse_type = http_parse_none;
    request_method = http_header_string();
    request_uri = http_header_string();
    fragment = http_header_string();
    request_path = http_header_string();
    query_string = http_header_string();
    http_version = http_header_string();
    body_start = http_header_string();
    header_list.clear();
    header_map.clear();
    overflow = false;
}

void http_request::resize(size_t buffer_size)
{
    // TODO - handle bad_alloc exceptions
    buffer.resize(buffer_size);
}

http_header_string http_request::alloc_string(const http_header_string &str)
{
    if (bytes_writable() < str.length + 1) {
        overflow = true;
        return http_header_string(NULL, 0);
    }
    
    char *str_buf = buffer.data() + buffer_offset;
    memcpy((void*)str_buf, str.data, str.length);
    str_buf[str.length] = '\0';
    buffer_offset += str.length + 1;
    
    return http_header_string(str_buf, str.length);
}

bool http_request::set_header_field(http_header_string name, http_header_string value)
{
    auto hi = header_map.find(name);
    if (hi == header_map.end()) {
        
        if (bytes_writable() < name.length + value.length + 2) {
            overflow = true;
            return false;
        }
        
        char *name_buf = buffer.data() + buffer_offset;
        memcpy((void*)name_buf, name.data, name.length);
        name_buf[name.length] = '\0';
        buffer_offset += name.length + 1;
        
        char *value_buf = buffer.data() + buffer_offset;
        memcpy((void*)value_buf, value.data, value.length);
        value_buf[value.length] = '\0';
        buffer_offset += value.length + 1;
        
        http_header_name_value nameval(http_header_string(name_buf, name.length), http_header_string(value_buf, value.length));
        header_list.push_back(nameval);
        header_map.insert(nameval);
        
    } else {
        const http_header_string &orig_value =(*hi).second;
        
        size_t value_length = orig_value.length + value.length + 2;
        if (bytes_writable() < value_length + 1) {
            overflow = true;
            return false;
        }
        
        // multiple sets to the same header cause a comma separated list (RFC2616)
        char *value_buf = buffer.data() + buffer_offset;
        memcpy((void*)value_buf, orig_value.data, orig_value.length);
        memcpy((void*)(value_buf + orig_value.length), ", ", 2);
        memcpy((void*)(value_buf + orig_value.length + 2), value.data, value.length);
        value_buf[value_length] = '\0';
        buffer_offset += value_length + 1;
        
        auto li = std::find(header_list.begin(), header_list.end(), http_header_name_value((*hi).first, (*hi).second));
        (*li).second = (*hi).second = http_header_string(value_buf, value_length);
    }
    return true;
}

const char* http_request::get_header_string(const char* name) const
{
    auto hi = header_map.find(http_header_string(name, strlen(name)));
    return (hi == header_map.end()) ? nullptr : (*hi).second.data;
}

void http_request::set_parse_type(http_parse_type t) { parse_type = t; }
void http_request::set_request_method(http_header_string str) { request_method = alloc_string(str); }
void http_request::set_request_uri(http_header_string str) { request_uri = alloc_string(str); }
void http_request::set_fragment(http_header_string str) { fragment = alloc_string(str); }
void http_request::set_request_path(http_header_string str) { request_path = alloc_string(str); }
void http_request::set_query_string(http_header_string str) { query_string = alloc_string(str); }
void http_request::set_body_start(http_header_string str) { body_start = str; }
void http_request::set_http_version(http_header_string str) { http_version = alloc_string(str); }
void http_request::set_reason_phrase(http_header_string str) {}
void http_request::set_status_code(int code) {}

bool http_request::has_error()
{
    return (http_parser::has_error() || has_overflow() || (http_parser::is_finished() && parse_type != http_parse_request));
}

bool http_request::has_overflow()
{
    return overflow;
}

std::string http_request::to_string() const
{
    std::stringstream ss;
    if (request_method.data && request_uri.data) {
        ss << get_request_method() << " " << get_request_uri();
    }
    if (query_string.data) {
        ss << "?" << get_query_string();
    }
    if (fragment.data) {
        ss << "#" << get_fragment();
    }
    if (http_version.data) {
        ss << " " << get_http_version();
    }
    ss << "\r\n";
    for (auto h : header_list) {
        ss << std::string(h.first.data, h.first.length) << ": " << std::string(h.second.data, h.second.length)  << "\r\n";
    }
    ss << "\r\n";
    return ss.str();
}

ssize_t http_request::to_buffer(char* buffer, size_t buffer_size) const
{
    size_t length = 0;
    
    if (!(request_method.data && request_uri.data && http_version.data)) {
        return -1;
    }

    if (request_method.length + request_uri.length +
       (query_string.data ? query_string.length + 1 : 0) +
       http_version.length + 4 < buffer_size - length)
    {
        memcpy(buffer, request_method.data, request_method.length);
        buffer += request_method.length;
        *buffer++ = ' ';
        memcpy(buffer, request_uri.data, request_uri.length);
        buffer += request_uri.length;
        if (query_string.data) {
            *buffer++ = '?';
            memcpy(buffer, query_string.data, query_string.length);
            buffer += query_string.length;
        }
        *buffer++ = ' ';
        memcpy(buffer, http_version.data, http_version.length);
        buffer += http_version.length;
        *buffer++ = '\r';
        *buffer++ = '\n';
        length += request_method.length + request_uri.length + (query_string.data ? query_string.length + 1 : 0) + http_version.length + 4;
    } else {
        return -1;
    }
    
    for (auto nameval : header_list) {
        if (nameval.first.length + nameval.second.length + 4 < buffer_size - length) {
            memcpy(buffer, nameval.first.data, nameval.first.length);
            buffer += nameval.first.length;
            *buffer++ = ':';
            *buffer++ = ' ';
            memcpy(buffer, nameval.second.data, nameval.second.length);
            buffer += nameval.second.length;
            *buffer++ = '\r';
            *buffer++ = '\n';
            length += nameval.first.length + nameval.second.length + 4;
        } else {
            return -1;
        }
    }
    
    if (2 < buffer_size - length) {
        *buffer++ = '\r';
        *buffer++ = '\n';
        length += 2;
    } else {
        return -1;
    }
    
    return length;
}
