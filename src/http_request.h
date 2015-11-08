//
//  http_request.h
//

#ifndef http_request_h
#define http_request_h

/* http_request */

struct http_request : http_parser
{    
    std::vector<char>   buffer;
    size_t              buffer_offset;
    size_t              max_headers;
    http_parse_type     parse_type;
    http_header_string  request_method;
    http_header_string  request_uri;
    http_header_string  fragment;
    http_header_string  request_path;
    http_header_string  query_string;
    http_header_string  body_start;
    http_header_string  http_version;
    http_header_list    header_list;
    http_header_map     header_map;
    bool                overflow;
    
    http_request();
    ~http_request();

    void reset();
    bool has_error();
    bool has_overflow();
    
    void resize(size_t header_buffer_size, size_t max_headers);
    size_t bytes_writable() { return buffer.capacity() - buffer_offset; }
    char* buffer_position() { return buffer.data() + buffer_offset; }

    http_header_string alloc_string(const http_header_string &str);

    void set_parse_type(http_parse_type t);
    bool set_header_field(http_header_string name, http_header_string value);
    void set_request_method(http_header_string str);
    void set_request_uri(http_header_string str);
    void set_fragment(http_header_string str);
    void set_request_path(http_header_string str);
    void set_query_string(http_header_string str);
    void set_body_start(http_header_string str);
    void set_http_version(http_header_string str);
    void set_status_code(int code);
    void set_reason_phrase(http_header_string str);

    const char* get_request_method() const    { return request_method.data; }
    const char* get_request_uri() const       { return request_uri.data; }
    const char* get_fragment() const          { return fragment.data; }
    const char* get_request_path() const      { return request_path.data; }
    const char* get_query_string() const      { return query_string.data; }
    const char* get_body_start() const        { return body_start.data; }
    const char* get_http_version() const      { return http_version.data; }
    const char* get_header_string(const char* name) const;
    
    std::string to_string() const;
    ssize_t to_buffer(char* buffer, size_t buffer_size) const;
};

#endif
