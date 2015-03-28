/*
 * derived from mongrel/http11_parser.h
 *
 * Copyright (c) 2005 Zed A. Shaw
 * You can redistribute it and/or modify it under the same terms as Ruby.
 */

#ifndef http_parser_h
#define http_parser_h

enum http_parse_type {
    http_parse_none,
    http_parse_request,
    http_parse_response,
};

struct http_parser
{
    int cs;
    size_t nread;
    const char *mark;
    const char *query_start;
    const char *field_start;
    size_t field_len;
    
    http_parser();
    virtual ~http_parser();

    virtual void reset();
    virtual size_t parse(const char *buf, size_t len);
    virtual bool has_error();
    virtual bool is_finished();
    virtual size_t bytes_read();

    virtual void set_parse_type(http_parse_type t) = 0;    
    virtual bool set_header_field(http_header_string name, http_header_string value) = 0;
    virtual void set_request_method(http_header_string str) = 0;
    virtual void set_request_uri(http_header_string str) = 0;
    virtual void set_fragment(http_header_string str) = 0;
    virtual void set_request_path(http_header_string str) = 0;
    virtual void set_query_string(http_header_string str) = 0;
    virtual void set_body_start(http_header_string str) = 0;
    virtual void set_http_version(http_header_string str) = 0;
    virtual void set_reason_phrase(http_header_string str) = 0;
    virtual void set_status_code(int code) = 0;
};

#endif
