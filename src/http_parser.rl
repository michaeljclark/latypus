/*
 * derived from mongrel/http11_parser.rl
 *
 * Copyright (c) 2005 Zed A. Shaw
 * You can redistribute it and/or modify it under the same terms as Ruby.
 */

#include <cstring>
#include <sstream>
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <mutex>

#include "http_common.h"
#include "http_constants.h"
#include "http_parser.h"

%%{
    
    machine http_parser;

    action mark             { mark = fpc; }
    action start_field      { field_start = fpc; }
    action write_field      { field_len = fpc - field_start; }
    action start_value      { mark = fpc; }
    action start_query      { query_start = fpc; }
    action write_value      { set_header_field(http_header_string(field_start, field_len), http_header_string(mark, fpc - mark)); }
    action request_method   { set_request_method(http_header_string(mark, fpc - mark)); }
    action request_uri      { set_request_uri(http_header_string(mark, fpc - mark)); }
    action fragment         { set_fragment(http_header_string(mark, fpc - mark)); }
    action query_string     { set_query_string(http_header_string(query_start, fpc - query_start)); }
    action http_version     { set_http_version(http_header_string(mark, fpc - mark)); }
    action request_path     { set_request_path(http_header_string(mark, fpc - mark)); }
    action status_code      { set_status_code(atoi(std::string(mark, fpc - mark).c_str())); }
    action reason_phrase    { set_reason_phrase(http_header_string(mark, fpc - mark)); }
    action parse_response   { set_parse_type(http_parse_response); }
    action parse_request    { set_parse_type(http_parse_request); }
    action done             { set_body_start(http_header_string(fpc + 1, len - (fpc + 1 - buf))); fbreak; }

    #### HTTP PROTOCOL GRAMMAR
    
    # line endings
    CRLF = ("\r\n" | "\n");

    # character types
    CTL = (cntrl | 127);
    safe = ("$" | "-" | "_" | ".");
    extra = ("!" | "*" | "'" | "(" | ")" | ",");
    reserved = (";" | "/" | "?" | ":" | "@" | "&" | "=" | "+");
    sorta_safe = ("\"" | "<" | ">");
    unsafe = (CTL | " " | "#" | "%" | sorta_safe);
    national = any -- (alpha | digit | reserved | extra | safe | unsafe);
    unreserved = (alpha | digit | safe | extra | national);
    escape = ("%" xdigit xdigit);
    uchar = (unreserved | escape | sorta_safe);
    pchar = (uchar | ":" | "@" | "&" | "=" | "+");
    tspecials = ("(" | ")" | "<" | ">" | "@" | "," | ";" | ":" | "\\" | "\"" | "/" | "[" | "]" | "?" | "=" | "{" | "}" | " " | "\t");

    # URI schemes and absolute paths
    scheme = ( alpha | digit | "+" | "-" | "." )* ;
    absolute_uri = (scheme ":" (uchar | reserved )*);
    path = ( pchar+ ( "/" pchar* )* ) ;
    query = ( uchar | reserved )* %query_string ;
    rel_path = ( path? %request_path ) ("?" %start_query query)?;
    absolute_path = ( "/"+ rel_path );

    # Request/Response
    http_number = ( digit+ "." digit+ ) ;
    HTTP_Version = ( "HTTP/" http_number ) >mark %http_version;

    # Request
    Request_URI = ( "*" | absolute_uri | absolute_path ) >mark %request_uri;
    Fragment = ( uchar | reserved )* >mark %fragment;
    Method = ( upper | digit | safe ){1,20} >mark %request_method;
    Request_Line = ( Method " " Request_URI ("#" Fragment){0,1} " " HTTP_Version CRLF ) %parse_request;
    
    # Response
    HTTP_StatusCode = ( digit{3} ) >mark %status_code;
    Reason_Phrase = ( any+ -- CRLF ) >mark %reason_phrase;
    Response_Line = ( HTTP_Version " " HTTP_StatusCode " " Reason_Phrase CRLF ) %parse_response;

    # Headers
    token = (ascii -- (CTL | tspecials));
    field_name = ( token -- ":" )+ >start_field %write_field;
    field_value = any* >start_value %write_value;
    message_header = field_name ":" " "* field_value :> CRLF;

    Request = Request_Line ( message_header )* ( CRLF );
    Response = Response_Line ( message_header )* ( CRLF );

    main := (Request | Response) @done;

}%%

%% write data;

http_parser::http_parser() {}
http_parser::~http_parser() {}

void http_parser::reset()
{
    %% write init;
    
    nread = 0;
    mark = NULL;
    query_start = NULL;
    field_start = NULL;
    field_len = 0;
    cs = http_parser_en_main;
}

size_t http_parser::parse(const char *buf, size_t len)
{
    const char *p = buf;
    const char *pe = buf + len;

    %% write exec;

    nread += p - buf;

    return nread;
}

bool http_parser::has_error() { return (cs == http_parser_error); }
bool http_parser::is_finished() { return (cs == http_parser_first_final); }
size_t http_parser::bytes_read() { return nread; }
