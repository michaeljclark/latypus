//
//  http_client_handler_file.h
//

#ifndef http_client_handler_file_h
#define http_client_handler_file_h


/* http_client_handler_file */

struct http_client_handler_file : http_client_handler
{
    HTTPVersion     http_version;
    HTTPStatusCode  status_code;
    HTTPMethod      request_method;
    ssize_t         content_length;
    ssize_t         total_read;
    io_file         file_resource;
    
    http_client_handler_file();
    http_client_handler_file(int fd);
    ~http_client_handler_file();
    
    virtual void init();
    virtual bool populate_request();
    virtual io_result write_request_body();
    virtual bool handle_response();
    virtual io_result read_response_body();
    virtual bool end_request();
};

#endif
