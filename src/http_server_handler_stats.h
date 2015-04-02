//
//  http_server_handler_stats.h
//

#ifndef http_server_handler_stats_h
#define http_server_handler_stats_h


/* http_server_handler_stats */

struct http_server_handler_stats : http_server_handler
{
    HTTPVersion     http_version;
    HTTPMethod      request_method;
    std::string     mime_type;
    std::string     status_text;
    io_reader*      reader;
    io_buffer       response_buffer;
    int             status_code;
    ssize_t         content_length;
    ssize_t         total_written;
    
    http_server_handler_stats();
    ~http_server_handler_stats();
    
    static void init_handler();
    
    virtual void init();
    virtual bool handle_request();
    virtual io_result read_request_body();
    virtual bool populate_response();
    virtual io_result write_response_body();
    virtual bool end_request();
};

#endif
