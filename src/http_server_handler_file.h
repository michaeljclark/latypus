//
//  http_server_handler_file.h
//

#ifndef http_server_handler_file_h
#define http_server_handler_file_h


/* http_server_handler_file */

struct http_server_handler_file : http_server_handler
{
    HTTPVersion     http_version;
    HTTPMethod      request_method;
    std::string     open_path;
    std::string     translated_path;
    std::string     mime_type;
    std::string     status_text;
    io_reader*      reader;
    io_buffer       error_buffer;
    io_file         file_resource;
    io_error        open_err;
    io_error        stat_err;
    int             status_code;
    ssize_t         content_length;
    ssize_t         total_written;
    struct stat     stat_result;
    http_date       last_modified;
    http_date       if_modified_since;
    
    http_server_handler_file();
    ~http_server_handler_file();
    
    static void init_handler();
    
    virtual void translate_path();
    virtual size_t create_error_response();
    virtual int open_resource(int oflag, int mask);
    
    virtual void init();
    virtual bool handle_request();
    virtual io_result read_request_body();
    virtual bool populate_response();
    virtual io_result write_response_body();
    virtual bool end_request();
};

#endif
