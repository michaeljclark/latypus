//
//  http_server_handler_func.h
//

#ifndef http_server_handler_func_h
#define http_server_handler_func_h


/* http_server_handler_func */

struct http_server_handler_func : http_server_handler
{
    http_server_function fn;
    
    HTTPVersion     http_version;
    HTTPMethod      request_method;
    std::string     mime_type;
    std::string     status_text;
    io_reader*      reader;
    io_buffer       response_buffer;
    int             status_code;
    ssize_t         content_length;
    ssize_t         total_written;
    
    http_server_handler_func(http_server_function fn);
    ~http_server_handler_func();
        
    virtual void init();
    virtual bool handle_request();
    virtual io_result read_request_body();
    virtual bool populate_response();
    virtual io_result write_response_body();
    virtual bool end_request();
};

struct http_server_handler_factory_func : http_server_handler_factory
{
    std::string name;
    http_server_function fn;
    
    http_server_handler_factory_func(std::string name, http_server_function fn) : name(name), fn(fn) {}
    
    std::string get_name() { return name; }
    http_server_handler_ptr new_handler() { return std::make_shared<http_server_handler_func>(fn); }
};

#endif
