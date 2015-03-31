//
//  config.h
//

#ifndef config_h
#define config_h

#define CLIENT_CONNECTIONS_DEFAULT  128
#define SERVER_CONNECTIONS_DEFAULT  1024
#define LISTEN_BACKLOG_DEFAULT      128
#define MAX_HEADERS_DEFAULT         128
#define HEADER_BUFFER_SIZE_DEFAULT  8192
#define IO_BUFFER_SIZE_DEFAULT      32768
#define IPC_BUFFER_SIZE_DEFAULT     1048576
#define CONNETION_TIMEOUT_DEFAULT   60
#define KEEPALIVE_TIMEOUT_DEFAULT   5

struct config;
struct config_record;
struct config_addr;
typedef std::shared_ptr<config> config_ptr;
typedef std::shared_ptr<config_addr> config_addr_ptr;
typedef std::vector<std::string> config_line;
typedef std::function<void(config_line&)>config_function;
typedef std::map<std::string,config_record> config_function_map;
struct protocol;

struct config_record
{
    int minargs;
    int maxargs;
    config_function fn;
};

struct config_addr
{
    socket_addr addr;
        
    std::string to_string();
    
    static config_addr_ptr decode(std::string addr_spec);
};

struct config : config_parser
{
    static config_function_map fn_map;
 
    config();

    std::vector<std::string> line;
    
    int client_connections;
    int server_connections;
    int listen_backlog;
    int max_headers;
    int header_buffer_size;
    int io_buffer_size;
    int ipc_buffer_size;
    int keepalive_timeout;
    int connection_timeout;

    std::string error_log;
    std::string access_log;
    std::string pid_file;
    std::string root;

    std::vector<std::pair<std::string,size_t>> client_threads;
    std::vector<std::pair<std::string,size_t>> server_threads;
    std::vector<std::pair<std::string,size_t>> proto_threads;
    std::vector<std::pair<protocol*,config_addr_ptr>> proto_listeners;
    std::map<std::string,std::string> mime_types;
    std::vector<std::string> index_files;
    std::vector<std::pair<std::string,std::string>> http_routes;
    
    void read(std::string cfg_file);
    void symbol(const char *value, size_t length);
    void end_statement();
    void config_done();
    std::string to_string();

    std::pair<std::string,std::string> lookup_mime_type(std::string path);
};

#endif
