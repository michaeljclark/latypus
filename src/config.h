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
#define IO_BUFFER_SIZE_DEFAULT      8192
#define IPC_BUFFER_SIZE_DEFAULT     1048576
#define LOG_BUFFERS_DEFAULT         1024
#define CONNETION_TIMEOUT_DEFAULT   60
#define KEEPALIVE_TIMEOUT_DEFAULT   5
#define TLS_SESSION_TIMEOUT_DEFAULT 7200
#define TLS_SESSION_COUNT_DEFAULT   32768

struct config;
struct config_record;
struct block_record;
struct config_addr;
typedef std::shared_ptr<config> config_ptr;
typedef std::shared_ptr<config_addr> config_addr_ptr;
typedef std::vector<std::string> config_line;
typedef std::function<void(config*,config_line&)>config_function;
typedef std::map<std::string,config_record> config_function_map;
typedef std::function<void(config*)>block_function;
typedef std::map<std::string,block_record> block_function_map;
struct protocol;
struct protocol_config;
typedef std::shared_ptr<protocol_config> protocol_config_ptr;
typedef std::map<const protocol*,protocol_config_ptr> protocol_config_map;

struct config_record
{
    int minargs;
    int maxargs;
    config_function fn;
};

struct block_record
{
    const char* parent_block;
    block_function fn;
};

struct config_addr
{
    socket_addr addr;
        
    std::string to_string();
    
    static config_addr_ptr decode(std::string addr_spec);
};

struct config : config_parser
{
    config_function_map         config_fn_map;
    block_function_map          block_start_fn_map;
    block_function_map          block_end_fn_map;
    protocol_config_map         proto_conf_map;
 
    config();

    std::vector<std::string>    block;
    std::vector<std::string>    line;
    
    template <typename T>
    typename T::config_type* get_config()
    {
        auto pci = proto_conf_map.find(T::get_proto());
        if (pci != proto_conf_map.end()) {
            return static_cast<typename T::config_type*>(pci->second.get());
        }
        return nullptr;
    }
    
    int client_connections;
    int server_connections;
    int listen_backlog;
    int max_headers;
    int header_buffer_size;
    int io_buffer_size;
    int ipc_buffer_size;
    int log_buffers;
    int keepalive_timeout;
    int connection_timeout;

    std::string tls_ca_file;
    std::string tls_key_file;
    std::string tls_cert_file;
    std::string tls_cipher_list;
    int tls_session_timeout;
    int tls_session_count;

    std::string error_log;
    std::string access_log;
    std::string pid_file;
    std::string root;

    std::vector<std::pair<std::string,size_t>> client_threads;
    std::vector<std::pair<std::string,size_t>> server_threads;
    std::vector<std::pair<std::string,size_t>> proto_threads;
    std::vector<std::tuple<protocol*,config_addr_ptr,socket_mode>> proto_listeners;
    std::map<std::string,std::string> mime_types;
    std::vector<std::string> index_files;
    
    void read(std::string cfg_file);
    void symbol(const char *value, size_t length);
    void end_statement();
    void start_block();
    void end_block();
    void config_done();
    std::string to_string();
    
    bool lookup_config_fn(std::string key, config_record &record);
    bool lookup_block_start_fn(std::string key, block_record &block);
    bool lookup_block_end_fn(std::string key, block_record &block);
    
    std::pair<std::string,std::string> lookup_mime_type(std::string path);
};

#endif
