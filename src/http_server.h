//
//  http_server.h
//

#ifndef http_server_h
#define http_server_h

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define USE_RINGBUFFER 1

struct http_server;
struct http_server_engine_state;
struct http_server_thread_state;

struct http_server_handler;
typedef std::shared_ptr<http_server_handler> http_server_handler_ptr;

struct http_server_handler_factory;
typedef std::shared_ptr<http_server_handler_factory> http_server_handler_factory_ptr;
typedef std::pair<std::string,http_server_handler_factory_ptr> http_server_handler_factory_entry;

template <typename TransportConnection> struct http_server_connection_tmpl;
typedef http_server_connection_tmpl<connection> http_server_connection;

typedef std::function<std::string(http_server_connection*)> http_server_function;

struct http_server_location;
typedef std::shared_ptr<http_server_location> http_server_location_ptr;
typedef std::vector<http_server_location_ptr> http_server_location_list;
typedef trie<http_server_location*> http_server_location_trie;

struct http_server_vhost;
typedef std::pair<socket_addr,socket_mode> http_server_listen_spec;
typedef std::shared_ptr<http_server_vhost> http_server_vhost_ptr;
typedef std::vector<http_server_vhost_ptr> http_server_vhost_list;
typedef std::map<std::string,http_server_vhost*> http_server_vhost_map;
typedef std::pair<std::string,http_server_vhost*> http_server_vhost_entry;

struct http_server_config;


/* http_server_handler_factory */

struct http_server_handler_factory
{
    virtual ~http_server_handler_factory() {}
    
    virtual std::string get_name() = 0;
    virtual http_server_handler_ptr new_handler() = 0;
};

template <typename T>
struct http_server_handler_factory_impl : http_server_handler_factory
{
    std::string name;
    
    http_server_handler_factory_impl(std::string name) : name(name) {}
    
    std::string get_name() { return name; }
    http_server_handler_ptr new_handler() { return http_server_handler_ptr(new T()); }
};


/* http_server_handler */

struct http_server_handler
{
    http_server_connection      *http_conn;
    protocol_thread_delegate    *delegate;
    http_server_vhost           *vhost;
    http_server_location        *location;
    std::string                 path_translated;
    time_t                      current_time;
    
    void set_connection(http_server_connection *conn) { http_conn = conn; }
    void set_delegate(protocol_thread_delegate *delegate) { this->delegate = delegate; }
    void set_current_time(time_t current_time) { this->current_time = current_time; }

    virtual void init() = 0;
    virtual bool handle_request() = 0;
    virtual io_result read_request_body() = 0;
    virtual bool populate_response() = 0;
    virtual io_result write_response_body() = 0;
    virtual bool end_request() = 0;
};


/* http_server_connection */

template <typename TransportConnection>
struct http_server_connection_tmpl : protocol_object
{
    TransportConnection         conn;
#if USE_RINGBUFFER
    io_ring_buffer              buffer;
#else
    io_buffer                   buffer;
#endif
    protocol_state              *state;
    http_request                request;
    http_response               response;
    http_server_handler_ptr     handler;
    unsigned int                request_has_body : 1;
    unsigned int                response_has_body : 1;
    unsigned int                connection_close : 1;

    // TODO add stats

    http_server_connection_tmpl<TransportConnection>() : state(nullptr) {}
    http_server_connection_tmpl<TransportConnection>(const http_server_connection_tmpl&) : state(nullptr) {}

    int get_poll_fd();
    poll_object_type get_poll_type();
    bool init(protocol_engine_delegate *delegate);
    bool free(protocol_engine_delegate *delegate);
};


/* http_server_location */

struct http_server_location
{
    http_server_vhost*                          vhost;
    
    http_server_location() = delete;
    http_server_location(http_server_vhost *vhost) : vhost(vhost) {}
    
    std::string                                 uri;
    std::string                                 root;
    std::string                                 handler;
    std::vector<std::string>                    index_files;
    http_server_handler_factory_ptr             handler_factory;
};


/* http_server_vhost */

struct http_server_vhost
{
    http_server_config*                         server_cfg;
    
    http_server_vhost() = delete;
    http_server_vhost(http_server_config *server_cfg) : server_cfg(server_cfg) {}
    
    std::vector<http_server_listen_spec>        listens;
    std::vector<std::string>                    server_names;
    std::string                                 access_log;
    std::string                                 error_log;
    std::string                                 tls_key_file;
    std::string                                 tls_cert_file;
    std::string                                 tls_cipher_list;
    http_server_location_list                   location_list;
    SSL_CTX*                                    ssl_ctx;
    
    http_server_location_trie                   location_trie;
    io_file                                     access_log_file;
    log_thread_ptr                              access_log_thread;
    io_file                                     error_log_file;
    log_thread_ptr                              error_log_thread;
};


/* http_server_config */

struct http_server_config : protocol_config
{
    http_server_vhost_ptr                       current_vhost;
    http_server_location_ptr                    current_location;
    
    http_server_vhost_list                      vhost_list;
    http_server_vhost_map                       vhost_map;

    std::vector<std::pair<std::string,std::string>> routes;
    
    http_server_config();
    
    std::string to_string();
};


/* http_server */

struct http_server : protocol
{
    typedef http_server_engine_state engine_state_type;
    typedef http_server_thread_state thread_state_type;
    typedef http_server_connection connection_type;
    typedef http_server_config config_type;
    typedef std::function<std::string(http_server_connection*)> function_type;
    
    /* sock */
    static protocol_sock server_sock_tcp_listen;
    static protocol_sock server_sock_tcp_connection;
    static protocol_sock server_sock_tcp_tls_listen;
    static protocol_sock server_sock_tcp_tls_connection;
    
    /* actions */
    static protocol_action action_router_tls_handshake;
    static protocol_action action_router_process_headers;
    static protocol_action action_worker_process_request;
    static protocol_action action_keepalive_wait_connection;
    static protocol_action action_linger_read_connection;
    
    /* threads */
    static protocol_mask thread_mask_listener;
    static protocol_mask thread_mask_router;
    static protocol_mask thread_mask_keepalive;
    static protocol_mask thread_mask_worker;
    static protocol_mask thread_mask_linger;
    
    /* states */
    static protocol_state connection_state_free;
    static protocol_state connection_state_tls_handshake;
    static protocol_state connection_state_client_request;
    static protocol_state connection_state_client_body;
    static protocol_state connection_state_server_response;
    static protocol_state connection_state_server_body;
    static protocol_state connection_state_waiting;
    static protocol_state connection_state_lingering_close;

    /* id */
    static const char* ServerName;
    static const char* ServerVersion;

    /* initialization */
    
    static std::once_flag protocol_init;

    /* handlers */
    
    static std::map<std::string,http_server_handler_factory_ptr> handler_factory_map;

    template <typename T>
    static void register_handler(std::string name)
    {
        http_server_handler_factory_ptr factory(new http_server_handler_factory_impl<T>(name));
        handler_factory_map.insert(http_server_handler_factory_entry(name, factory));
    }
    
    /* constructor, destructor */
    
    http_server(std::string name);
    virtual ~http_server();
    
    /* state helpers */

    static http_server_engine_state* get_engine_state(protocol_thread_delegate *delegate);
    static http_server_engine_state* get_engine_state(protocol_engine_delegate *delegate);

    /* protocol */

    static protocol* get_proto();
    
    void proto_init();
    void make_default_config(config_ptr cfg) const;
    void make_default_vhost(config_ptr cfg) const;
    protocol_config_ptr make_protocol_config() const;

    protocol_engine_state* create_engine_state(config_ptr cfg) const;
    protocol_thread_state* create_thread_state(config_ptr cfg) const;
    
    void engine_init(protocol_engine_delegate *) const;
    void engine_shutdown(protocol_engine_delegate *) const;
    void thread_init(protocol_thread_delegate *) const;
    void thread_shutdown(protocol_thread_delegate *) const;
    
    void handle_message(protocol_thread_delegate *, protocol_message &) const;
    void handle_accept(protocol_thread_delegate *, const protocol_sock *, int listen_fd) const;
    void handle_connection(protocol_thread_delegate *, protocol_object *, int revents) const;
    void timeout_connection(protocol_thread_delegate *, protocol_object *) const;

    /* http_server messages */
    
    static void router_tls_handshake(protocol_thread_delegate *, protocol_object *);
    static void router_process_headers(protocol_thread_delegate *, protocol_object *);
    static void keepalive_wait_connection(protocol_thread_delegate *, protocol_object *);
    static void worker_process_request(protocol_thread_delegate *, protocol_object *);
    static void linger_read_connection(protocol_thread_delegate *, protocol_object *);

    /* http_server state handlers */

    static void handle_state_tls_handshake(protocol_thread_delegate *, protocol_object *);
    static void handle_state_client_request(protocol_thread_delegate *, protocol_object *);
    static void handle_state_client_body(protocol_thread_delegate *, protocol_object *);
    static void handle_state_server_response(protocol_thread_delegate *, protocol_object *);
    static void handle_state_server_body(protocol_thread_delegate *, protocol_object *);
    static void handle_state_waiting(protocol_thread_delegate *, protocol_object *);
    static void handle_state_lingering_close(protocol_thread_delegate *, protocol_object *);

    /* http_server internal */

    static bool process_request_headers(protocol_thread_delegate *, protocol_object *);
    static http_server_handler_ptr translate_path(protocol_thread_delegate *, http_server_connection *);
    static ssize_t populate_response_headers(protocol_thread_delegate *, protocol_object *);
    static void finished_request(protocol_thread_delegate *, protocol_object *);
    static void dispatch_connection(protocol_thread_delegate *, protocol_object *);
    static void dispatch_connection_tls(protocol_thread_delegate *, protocol_object *);
    static void work_connection(protocol_thread_delegate *, protocol_object *);
    static void keepalive_connection(protocol_thread_delegate *, protocol_object *);
    static void linger_connection(protocol_thread_delegate *, protocol_object *);
    static void forward_connection(protocol_thread_delegate*, protocol_object *, const protocol_mask &proto_mask, const protocol_action &proto_action);
    static http_server_connection* new_connection(protocol_thread_delegate *);
    static http_server_connection* get_connection(protocol_thread_delegate *, int conn_id);
    static void abort_connection(protocol_thread_delegate*, protocol_object *);
    static void close_connection(protocol_thread_delegate*, protocol_object *);
};


/* http_server_engine_stats */

struct http_server_engine_stats
{
    http_server_engine_stats() :
        connections_accepted(0),
        connections_aborted(0),
        connections_closed(0),
        connections_keepalive(0),
        connections_linger(0),
        requests_processed(0) {}
    
    std::atomic<unsigned long> connections_accepted;
    std::atomic<unsigned long> connections_aborted;
    std::atomic<unsigned long> connections_closed;
    std::atomic<unsigned long> connections_keepalive;
    std::atomic<unsigned long> connections_linger;
    std::atomic<unsigned long> requests_processed;
};

/* http_server_engine_state */

struct http_server_engine_state : protocol_engine_state, protocol_connection_state<http_server_connection>
{
    config_ptr                                  cfg;
    http_server_engine_stats                    stats;
    connected_socket_list                       listens;
    SSL_CTX*                                    ssl_ctx;
    
    http_server_engine_state(config_ptr cfg) : cfg(cfg), ssl_ctx(nullptr) {}
    
    protocol* get_proto() const { return http_server::get_proto(); }
    
    void bind_function(config_ptr cfg, std::string path, typename http_server::function_type);
};

/* http_server_thread_state */

struct http_server_thread_state : protocol_thread_state
{
    config_ptr                                  cfg;
    
    http_server_thread_state(config_ptr cfg) : cfg(cfg) {}

    protocol* get_proto() const { return http_server::get_proto(); }
};

#endif
