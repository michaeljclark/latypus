//
//  http_cient.h
//

#ifndef http_cient_h
#define http_cient_h

#define USE_RINGBUFFER 1

struct http_client;
struct http_client_engine_state;
struct http_client_thread_state;

struct http_client_handler;
typedef std::shared_ptr<http_client_handler> http_client_handler_ptr;

struct http_client_request;
typedef std::shared_ptr<http_client_request> http_client_request_ptr;
typedef std::deque<http_client_request_ptr> http_client_request_list;

template <typename TransportConnection> struct http_client_connection_tmpl;
typedef http_client_connection_tmpl<connection_tcp> http_client_connection;


/* http_client_request */

struct http_client_request
{
    HTTPMethod                  method;
    url_ptr                     url;
    http_client_handler_ptr     handler;
    
    http_client_request(HTTPMethod method, url_ptr url, http_client_handler_ptr handler);
};


/* http_client_handler */

struct http_client_handler
{
    http_client_connection      *http_conn;
    protocol_thread_delegate    *delegate;
    time_t                      current_time;
    
    void set_connection(http_client_connection *conn) { http_conn = conn; }
    void set_delegate(protocol_thread_delegate *delegate) { this->delegate = delegate; }
    void set_current_time(time_t current_time) { this->current_time = current_time; }

    virtual void init() = 0;
    virtual bool populate_request() = 0;
    virtual io_result write_request_body() = 0;
    virtual bool handle_response() = 0;
    virtual io_result read_response_body() = 0;
    virtual bool end_request() = 0;
};


/* http_client_connection */

template <typename TransportConnection>
struct http_client_connection_tmpl : protocol_object
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
    http_client_handler_ptr     handler;
    unsigned int                request_has_body : 1;
    unsigned int                response_has_body : 1;
    unsigned int                connection_close : 1;
    std::string                 remote_host;
    http_client_request_list    url_requests;
    std::mutex                  connection_mutex;
    int                         requests_processed;
    
    // TODO add stats
    
    http_client_connection_tmpl<TransportConnection>() : state(nullptr) {}
    http_client_connection_tmpl<TransportConnection>(const http_client_connection_tmpl&) : state(nullptr) {}
    
    int get_poll_fd();
    poll_object_type get_poll_type();    
    bool init(protocol_engine_delegate *delegate);
    bool free(protocol_engine_delegate *delegate);
};


/* http_client_config_factory */

struct http_client_config_factory : protocol_config_factory
{
    void make_config(config_ptr cfg) const;
};


/* http_client */

struct http_client : protocol
{
    typedef http_client_engine_state engine_state_type;
    typedef http_client_thread_state thread_state_type;
    typedef http_client_connection connection_type;
    typedef std::function<std::string(http_client_connection*)> function_type;
    
    /* sock */
    static protocol_sock client_sock_tcp_connection;
    static protocol_sock client_sock_tcp_tls_connection;
    
    /* actions */
    static protocol_action action_connect_host;
    static protocol_action action_process_next_request;
    static protocol_action action_keepalive_wait_connection;
    
    /* threads */
    static protocol_mask thread_mask_connect;
    static protocol_mask thread_mask_processor;
    static protocol_mask thread_mask_keepalive;
    
    /* states */
    static protocol_state connection_state_free;
    static protocol_state connection_state_client_request;
    static protocol_state connection_state_client_body;
    static protocol_state connection_state_server_response;
    static protocol_state connection_state_server_body;
    static protocol_state connection_state_waiting;

    /* id */
    static const char* ClientName;
    static const char* ClientVersion;

    /* initialization */
    
    static std::once_flag protocol_init;
    
    /* constructor, destructor */
    
    http_client(std::string name);
    virtual ~http_client();
    
    /* state helpers */
    
    static http_client_engine_state* get_engine_state(protocol_thread_delegate *delegate);
    static http_client_engine_state* get_engine_state(protocol_engine_delegate *delegate);
    
    /* protocol */

    static protocol* get_proto();
    void proto_init();

    protocol_engine_state* create_engine_state() const;
    protocol_thread_state* create_thread_state() const;
    
    void engine_init(protocol_engine_delegate *) const;
    void engine_shutdown(protocol_engine_delegate *) const;
    void thread_init(protocol_thread_delegate *) const;
    void thread_shutdown(protocol_thread_delegate *) const;
    
    void handle_message(protocol_thread_delegate *, protocol_message &) const;
    void handle_connection(protocol_thread_delegate *, protocol_object *, int revents) const;
    void timeout_connection(protocol_thread_delegate *, protocol_object *) const;
    
    /* http_client messages */

    static void connect_host(protocol_thread_delegate *, protocol_object *);
    static void process_next_request(protocol_thread_delegate *, protocol_object *);
    static void keepalive_wait_connection(protocol_thread_delegate *, protocol_object *);

    /* http_server state handlers */

    static void handle_state_client_request(protocol_thread_delegate *, protocol_object *);
    static void handle_state_client_body(protocol_thread_delegate *, protocol_object *);
    static void handle_state_server_response(protocol_thread_delegate *, protocol_object *);
    static void handle_state_server_body(protocol_thread_delegate *, protocol_object *);
    static void handle_state_waiting(protocol_thread_delegate *, protocol_object *);

    /* http_client internal */
    
    static ssize_t populate_request_headers(protocol_thread_delegate *, protocol_object *);
    static void process_response_headers(protocol_thread_delegate *, protocol_object *);
    static void connect_connection(protocol_thread_delegate *, protocol_object *);
    static void process_connection(protocol_thread_delegate *, protocol_object *);
    static void keepalive_connection(protocol_thread_delegate *, protocol_object *);
    static void forward_connection(protocol_thread_delegate*, protocol_object *, const protocol_mask &proto_mask, const protocol_action &proto_action);
    static http_client_connection* get_connection(protocol_thread_delegate *, int conn_id);
    static void abort_connection(protocol_thread_delegate*, protocol_object *);
    static void close_connection(protocol_thread_delegate*, protocol_object *);

    static http_client_connection* get_new_connection_for_url(protocol_engine_delegate *, url_ptr url);
    static http_client_connection* get_existing_connection_for_url(protocol_engine_delegate *, url_ptr url, size_t max_requests_per_connection);

    /* public interface */
    
    static bool submit_request(protocol_engine_delegate *,
                               http_client_request_ptr url_req,
                               size_t max_requests_per_connection);
};


/* http_client_engine_state */

struct http_client_engine_state : protocol_engine_state, protocol_connection_state<http_client_connection>
{
    protocol* get_proto() const { return http_client::get_proto(); }

    void bind_function(std::string path, typename http_client::function_type)
    {
        log_error("%s bind_function not implemented", get_proto()->name.c_str());
    }
};


/* http_client_thread_state */

struct http_client_thread_state : protocol_thread_state
{    
    protocol* get_proto() const { return http_client::get_proto(); }
};

#endif
