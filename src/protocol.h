//
//  protocol.h
//

#ifndef protocol_h
#define protocol_h

struct resolver;
typedef std::shared_ptr<resolver> resolver_ptr;

struct pollset;
typedef std::shared_ptr<pollset> pollset_ptr;

struct protocol;
struct protocol_object;
struct protocol_thread;
struct protocol_engine;
typedef std::map<std::string,protocol*> protocol_map;
typedef std::vector<const protocol*> protocol_table;
typedef std::pair<protocol*,std::string> protocol_name_pair;
struct protocol_sock;
typedef std::map<protocol_name_pair,protocol_sock*> protocol_sock_map;
typedef std::vector<const protocol_sock*> protocol_sock_table;
struct protocol_action;
typedef std::map<protocol_name_pair,protocol_action*> protocol_action_map;
typedef std::vector<const protocol_action*> protocol_action_table;
struct protocol_mask;
typedef std::map<protocol_name_pair,protocol_mask*> protocol_mask_map;
typedef std::vector<const protocol_mask*> protocol_mask_table;
struct protocol_state;
typedef std::map<protocol_name_pair,protocol_state*> protocol_state_map;
typedef std::vector<const protocol_state*> protocol_state_table;
struct protocol_message;
typedef std::shared_ptr<protocol> protocol_ptr;
typedef std::deque<protocol_message> protocol_message_list;
struct protocol_handler;
typedef std::shared_ptr<protocol_handler> protocol_handler_ptr;
struct protocol_engine_state;
typedef std::unique_ptr<protocol_engine_state> protocol_engine_state_ptr;
typedef std::vector<protocol_engine_state_ptr> protocol_engine_state_list;
struct protocol_engine_delegate;
struct protocol_thread_delegate;
struct protocol_config;
typedef std::shared_ptr<protocol_config> protocol_config_ptr;
typedef std::map<const protocol*,protocol_config_ptr> protocol_config_map;
struct protocol_config_factory;
typedef std::shared_ptr<protocol_config_factory> protocol_config_factory_ptr;
typedef std::map<protocol*,protocol_config_factory_ptr> protocol_config_factory_map;
typedef std::pair<protocol*,protocol_config_factory_ptr> protocol_config_factory_entry;

typedef void (protocol_cb) (protocol_thread_delegate *, protocol_object *);
typedef std::map<protocol_action*,protocol_cb*> protocol_action_funcs;
typedef std::map<protocol_state*,protocol_cb*> protocol_state_funcs;


/* protocol_debug */

enum protocol_debug {
    protocol_debug_event   = 0x00000001,
    protocol_debug_socket  = 0x00000002,
    protocol_debug_message = 0x00000004,
    protocol_debug_handler = 0x00000008,
    protocol_debug_headers = 0x00000010,
    protocol_debug_timeout = 0x00000020,
    protocol_debug_engine  = 0x00000040,
    protocol_debug_thread  = 0x00000080,
    protocol_debug_tls     = 0x00000100,
    protocol_debug_all     = 0xffffffff,
};


/* protocol_sock_flags */

enum protocol_sock_flags {
    protocol_sock_none                  = 0x0001,
    protocol_sock_unix_ipc              = 0x0002,
    protocol_sock_tcp_listen            = 0x0004,
    protocol_sock_tcp_connection        = 0x0008,
    protocol_sock_udp                   = 0x0010,
    protocol_sock_udp_mcast             = 0x0020,
};


/* protocol_sock */

struct protocol_sock
{
    static protocol_sock_map*       get_map();
    static protocol_sock_table*     get_table();
    
    protocol *const                 proto;
    const std::string               name;
    const int                       flags;
    const int                       type;
    
    protocol_sock(protocol *proto, std::string name, int flags,
                  int type = (int)get_table()->size());
    
    std::string to_string() const;
};


/* protocol_action */

struct protocol_action
{
    static protocol_action_map*     get_map();
    static protocol_action_table*   get_table();
    
    protocol *const                 proto;
    const std::string               name;
    protocol_cb                     *callback;
    const int                       action;
    
    protocol_action(protocol *proto, std::string name,
                    protocol_cb *callback = nullptr,
                    int action = (int)get_table()->size());

    std::string to_string() const;
};


/* protocol_mask */

struct protocol_mask
{
    static protocol_mask_map*       get_map();
    static protocol_mask_table*     get_table();
    
    protocol *const                 proto;
    const std::string               name;
    const int                       offset;
    const int                       mask;
    
    protocol_mask(protocol *proto, std::string name,
                    int offset = (int)get_table()->size(),
                    int mask = 1 << (int)get_table()->size());

    std::string to_string() const;
};


/* protocol_state */

struct protocol_state
{
    static protocol_state_map*      get_map();
    static protocol_state_table*    get_table();
    
    protocol *const                 proto;
    const std::string               name;
    protocol_cb                     *callback;
    const int                       state;
    
    protocol_state(protocol *proto, std::string name,
                   protocol_cb *callback = nullptr,
                   int state = (int)get_table()->size());

    std::string to_string() const;
};


/* protocol_message */

struct protocol_message
{
    int                             action;
    int                             connection_num;
    
    protocol_message();
    protocol_message(int action, int connection_num);

    std::string to_string() const;
};


/* protocol_engine_state */

struct protocol_engine_state
{
    virtual ~protocol_engine_state() {}
    virtual protocol* get_proto() const = 0;
};


/* protocol_config */

struct protocol_config
{
    config_function_map                             config_fn_map;
    block_function_map                              block_start_fn_map;
    block_function_map                              block_end_fn_map;
    
    bool lookup_config_fn(std::string key, config_record &record);
    bool lookup_block_start_fn(std::string key, block_record &record);
    bool lookup_block_end_fn(std::string key, block_record &record);
    
    virtual std::string to_string() { return ""; };
};


/* protocol_engine_delegate */

struct protocol_engine_delegate
{
    virtual ~protocol_engine_delegate() {}

    virtual protocol_engine_state* get_engine_state(protocol *proto) = 0;
    virtual config_ptr get_config() const = 0;
    virtual void add_thread(protocol_thread *thread) = 0;
    virtual protocol_thread* choose_thread(int mask) = 0;
};


/* protocol_thread_delegate */

struct protocol_thread_delegate
{
    virtual ~protocol_thread_delegate() {}
    
    virtual protocol_engine_delegate* get_engine_delegate() const = 0;
    virtual time_t get_current_time() const = 0;
    virtual config_ptr get_config() const = 0;
    virtual pollset_ptr get_pollset() const = 0;
    virtual resolver_ptr get_resolver() const = 0;
    virtual std::thread::id get_thread_id() const = 0;
    virtual std::string get_thread_string() const = 0;
    virtual int get_thread_mask() const = 0;
    virtual int get_debug_mask() const = 0;
    
    virtual protocol_thread_delegate* choose_thread(int mask) = 0;
    virtual void send_message(protocol_thread_delegate *to_thread, protocol_message msg) = 0;
    virtual void queue_message(protocol_thread_delegate *to_thread, protocol_message msg) = 0;
    virtual void add_events(protocol_object *, int events) = 0;
    virtual void remove_events(protocol_object *) = 0;
};


/* protocol_object */

struct protocol_object
{
    virtual ~protocol_object() {}

    virtual std::string to_string();
    virtual int get_poll_fd() = 0;
    virtual poll_object_type get_poll_type() = 0;
    virtual bool init(protocol_engine_delegate *) { return true; }
    virtual bool free(protocol_engine_delegate *) { return true; }
};


/* protocol */

struct protocol
{
    static bool                     debug;
    
    static std::once_flag           protocol_init;

    static protocol                 proto_none;
    static protocol_sock            sock_none;
    static protocol_sock            sock_ipc;
    static protocol_action          action_none;
    static protocol_state           state_none;

    static protocol_map*            get_map();
    static protocol_table*          get_table();
    
    std::string                     name;
    int                             proto;
    
    protocol(std::string name, int proto = (int)get_table()->size());
    virtual ~protocol() {}
    
    std::string to_string() const;
    
    static void init();
    
    virtual void proto_init() {}
    virtual void make_default_config(config_ptr cfg) const {};
    virtual protocol_config_ptr make_protocol_config() const { return protocol_config_ptr(); }
    
    virtual protocol_engine_state* create_engine_state(config_ptr cfg) const { return nullptr; }
    
    virtual void engine_init(protocol_engine_delegate *) const {};
    virtual void engine_shutdown(protocol_engine_delegate *) const {};
    virtual void thread_init(protocol_thread_delegate *) const {};
    virtual void thread_shutdown(protocol_thread_delegate *) const {};
    
    virtual void handle_message(protocol_thread_delegate *, protocol_message &) const {};
    virtual void handle_accept(protocol_thread_delegate *, const protocol_sock *, int listen_fd) const {};
    virtual void handle_connection(protocol_thread_delegate *, protocol_object *, int revents) const {};
    virtual void timeout_connection(protocol_thread_delegate *, protocol_object *) const {};
};

#endif
