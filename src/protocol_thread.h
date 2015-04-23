//
//  protocol_thread.h
//

#ifndef protocol_thread_h
#define protocol_thread_h

struct protocol_engine;
struct protocol_thread;
typedef std::unique_ptr<protocol_thread> protocol_thread_ptr;
typedef std::vector<protocol_thread_ptr> protocol_thread_table;
typedef std::vector<protocol_thread*> protocol_thread_list;
typedef std::map<int,protocol_thread_list> protocol_thread_map;
typedef std::map<int,size_t> protocol_thread_next_map;


/* protocol_thread */

struct protocol_thread : protocol_thread_delegate
{
    protocol_engine                 *engine;
    int                             thread_mask;
    unix_socketpair                 notify;
    pollset_ptr                     pollset;
    std::atomic<bool>               running;
    time_t                          current_time;
    time_t                          timeout_check;
    std::vector<int>                fd_lingering_close;
    std::mutex                      message_lock;
    protocol_message_list           message_queue;
    resolver_ptr                    dns;
    std::thread                     thread;
    
    protocol_thread(protocol_engine *server, int thread_mask);
    virtual ~protocol_thread();

    static int string_to_thread_mask(std::string str);
    static std::string thread_mask_to_string(int mask);
    static protocol_table thread_mask_to_protocols(int mask);

    void set_thread_name(std::string name);
    protocol_engine_delegate* get_engine_delegate() const;
    time_t get_current_time() const;
    config_ptr get_config() const;
    pollset_ptr get_pollset() const;
    resolver_ptr get_resolver() const;
    std::thread::id get_thread_id() const;
    std::string get_thread_string() const;
    int get_thread_mask() const;
    int get_debug_mask() const;
    
    protocol_thread_delegate* choose_thread(int mask);
    void send_message(protocol_thread_delegate *to_thread, protocol_message msg);
    void queue_message(protocol_thread_delegate *to_thread, protocol_message msg);
    void add_events(protocol_object *, int events);
    void remove_events(protocol_object *);
    
    void receive_message();
    void mainloop();
};

#endif
