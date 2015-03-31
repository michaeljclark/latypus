//
//  protocol_engine.h
//

#ifndef protocol_engine_h
#define protocol_engine_h


/* protocol_engine */

struct protocol_engine : protocol_engine_delegate
{
    int                             debug_mask;
    
    protocol_engine_state_list      state_list;
    
    config_ptr                      cfg;

    protocol_thread_table           threads_all;
    std::mutex                      threads_mutex;
    protocol_thread_map             threads_map;
    protocol_thread_next_map        threads_next;
    std::condition_variable         threads_cond;
    
    static protocol_config_factory_map config_factory_map;
    static std::vector<protocol_engine*> engine_list;
    static std::mutex engine_lock;
    
    static void signal_handler(int signum, siginfo_t *info, void *);
    
    void default_config(std::string protocol);
    void read_config(std::string config_file);
    void run();
    void stop();
    void join();
    
    protocol_engine();
    virtual ~protocol_engine();
    
    std::vector<int> get_thread_masks();
    int get_all_threads_mask();
    protocol_engine_state* get_engine_state(protocol *proto);
    config_ptr get_config() const;
    void add_thread(protocol_thread *thread);
    protocol_thread* choose_thread(int mask);
};

#endif
