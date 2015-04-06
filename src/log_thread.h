//
//  log_thread.h
//

#ifndef log_thread_h
#define log_thread_h

#include "queue_atomic.h"

struct log_thread;
typedef std::shared_ptr<log_thread> log_thread_ptr;

#define LOG_BUFFER_SIZE 1024

struct log_thread : std::thread
{
    static const bool               debug;
    static const int                flush_interval_msecs;
    
    FILE*                           file;
    const size_t                    num_buffers;
    queue_atomic<char*>             log_buffers_free;
    queue_atomic<char*>             log_buffers_inuse;
    time_t                          last_time;
    std::atomic<bool>               running;
    std::atomic<bool>               writer_waiting;
    std::thread                     thread;
    std::mutex                      log_mutex;
    std::condition_variable         log_cond;
    std::condition_variable         writer_cond;

    log_thread(int fd, size_t num_buffers);
    virtual ~log_thread();
    
    void shutdown();
    void create_buffers();
    void delete_buffers();
    void log(time_t current_time, const char* message);
    void write_logs();
    void mainloop();
};

#endif
