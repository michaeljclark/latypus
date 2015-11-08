//
//  pollset_epoll.h
//

#if defined(__linux__)

#ifndef pollset_epoll_h
#define pollset_epoll_h

struct pollset_epoll : pollset
{
    static const int            max_events;
    
    int                         epoll_fd;
    std::vector<struct epoll_event>  eevents;
    std::vector<poll_object>    pollobjects;
    std::vector<poll_object>    pollobjects_map;
    std::vector<poll_object>    events;
    
    pollset_epoll();
    ~pollset_epoll();
    
    const std::vector<poll_object>& get_objects();
    bool add_object(poll_object obj, int events);
    bool remove_object(poll_object obj);
    const std::vector<poll_object>& do_poll(int timeout);
};

#endif

#endif
