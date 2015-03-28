//
//  pollset_kqueue.h
//

#ifndef pollset_kqueue_h
#define pollset_kqueue_h

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__OpenBSD__) || defined(__APPLE__)

#include <sys/event.h>

struct pollset_kqueue : pollset
{
    static const int            max_events;
    
    int                         kevent_fd;
    std::vector<struct kevent>  kevents;
    std::vector<poll_object>    pollobjects;
    std::vector<short>          pollfilter;
    std::vector<poll_object>    events;
    
    pollset_kqueue();
    ~pollset_kqueue();
    
    const std::vector<poll_object>& get_objects();
    bool add_object(poll_object obj, int events);
    bool remove_object(poll_object obj);
    const std::vector<poll_object>& do_poll(int timeout);
};

#endif

#endif
