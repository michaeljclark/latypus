//
//  pollset_poll.h
//

#ifndef pollset_poll_h
#define pollset_poll_h

struct pollset_poll : pollset
{
    std::vector<pollfd>         pollfds;
    std::vector<poll_object>    pollobjects;
    std::vector<poll_object>    events;
    
    pollset_poll();
    
    const std::vector<poll_object>& get_objects();
    bool add_object(poll_object obj, int events);
    bool remove_object(poll_object obj);
    const std::vector<poll_object>& do_poll(int timeout);
};

#endif
