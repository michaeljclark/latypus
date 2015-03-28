//
//  pollset.h
//

#ifndef pollset_h
#define pollset_h

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__OpenBSD__) || defined(__APPLE__)
#define pollset_platform_type pollset_kqueue
#elif defined (__linux__)
#define pollset_platform_type pollset_epoll
#else
#define pollset_platform_type pollset_poll
#endif

/* pollset
 *
 * delta based interface around poll that also records the object
 * associated with file descriptors in the poll set
 */

struct pollset;
typedef std::shared_ptr<pollset> pollset_ptr;

typedef int poll_object_type;

enum {
    poll_event_in =         POLLIN,     /* 0x001 */
    poll_event_out =        POLLOUT,    /* 0x004 */
    poll_event_err =        POLLERR,    /* 0x008 */
    poll_event_hup =        POLLHUP,    /* 0x010 */
    poll_event_invalid =    POLLNVAL,   /* 0x020 */
};

typedef int poll_event_mask;

struct poll_object
{
    void *ptr;
    int fd;
    unsigned short type;
    unsigned short event_mask;
    
    poll_object() : ptr(nullptr), fd(-1), type(0), event_mask(0) {}
    poll_object(poll_object_type type, void *ptr, int fd) : ptr(ptr), fd(fd), type(type), event_mask(0) {}
    poll_object(const poll_object &o, const pollfd &pfd) : ptr(o.ptr), fd(o.fd), type(o.type), event_mask(pfd.revents) {}
    poll_object(const poll_object &o, unsigned short event_mask) : ptr(o.ptr), fd(o.fd), type(o.type), event_mask(event_mask) {}

    bool operator==(const poll_object &o) { return (ptr == o.ptr && type == o.type); }
    bool operator!=(const poll_object &o) { return !(ptr == o.ptr && type == o.type); }
    
    std::string to_string();
};

struct pollset
{
    virtual ~pollset();
    
    virtual const std::vector<poll_object>& get_objects() = 0;
    virtual bool add_object(poll_object obj, int events) = 0;
    virtual bool remove_object(poll_object obj) = 0;
    virtual const std::vector<poll_object>& do_poll(int timeout) = 0;
};

#endif
