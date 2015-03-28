//
//  resolver.h
//

#ifndef resolver_h
#define resolver_h

struct resolver;
typedef std::shared_ptr<resolver> resolver_ptr;

struct resolver
{
    bool lookup(socket_addr &addr, std::string host, int port = 0);
};

#endif
