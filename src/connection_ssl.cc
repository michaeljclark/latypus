//
//  connection_ssl.cc
//

#include "plat_os.h"
#include "plat_net.h"
#include "plat_poll.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cerrno>
#include <iostream>
#include <sstream>
#include <functional>
#include <thread>
#include <mutex>
#include <memory>
#include <string>
#include <vector>
#include <deque>
#include <map>

#include "io.h"
#include "url.h"
#include "log.h"
#include "socket.h"
#include "resolver.h"
#include "config_parser.h"
#include "config.h"
#include "pollset.h"
#include "pollset_poll.h"
#include "pollset_kqueue.h"
#include "protocol.h"
#include "connection.h"
#include "connection_ssl.h"


/* connection_ssl */

#if 0
static BIO_METHOD bio_methods = {
    BIO_TYPE_SOURCE_SINK,
    "connection_ssl",
    connection_ssl::bio_write,
    connection_ssl::bio_read,
    NULL, /* connection_ssl::bio_puts */
    NULL, /* connection_ssl::bio_gets */
    connection_ssl::bio_ctrl,
    connection_ssl::bio_create,
    connection_ssl::bio_destroy,
    NULL, /*  connection_ssl::callback_ctrl */
};
#endif

int connection_ssl::bio_write(BIO *b, const char *buf, int len)
{
    return 0;
}

int connection_ssl::bio_read(BIO *b, char *buf, int len)
{
    return 0;
}

long connection_ssl::bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    return 0;
}

int connection_ssl::bio_create(BIO *b)
{
    return 0;
}

int connection_ssl::bio_destroy(BIO *b)
{
    return 0;
}

