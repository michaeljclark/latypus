//
//  latypus.h
//

#ifndef latypus_h
#define latypus_h

#include "plat_os.h"
#include "plat_net.h"
#include "plat_poll.h"

#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <memory>
#include <utility>
#include <algorithm>
#include <functional>
#include <map>
#include <deque>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <atomic>
#include <mutex>
#include <thread>
#include <condition_variable>

#include "os.h"
#include "io.h"
#include "url.h"
#include "log.h"
#include "log_thread.h"
#include "trie.h"
#include "socket.h"
#include "socket_tcp.h"
#include "socket_udp.h"
#include "socket_unix.h"
#include "netdev.h"
#include "resolver.h"
#include "cmdline_options.h"
#include "config_parser.h"
#include "config.h"
#include "pollset.h"
#include "pollset_poll.h"
#include "pollset_epoll.h"
#include "pollset_kqueue.h"
#include "protocol.h"
#include "connection.h"
#include "connection.h"
#include "protocol_thread.h"
#include "protocol_engine.h"
#include "protocol_connection.h"

#include "http_common.h"
#include "http_constants.h"
#include "http_parser.h"
#include "http_request.h"
#include "http_response.h"
#include "http_date.h"
#include "http_server.h"
#include "http_server_handler_file.h"
#include "http_server_handler_func.h"
#include "http_server_handler_stats.h"
#include "http_client.h"
#include "http_client_handler_file.h"

#endif
