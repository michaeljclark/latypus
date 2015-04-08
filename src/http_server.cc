//
//  http_server.cc
//

#include "plat_os.h"
#include "plat_net.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cerrno>
#include <csignal>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <functional>
#include <deque>
#include <map>
#include <atomic>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>

#include "io.h"
#include "url.h"
#include "log.h"
#include "log_thread.h"
#include "trie.h"
#include "socket.h"
#include "socket_unix.h"
#include "socket_tcp.h"
#include "socket_tls.h"
#include "resolver.h"
#include "config_parser.h"
#include "config.h"
#include "pollset.h"
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

#define USE_NODELAY 1
#define USE_NOPUSH 1


// sock
protocol_sock http_server::server_sock_tcp_listen
    (get_proto(), "tcp_listen", protocol_sock_tcp_listen);
protocol_sock http_server::server_sock_tcp_connection
    (get_proto(), "tcp_connection", protocol_sock_tcp_connection);
protocol_sock http_server::server_sock_tcp_tls_listen
    (get_proto(), "tcp_tls_listen", protocol_sock_tcp_listen | protocol_sock_tcp_tls);
protocol_sock http_server::server_sock_tcp_tls_connection
    (get_proto(), "tcp_tls_connection", protocol_sock_tcp_connection | protocol_sock_tcp_tls);

// actions
protocol_action http_server::action_router_tls_handshake
    (get_proto(), "router_tls_handshake", &router_tls_handshake);
protocol_action http_server::action_router_process_headers
    (get_proto(), "router_process_headers", &router_process_headers);
protocol_action http_server::action_worker_process_request
    (get_proto(), "worker_process_request", &worker_process_request);
protocol_action http_server::action_keepalive_wait_connection
    (get_proto(), "keepalive_wait_connection", &keepalive_wait_connection);
protocol_action http_server::action_linger_read_connection
    (get_proto(), "linger_read_connection", &linger_read_connection);

// threads
protocol_mask http_server::thread_mask_listener
    (get_proto(), "listener");
protocol_mask http_server::thread_mask_router
    (get_proto(), "router");
protocol_mask http_server::thread_mask_keepalive
    (get_proto(), "keepalive");
protocol_mask http_server::thread_mask_worker
    (get_proto(), "worker");
protocol_mask http_server::thread_mask_linger
    (get_proto(), "linger");

// states
protocol_state http_server::connection_state_free
    (get_proto(), "free");
protocol_state http_server::connection_state_tls_handshake
    (get_proto(), "client_request", &handle_state_tls_handshake);
protocol_state http_server::connection_state_client_request
    (get_proto(), "client_request", &handle_state_client_request);
protocol_state http_server::connection_state_client_body
    (get_proto(), "client_body", &handle_state_client_body);
protocol_state http_server::connection_state_server_response
    (get_proto(), "server_response", &handle_state_server_response);
protocol_state http_server::connection_state_server_body
    (get_proto(), "server_body", &handle_state_server_body);
protocol_state http_server::connection_state_waiting
    (get_proto(), "waiting", &handle_state_waiting);
protocol_state http_server::connection_state_lingering_close
    (get_proto(), "lingering_close", &handle_state_lingering_close);


/* http_server_connection */

template <>
int http_server_connection_tmpl<connection>::get_poll_fd()
{
    return conn.get_poll_fd();
}

template <>
poll_object_type http_server_connection_tmpl<connection>::get_poll_type()
{
    return http_server::server_sock_tcp_connection.type;
}

template <>
bool http_server_connection_tmpl<connection>::init(protocol_engine_delegate *delegate)
{
    buffer.reset();
    conn.reset();
    request.reset();
    response.reset();
    request_has_body = false;
    response_has_body = false;
    connection_close = true;
    state = &http_server::connection_state_free;
    if (buffer.size() == 0) {
        auto cfg = delegate->get_config();
        buffer.resize(cfg->io_buffer_size);
        request.resize(cfg->header_buffer_size);
        response.resize(cfg->header_buffer_size);
    } else {
#if ZERO_BUFFERS
        io_buffer::clear();
#endif
    }
    return true;
}

template <>
bool http_server_connection_tmpl<connection>::free(protocol_engine_delegate *delegate)
{
    state = &http_server::connection_state_free;
    handler = http_server_handler_ptr();
    return true;
}


/* http_server_config_factory */

void http_server_config_factory::make_config(config_ptr cfg) const
{
    log_info("%s using default config", http_server::get_proto()->name.c_str());
    cfg->pid_file = "/tmp/latypus.pid";
    cfg->error_log = "/tmp/latypus.errors";
    cfg->access_log = "/tmp/latypus.access";
    cfg->listen_backlog = LISTEN_BACKLOG_DEFAULT;
    cfg->server_connections = SERVER_CONNECTIONS_DEFAULT;
    cfg->connection_timeout = CONNETION_TIMEOUT_DEFAULT;
    cfg->keepalive_timeout = KEEPALIVE_TIMEOUT_DEFAULT;
    cfg->max_headers = MAX_HEADERS_DEFAULT;
    cfg->header_buffer_size = HEADER_BUFFER_SIZE_DEFAULT;
    cfg->io_buffer_size = IO_BUFFER_SIZE_DEFAULT;
    cfg->ipc_buffer_size = IPC_BUFFER_SIZE_DEFAULT;
    cfg->log_buffers = LOG_BUFFERS_DEFAULT;
    cfg->proto_listeners.push_back(std::tuple<protocol*,config_addr_ptr,socket_mode>
                                   (http_server::get_proto(),
                                    config_addr::decode("[]:8080"),
                                    socket_mode_plain));
    cfg->proto_listeners.push_back(std::tuple<protocol*,config_addr_ptr,socket_mode>
                                   (http_server::get_proto(),
                                    config_addr::decode("127.0.0.1:8080"),
                                    socket_mode_plain));
    cfg->proto_threads.push_back(std::pair<std::string,size_t>("http_server/listener", 1));
    cfg->proto_threads.push_back(std::pair<std::string,size_t>("http_server/router,http_server/worker,http_server/keepalive,http_server/linger", std::thread::hardware_concurrency()));
    cfg->root = "html";
    cfg->http_routes.push_back(std::pair<std::string,std::string>("/", "http_server_handler_file"));
    cfg->http_routes.push_back(std::pair<std::string,std::string>("/stats/", "http_server_handler_stats"));
    cfg->mime_types["html"] = "text/html";
    cfg->mime_types["htm"] = "text/html";
    cfg->mime_types["txt"] = "text/plain";
    cfg->mime_types["css"] = "text/css";
    cfg->mime_types["js"] = "text/java-script";
    cfg->mime_types["gif"] = "image/gif";
    cfg->mime_types["jpeg"] = "image/jpeg";
    cfg->mime_types["jpg"] = "image/jpeg";
    cfg->mime_types["png"] = "image/png";
    cfg->mime_types["crt"] = "application/x-x509-ca-cert";
    cfg->mime_types["default"] = "application/octet-stream";
    cfg->index_files.push_back("index.html");
    cfg->index_files.push_back("index.htm");
}


/* http_server */

const char* http_server::ServerName = "latypus";
const char* http_server::ServerVersion = "0.0.0";

std::once_flag http_server::protocol_init;
std::map<std::string,http_server_handler_factory_ptr> http_server::handler_factory_map;

http_server::http_server(std::string name) : protocol(name) {}
http_server::~http_server() {}

protocol* http_server::get_proto()
{
    static http_server proto("http_server");
    return &proto;
}

void http_server::proto_init()
{
    std::call_once(protocol_init, [](){
        http_constants::init();
        protocol_engine::config_factory_map.insert
            (protocol_config_factory_entry(get_proto(), std::make_shared<http_server_config_factory>()));
        http_server_handler_file::init_handler();
        http_server_handler_stats::init_handler();
    });
}

http_server_engine_state* http_server::get_engine_state(protocol_thread_delegate *delegate) {
    return static_cast<http_server_engine_state*>(delegate->get_engine_delegate()->get_engine_state(get_proto()));
}

http_server_engine_state* http_server::get_engine_state(protocol_engine_delegate *delegate) {
    return static_cast<http_server_engine_state*>(delegate->get_engine_state(get_proto()));
}

protocol_engine_state* http_server::create_engine_state() const
{
    return new http_server_engine_state();
}

protocol_thread_state* http_server::create_thread_state() const
{
    return new http_server_thread_state();
}

static int log_tls_errors(const char *str, size_t len, void *bio)
{
    fprintf(stderr, "%s", str);
    return 0;
}

void http_server::engine_init(protocol_engine_delegate *delegate) const
{
    // get config
    auto cfg = delegate->get_config();
    auto engine_state = get_engine_state(delegate);
    
    // initialize routes
    for (auto &route : cfg->http_routes) {
        auto &path = route.first;
        auto &handler = route.second;
        auto fi = handler_factory_map.find(handler);
        if (fi == handler_factory_map.end()) {
            log_error("%s couldn't find handler factory: %s", get_proto()->name.c_str(), handler.c_str());
        } else {
            log_info("%s registering route \"%s\" -> %s", get_proto()->name.c_str(), path.c_str(), handler.c_str());
            engine_state->handler_list.push_back
                (http_server_handler_info_ptr(new http_server_handler_info(path, fi->second)));
        }
    }
    
    // initialize connection table
    engine_state->init(delegate, cfg->server_connections);
    
    // open log file
    if (cfg->access_log.size() > 0 && cfg->access_log != "off") {
        int log_fd = open(cfg->access_log.c_str(), O_WRONLY|O_CREAT|O_APPEND, 0755);
        if (log_fd < 0) {
            log_fatal_exit("unable to open log file: %s: %s",
                           cfg->access_log.c_str(), strerror(errno));
        }
        engine_state->access_log_file.set_fd(log_fd);
        engine_state->access_log_thread = log_thread_ptr(new log_thread(log_fd, cfg->log_buffers));
    }
    
    if (cfg->tls_cert_file.length() > 0 && cfg->tls_key_file.length() > 0)
    {
        SSL_library_init();
        SSL_load_error_strings();
        
        engine_state->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
        SSL_CTX_set_options(engine_state->ssl_ctx, SSL_OP_NO_SSLv2);
        SSL_CTX_set_options(engine_state->ssl_ctx, SSL_OP_NO_SSLv3);
        SSL_CTX_set_options(engine_state->ssl_ctx, SSL_OP_NO_COMPRESSION);
        
        if (SSL_CTX_use_certificate_file(engine_state->ssl_ctx,
                                         cfg->tls_cert_file.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_cb(log_tls_errors, NULL);
            log_fatal_exit("%s failed to load certificate: %s",
                           get_proto()->name.c_str(), cfg->tls_cert_file.c_str());
        } else {
            log_info("%s loaded cert: %s",
                     get_proto()->name.c_str(), cfg->tls_cert_file.c_str());
        }
        
        if (SSL_CTX_use_PrivateKey_file(engine_state->ssl_ctx,
                                        cfg->tls_key_file.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_cb(log_tls_errors, NULL);
            log_fatal_exit("%s failed to load private key: %s",
                           get_proto()->name.c_str(), cfg->tls_key_file.c_str());
        } else {
            log_info("%s loaded key: %s",
                     get_proto()->name.c_str(), cfg->tls_key_file.c_str());
        }
    }

    // create listening sockets for this protocol
    for (size_t i = 0; i < cfg->proto_listeners.size(); i++) {
        auto &proto_listener = cfg->proto_listeners[i];
        protocol *proto = std::get<0>(proto_listener);
        if (proto != get_proto()) continue;
        auto listener = std::get<1>(proto_listener);
        socket_mode mode = std::get<2>(proto_listener);
        if (mode == socket_mode_tls) {
            engine_state->listens.push_back(connected_socket_ptr(new tls_connected_socket()));
        } else {
            engine_state->listens.push_back(connected_socket_ptr(new tcp_connected_socket()));
        }
        auto &listen = engine_state->listens[i];
        if (listen->start_listening(listener->addr, cfg->listen_backlog)) {
            log_info("%s listening on: %s",
                     get_proto()->name.c_str(), listen->to_string().c_str());
        } else {
            log_fatal_exit("%s can't listen on: %s",
                           get_proto()->name.c_str(), listen->to_string().c_str());
        }
    }
}

void http_server::engine_shutdown(protocol_engine_delegate *delegate) const
{
    // shutdown listeners
    for (auto &listen : get_engine_state(delegate)->listens) {
        listen->close_connection();
    }
    
    // shutdown log thread
    log_thread_ptr access_log_thread = get_engine_state(delegate)->access_log_thread;
    if (access_log_thread) {
        access_log_thread->shutdown();
    }
}

void http_server::thread_init(protocol_thread_delegate *delegate) const
{
    if (delegate->get_thread_mask() & thread_mask_listener.mask) {
        for (auto &listen : get_engine_state(delegate)->listens) {
            // TODO - handle TLS listening sockets
            delegate->get_pollset()->add_object(poll_object(server_sock_tcp_listen.type,
                                                            listen.get(), listen->get_fd()), poll_event_in);
        }
    }
}

void http_server::thread_shutdown(protocol_thread_delegate *delegate) const
{
}

void http_server::handle_message(protocol_thread_delegate *delegate, protocol_message &msg) const
{
    auto http_conn = get_connection(delegate, msg.connection_num);
    auto &conn = http_conn->conn;
    auto action = (*protocol_action::get_table())[msg.action];
    
    conn.set_last_activity(delegate->get_current_time());
    if (delegate->get_debug_mask() & protocol_debug_message) {
        log_debug("%90s:%p: %s: message: %s",
                  delegate->get_thread_string().c_str(),
                  delegate->get_thread_id(),
                  http_conn->to_string().c_str(),
                  action->name.c_str());
    }
    action->callback(delegate, http_conn);
}

void http_server::handle_accept(protocol_thread_delegate *delegate, const protocol_sock *proto_sock, int listen_fd) const
{
    auto engine_state = get_engine_state(delegate);
    
    // accept new connections
    while (true) {
        int fd;
        struct sockaddr_storage addr;
        memset(&addr, 0, sizeof(sockaddr_storage));
        socklen_t addrlen = sizeof(sockaddr_storage);
        if ((fd = accept(listen_fd, (sockaddr*)&addr, &addrlen)) < 0) {
            if (errno == EAGAIN) return;
            log_error("%90s:%p: accept: %s",
                      delegate->get_thread_string().c_str(),
                      delegate->get_thread_id(),
                      strerror(errno));
            return;
        }
        
        // get a free connection
        auto http_conn = new_connection(delegate);
        if (http_conn == nullptr) {
            log_error("%90s:%p: accept: no free connections",
                      delegate->get_thread_string().c_str(),
                      delegate->get_thread_id());
            // TODO - queue accept
            close(fd);
            continue;
        }

        // find listen socket
        auto it = std::find_if(engine_state->listens.begin(), engine_state->listens.end(),
                               [listen_fd](const connected_socket_ptr& listen)
                               { return listen->get_fd() == listen_fd; });
        auto &listen = *it;

        // assign file descriptor
        auto &conn = http_conn->conn;
        // send connection to a router
        switch (listen->get_mode()) {
            case socket_mode_plain:
                conn.accept(fd);
                break;
            case socket_mode_tls:
                conn.accept_tls(fd, engine_state->ssl_ctx);
                break;
        }
        if (delegate->get_debug_mask() & protocol_debug_socket) {
            log_debug("%90s:%p: %s: accepted%s connection",
                      delegate->get_thread_string().c_str(),
                      delegate->get_thread_id(),
                      http_conn->to_string().c_str(),
                      listen->get_mode() == socket_mode_tls ? " tls" : "");
        }
        
        // copy local address into connection and get peer address
        memcpy(&conn.get_local_addr().storage, &addr, sizeof(sockaddr_storage));
        addrlen = sizeof(sockaddr_storage);
        if (getpeername(fd, (sockaddr*)&conn.get_peer_addr().storage, &addrlen) < 0) {
            log_error("%90s:%p: getpeername: %s",
                      delegate->get_thread_string().c_str(),
                      delegate->get_thread_id(),
                      strerror(errno));
        }
        
        get_engine_state(delegate)->stats.connections_accepted++;
        
        // send connection to a router
        switch (listen->get_mode()) {
            case socket_mode_plain:
                dispatch_connection(delegate, http_conn);
                break;
            case socket_mode_tls:
                dispatch_connection_tls(delegate, http_conn);
                break;
        }
    }
}

void http_server::handle_connection(protocol_thread_delegate *delegate, protocol_object *obj, int revents) const
{
    auto http_conn = static_cast<http_server_connection*>(obj);
    auto &conn = http_conn->conn;
    time_t current_time = delegate->get_current_time();
    
    if (revents & poll_event_hup) {
        if (delegate->get_debug_mask() & protocol_debug_socket) {
            int socket_error = conn.get_sock_error();
            log_debug("%90s:%p: %s: %s",
                      delegate->get_thread_string().c_str(),
                      delegate->get_thread_id(),
                      obj->to_string().c_str(),
                      socket_error ? strerror(socket_error) : "connection closed");
        }
        delegate->remove_events(http_conn);
        close_connection(delegate, http_conn);
        return;
    } else if (revents & poll_event_err) {
        if (delegate->get_debug_mask() & protocol_debug_socket) {
            log_debug("%90s:%p: %s: socket exception",
                      delegate->get_thread_string().c_str(),
                      delegate->get_thread_id(),
                      obj->to_string().c_str());
        }
        delegate->remove_events(http_conn);
        close_connection(delegate, http_conn);
        return;
    } else if (revents & poll_event_invalid) {
        if (delegate->get_debug_mask() & protocol_debug_socket) {
            log_debug("%90s:%p: %s: invalid socket",
                      delegate->get_thread_string().c_str(),
                      delegate->get_thread_id(),
                      obj->to_string().c_str());
        }
        delegate->remove_events(http_conn);
        close_connection(delegate, http_conn);
    } else {
        conn.set_last_activity(current_time);
        if (http_conn->state->callback) {
            http_conn->state->callback(delegate, obj);
        } else {
            log_error("%90s:%p: %s: invalid connection state: state=%d",
                      delegate->get_thread_string().c_str(),
                      delegate->get_thread_id(),
                      obj->to_string().c_str(),
                      http_conn->state);
            delegate->remove_events(http_conn);
            abort_connection(delegate, http_conn);
        }
    }
}

void http_server::timeout_connection(protocol_thread_delegate *delegate, protocol_object *obj) const
{
    auto http_conn = static_cast<http_server_connection*>(obj);
    auto &conn = http_conn->conn;
    auto cfg = delegate->get_config();
    time_t current_time = delegate->get_current_time();
    time_t last_activity = conn.get_last_activity();
    
    // timeout connections
    if (http_conn->state == &connection_state_free)
    {
        return;
    }
    else if (http_conn->state == &connection_state_client_request ||
             http_conn->state == &connection_state_client_body ||
             http_conn->state == &connection_state_server_response ||
             http_conn->state == &connection_state_server_body)
    {
        if (current_time - last_activity > cfg->connection_timeout) {
            if (delegate->get_debug_mask() & protocol_debug_timeout) {
                log_debug("%90s:%p: %s: inactivity timeout reached: aborting connection",
                          delegate->get_thread_string().c_str(),
                          delegate->get_thread_id(),
                          obj->to_string().c_str());
            }
            delegate->remove_events(http_conn);
            linger_connection(delegate, http_conn);
        }
    } else if (http_conn->state == &connection_state_lingering_close) {
        if (current_time - last_activity > cfg->connection_timeout) {
            if (delegate->get_debug_mask() & protocol_debug_timeout) {
                log_debug("%90s:%p: %s: inactivity timeout reached: aborting connection",
                          delegate->get_thread_string().c_str(),
                          delegate->get_thread_id(),
                          obj->to_string().c_str());
            }
            delegate->remove_events(http_conn);
            abort_connection(delegate, http_conn);
        }
    } else if (http_conn->state == &connection_state_waiting) {
        if (current_time - last_activity > cfg->keepalive_timeout) {
            if (delegate->get_debug_mask() & protocol_debug_timeout) {
                log_debug("%90s:%p: %s: keepalive timeout reached: closing connection",
                          delegate->get_thread_string().c_str(),
                          delegate->get_thread_id(),
                          obj->to_string().c_str());
            }
            delegate->remove_events(http_conn);
            close_connection(delegate, http_conn);
        }
    }
}


/* http_server state handlers */

void http_server::handle_state_tls_handshake(protocol_thread_delegate *delegate, protocol_object *obj)
{
    auto http_conn = static_cast<http_server_connection*>(obj);
    auto &conn = http_conn->conn;
    
    // TODO - implement SNI, retrieve servername in callback function
    // using SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)
    // and then call SSL_set_SSL_CTX to change to another SSL_CTX
    // Call the following in startup code to set up the callback function
    // SSL_CTX_set_tlsext_servername_callback(ctx, tls_servername_callback);
    // SSL_CTX_set_tlsext_servername_arg(ctx, &tls_servername_callback_arg);
    
    int ret = conn.sock->do_handshake();
    switch (ret) {
        case socket_error_none:
            if (delegate->get_debug_mask() & protocol_debug_tls)
            {
                int cipher_bits;
                const char *cipher_name, *cipher_version;
                SSL *ssl = static_cast<tls_connected_socket*>(conn.sock.get())->ssl;
                const SSL_CIPHER  *cipher = SSL_get_current_cipher(ssl);
                const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
                if (cipher) {
                    cipher_bits = SSL_CIPHER_get_bits(cipher, nullptr);
                    cipher_name = SSL_CIPHER_get_name(cipher);
                    cipher_version = SSL_CIPHER_get_version(cipher);
                    log_debug("%90s:%p: %s: tls cipher_name=%s cipher_version=%s cipher_bits=%d",
                              delegate->get_thread_string().c_str(),
                              delegate->get_thread_id(),
                              obj->to_string().c_str(),
                              cipher_name, cipher_version, cipher_bits);
                }
                if (servername) {
                    log_debug("%90s:%p: %s: tls servername=%s",
                              delegate->get_thread_string().c_str(),
                              delegate->get_thread_id(),
                              obj->to_string().c_str(),
                              servername);
                }
            }
            
            dispatch_connection(delegate, http_conn);
            break;
        case socket_error_want_write:
            delegate->add_events(http_conn, poll_event_out);
            break;
        case socket_error_want_read:
            delegate->add_events(http_conn, poll_event_in);
            break;
        default:
            log_debug("%90s:%p: %s: unknown tls handshake error %d: closing connection",
                      delegate->get_thread_string().c_str(),
                      delegate->get_thread_id(),
                      obj->to_string().c_str(), ret);
            delegate->remove_events(http_conn);
            close_connection(delegate, http_conn);
            break;
    }
}

void http_server::handle_state_client_request(protocol_thread_delegate *delegate, protocol_object *obj)
{
    auto http_conn = static_cast<http_server_connection*>(obj);
    auto &conn = http_conn->conn;
    auto &buffer = http_conn->buffer;
    
    // read request and request headers
    if (buffer.bytes_writable() <= 0) {
        log_error("%90s:%p: %s: header buffer full: aborting connection",
                  delegate->get_thread_string().c_str(),
                  delegate->get_thread_id(),
                  obj->to_string().c_str());
        delegate->remove_events(http_conn);
        abort_connection(delegate, http_conn); // TODO - bad request or lingering close?
        return;
    }
    io_result result = buffer.buffer_read(conn);
    if (result.has_error()) {
        log_error("%90s:%p: %s: read exception: aborting connection: %s",
                  delegate->get_thread_string().c_str(),
                  delegate->get_thread_id(),
                  obj->to_string().c_str(),
                  result.error_string().c_str());
        delegate->remove_events(http_conn);
        abort_connection(delegate, http_conn);
        return;
    }

    // Close connection if we get EOF reading headers
#if USE_RINGBUFFER
    if (result.size() == 0 && buffer.back == 0) {
#else
    if (result.size() == 0 && buffer.offset() == 0) {
#endif
        delegate->remove_events(http_conn);
        close_connection(delegate, http_conn);
        return;
    }
    
    // incrementally parse headers
#if USE_RINGBUFFER
    /* size_t bytes_parsed = */ http_conn->request.parse(buffer.data() + buffer.back - result.size(), result.size());
    buffer.front += result.size();
#else
    /* size_t bytes_parsed = */ http_conn->request.parse(buffer.data() + buffer.offset(), result.size());
    buffer.set_offset(buffer.offset() + result.size());
#endif
    
    // switch state if request processing is finished
    if (http_conn->request.is_finished()) {
        process_request_headers(delegate, http_conn);
        delegate->remove_events(http_conn);
        work_connection(delegate, http_conn);
    } else if (http_conn->request.has_error() || http_conn->request.is_finished()) {
        log_debug("%90s:%p: %s: header parse error: aborting connection",
                  delegate->get_thread_string().c_str(),
                  delegate->get_thread_id(),
                  obj->to_string().c_str());
        delegate->remove_events(http_conn);
        abort_connection(delegate, http_conn); // TODO - bad request or lingering close?
    }
}

void http_server::handle_state_client_body(protocol_thread_delegate *delegate, protocol_object *obj)
{
    auto http_conn = static_cast<http_server_connection*>(obj);
    
    // read request body e.g. POST
    io_result result = http_conn->handler->read_request_body();
    if (result.has_error()) {
        log_error("%90s:%p: %s: handler read_request_body failed: aborting connection: %s",
                  delegate->get_thread_string().c_str(),
                  delegate->get_thread_id(),
                  obj->to_string().c_str(),
                  result.error_string().c_str());
        delegate->remove_events(http_conn);
        abort_connection(delegate, http_conn); // TODO - bad request or lingering close?
    } else if (result.size() == 0) {
        populate_response_headers(delegate, http_conn);
        http_conn->state = &connection_state_server_response;
    }
}

void http_server::handle_state_server_response(protocol_thread_delegate *delegate, protocol_object *obj)
{
    auto http_conn = static_cast<http_server_connection*>(obj);
    auto &conn = http_conn->conn;
    auto &buffer = http_conn->buffer;

#if defined (USE_NOPUSH)
    if (http_conn->response_has_body) {
        conn.set_nopush(true);
    }
#endif
    
    // write response and response headers
    // TODO - if response has body then populate io_buffer and write in write_response_body
    io_result result = buffer.buffer_write(conn);
    if (result.has_error()) {
        log_error("%90s:%p: %s: write exception: aborting connection: %s",
                  delegate->get_thread_string().c_str(),
                  delegate->get_thread_id(),
                  obj->to_string().c_str(),
                  result.error_string().c_str());
        delegate->remove_events(http_conn);
        abort_connection(delegate, http_conn);
        return;
    }
    
    // if there is any response header data still to be written then
    // enter poll loop waiting for another poll_event_out event
    if (buffer.bytes_readable() > 0) {
        return;
    }
    
    // clear buffers
    buffer.reset();
#if defined (USE_NOPUSH) && defined (__APPLE__)
    // On darwin we turn off cork early
    // BSD BUG exists where clearing nopush doesn't cause a flush (present on latest Darwin)
    // On linux we can turn off cork at the end of the file body
    // TODO - writev or prepopulate output buffer to combine headers and body and use TCP_MAXSEG (TCP_MSS) sized writes
    if (http_conn->response_has_body) {
        conn.set_nopush(false);
    }
#endif
    
    // if response has a body then enter http_server_connection_state_server_body
    // otherwise end the request and close the connection or forward the
    // connection to the keepalive thread
    if (http_conn->response_has_body) {
        http_conn->state = &connection_state_server_body;
    } else {
        // BUG http_conn->handler can be null as handler can abort connection - revise handler interface to return errors
        if (!http_conn->handler->end_request()) {
            log_error("%90s:%p: %s: handler end_request failed: aborting connection",
                      delegate->get_thread_string().c_str(),
                      delegate->get_thread_id(),
                      obj->to_string().c_str());
            delegate->remove_events(http_conn);
            abort_connection(delegate, http_conn);
        } else if (http_conn->connection_close) {
            if (delegate->get_debug_mask() & protocol_debug_socket) {
                log_debug("%90s:%p: %s: closing connection",
                          delegate->get_thread_string().c_str(),
                          delegate->get_thread_id(),
                          obj->to_string().c_str());
            }
            get_engine_state(delegate)->stats.requests_processed++;
            delegate->remove_events(http_conn);
            close_connection(delegate, http_conn);
        } else {
            get_engine_state(delegate)->stats.requests_processed++;
            delegate->remove_events(http_conn);
            keepalive_connection(delegate, http_conn);
        }
    }
}

void http_server::handle_state_server_body(protocol_thread_delegate *delegate, protocol_object *obj)
{
    auto http_conn = static_cast<http_server_connection*>(obj);

    // write server response body and when finished close the connection
    // or forward the connection to the keepalive thread
    io_result result = http_conn->handler->write_response_body();
    if (result.has_error()) {
        log_error("%90s:%p: %s: handler write_response_body failed: aborting connection: %s",
                  delegate->get_thread_string().c_str(),
                  delegate->get_thread_id(),
                  obj->to_string().c_str(),
                  result.error_string().c_str());
        delegate->remove_events(http_conn);
        abort_connection(delegate, http_conn);
    } else if (result.size() == 0) {
        if (!http_conn->handler->end_request()) {
            log_error("%90s:%p: %s: handler end_request failed: aborting connection",
                      delegate->get_thread_string().c_str(),
                      delegate->get_thread_id(),
                      obj->to_string().c_str());
            delegate->remove_events(http_conn);
            abort_connection(delegate, http_conn);
        } else if (http_conn->connection_close) {
            if (delegate->get_debug_mask() & protocol_debug_socket) {
                log_debug("%90s:%p: %s: closing connection",
                          delegate->get_thread_string().c_str(),
                          delegate->get_thread_id(),
                          obj->to_string().c_str());
            }
            finished_request(delegate, obj);
            delegate->remove_events(http_conn);
            close_connection(delegate, http_conn);
        } else {
            finished_request(delegate, obj);
            delegate->remove_events(http_conn);
            keepalive_connection(delegate, http_conn);
        }
    }
}

void http_server::finished_request(protocol_thread_delegate *delegate, protocol_object *obj)
{
    auto engine_state = get_engine_state(delegate);
    engine_state->stats.requests_processed++;
    if (engine_state->access_log_thread)
    {
        char date_buf[32], addr_buf[32];
        char log_buffer[LOG_BUFFER_SIZE];
        
        // format date
        time_t current_time = delegate->get_current_time();
        http_date(current_time).to_log_string(date_buf, sizeof(date_buf));

        // format address
        auto http_conn = static_cast<http_server_connection*>(obj);
        socket_addr &addr = http_conn->conn.get_peer_addr();
        if (addr.saddr.sa_family == AF_INET) {
            inet_ntop(addr.saddr.sa_family, (void*)&addr.ip4addr.sin_addr, addr_buf, sizeof(addr_buf));
        }
        if (addr.saddr.sa_family == AF_INET6) {
            inet_ntop(addr.saddr.sa_family, (void*)&addr.ip6addr.sin6_addr, addr_buf, sizeof(addr_buf));
        }
        
        // format log message
        auto &request = http_conn->request;
        auto &response = http_conn->response;
        std::string user = "-"; // todo
        std::string request_method(request.request_method.data, request.request_method.length);
        std::string request_path(request.request_path.data, request.request_path.length);
        std::string http_version(request.http_version.data, request.http_version.length);
        int status_code = response.status_code;
        size_t bytes_transferred = 0; // todo
        snprintf(log_buffer, sizeof(log_buffer) - 1, "%s - %s %s \"%s %s %s\" %d %lu\n",
                 addr_buf, user.c_str(), date_buf, request_method.c_str(), request_path.c_str(),
                 http_version.c_str(), status_code, bytes_transferred);
        log_buffer[sizeof(log_buffer) - 1] = '\0';
        engine_state->access_log_thread->log(current_time, log_buffer);
    }
}
    
void http_server::handle_state_waiting(protocol_thread_delegate *delegate, protocol_object *obj)
{
    auto http_conn = static_cast<http_server_connection*>(obj);
    delegate->remove_events(http_conn);
    dispatch_connection(delegate, http_conn);
}

void http_server::handle_state_lingering_close(protocol_thread_delegate *delegate, protocol_object *obj)
{
    auto http_conn = static_cast<http_server_connection*>(obj);
    auto &conn = http_conn->conn;
    auto &buffer = http_conn->buffer;

    buffer.reset();
    io_result result = buffer.buffer_read(conn);
    if (result.has_error()) {
        delegate->remove_events(http_conn);
        close_connection(delegate, http_conn);
    }
}

/* http_server messages */

void http_server::router_tls_handshake(protocol_thread_delegate *delegate, protocol_object *obj)
{
    auto http_conn = static_cast<http_server_connection*>(obj);
    
    http_conn->state = &connection_state_tls_handshake;
    delegate->add_events(obj, poll_event_in);
}

void http_server::router_process_headers(protocol_thread_delegate *delegate, protocol_object *obj)
{
    auto http_conn = static_cast<http_server_connection*>(obj);

    http_conn->request.reset();
    http_conn->state = &connection_state_client_request;
    delegate->add_events(obj, poll_event_in);
}

void http_server::keepalive_wait_connection(protocol_thread_delegate *delegate, protocol_object *obj)
{
    auto http_conn = static_cast<http_server_connection*>(obj);

    http_conn->state = &connection_state_waiting;
    delegate->add_events(obj, poll_event_in);
}

void http_server::worker_process_request(protocol_thread_delegate *delegate, protocol_object *obj)
{
    auto http_conn = static_cast<http_server_connection*>(obj);
    auto &buffer = http_conn->buffer;
    time_t current_time = delegate->get_current_time();
    char date_buf[32];
    
    // start request processing
    http_conn->response.reset();
    http_conn->response.set_http_version(kHTTPVersion11);
    http_conn->response.set_header_field(kHTTPHeaderServer, format_string("%s/%s", ServerName, ServerVersion));
    http_conn->response.set_header_field(kHTTPHeaderDate, http_date(current_time).to_header_string(date_buf, sizeof(date_buf)));
    http_conn->handler = get_engine_state(delegate)->lookup_handler(http_conn);
    http_conn->handler->init();
    http_conn->handler->set_delegate(delegate);
    http_conn->handler->set_connection(http_conn);
    http_conn->handler->set_current_time(current_time);
    if (!http_conn->handler->handle_request()) {
        log_debug("%90s:%p: %s: request handler failed",
                  delegate->get_thread_string().c_str(),
                  delegate->get_thread_id(),
                  obj->to_string().c_str());
        abort_connection(delegate, http_conn);
    } else if (http_conn->request_has_body) {
        // copy body fragment to start of buffer
        // Note: body_start is stored in the io_buffer not the header_buffer so this results in a memmove
        buffer.set(http_conn->request.body_start.data, http_conn->request.body_start.length);
        http_conn->state = &connection_state_client_body;
        delegate->add_events(obj, poll_event_in);
    } else if (populate_response_headers(delegate, http_conn) > 0) {
        http_conn->state = &connection_state_server_response;
        delegate->add_events(obj, poll_event_out);
    } else {
        log_debug("%90s:%p: %s: response buffer full",
                  delegate->get_thread_string().c_str(),
                  delegate->get_thread_id(),
                  obj->to_string().c_str());
        abort_connection(delegate, http_conn);
    }
}

void http_server::linger_read_connection(protocol_thread_delegate *delegate, protocol_object *obj)
{
    auto http_conn = static_cast<http_server_connection*>(obj);
    auto &conn = http_conn->conn;
    
    http_conn->state = &connection_state_lingering_close;
    conn.start_lingering_close();
    delegate->add_events(obj, poll_event_in);
}

/* http_server internal */

void http_server::process_request_headers(protocol_thread_delegate *delegate, protocol_object *obj)
{
    auto http_conn = static_cast<http_server_connection*>(obj);
    
    // sanitize the request path
    // TODO - correctly handle canonical unescaping before sanitizing path
    // TODO - detect proxy requests
    // TODO - null check on request path dereference
    // TODO - handle authorization
    int ret = http_common::sanitize_path(const_cast<char*>(http_conn->request.request_path.data));
    if (ret < 0) {
        log_error("%90s:%p: %s: TODO - send bad request error",
                  delegate->get_thread_string().c_str(),
                  delegate->get_thread_id(),
                  obj->to_string().c_str());
        delegate->remove_events(http_conn);
        abort_connection(delegate, http_conn); // TODO - bad request or lingering close?
    }
    
    // debug request
    if (delegate->get_debug_mask() & protocol_debug_headers) {
        printf("%s", http_conn->request.to_string().c_str());
    }
}

ssize_t http_server::populate_response_headers(protocol_thread_delegate *delegate, protocol_object *obj)
{
    auto http_conn = static_cast<http_server_connection*>(obj);
    auto &buffer = http_conn->buffer;
    
    if (!http_conn->handler->populate_response()) {
        abort_connection(delegate, http_conn);
    }
    
    // copy headers to io buffer
    buffer.reset();
    ssize_t length = http_conn->response.to_buffer(buffer.data(), buffer.size());
    
    // check headers fit into available buffer space
    if (length < 0) {
        log_error("%90s:%p: %s: header buffer overflow",
                  delegate->get_thread_string().c_str(),
                  delegate->get_thread_id(),
                  obj->to_string().c_str());
        // TODO - send internal error
        delegate->remove_events(http_conn);
        abort_connection(delegate, http_conn);
        return length;
    }
#if USE_RINGBUFFER
    buffer.back = length;
#else
    buffer.set_length(length);
#endif
    
    // debug response
    if (delegate->get_debug_mask() & protocol_debug_headers) {
        printf("%s", http_conn->response.to_string().c_str());
    }

    return length;
}

void http_server::dispatch_connection(protocol_thread_delegate *delegate, protocol_object *obj)
{
    forward_connection(delegate, obj, thread_mask_router, action_router_process_headers);
}

void http_server::dispatch_connection_tls(protocol_thread_delegate *delegate, protocol_object *obj)
{
    forward_connection(delegate, obj, thread_mask_router, action_router_tls_handshake);
}

void http_server::work_connection(protocol_thread_delegate *delegate, protocol_object *obj)
{
    forward_connection(delegate, obj, thread_mask_worker, action_worker_process_request);
}

void http_server::keepalive_connection(protocol_thread_delegate *delegate, protocol_object *obj)
{
    auto http_conn = static_cast<http_server_connection*>(obj);
    auto &conn = http_conn->conn;
    auto &buffer = http_conn->buffer;
    
    buffer.reset();
#if defined (USE_NODELAY)
    // force socket to send data instead of waiting (Nagle algorithm)
    conn.set_nodelay(true);
#endif
    
#if defined (USE_NOPUSH) && !defined (__APPLE__)
    // Turn off cork at the end of the file body (except on Dawrin)
    // BSD BUG exists where clearing nopush doesn't cause a flush (present on latest Darwin)
    // TODO - detect versions of BSD where clearing NOPUSH doens't cause a flush
    // TODO - writev or prepopulate output buffer to combine headers and body and use TCP_MAXSEG (TCP_MSS) sized writes
    if (http_conn->response_has_body) {
        conn.set_nopush(false);
    }
#endif
    
    get_engine_state(delegate)->stats.connections_keepalive++;
    forward_connection(delegate, obj, thread_mask_keepalive, action_keepalive_wait_connection);
}

void http_server::linger_connection(protocol_thread_delegate *delegate, protocol_object *obj)
{
    get_engine_state(delegate)->stats.connections_linger++;
    forward_connection(delegate, obj, thread_mask_linger, action_linger_read_connection);
}

void http_server::forward_connection(protocol_thread_delegate* delegate, protocol_object *obj, const protocol_mask &proto_mask, const protocol_action &proto_action)
{
    auto http_conn = static_cast<http_server_connection*>(obj);
    auto &conn = http_conn->conn;
    
    protocol_thread_delegate *destination_thread = delegate->choose_thread(proto_mask.mask);
    if (destination_thread) {
        delegate->send_message(destination_thread, protocol_message(proto_action.action, conn.get_id()));
    } else {
        log_error("%90s:%p: %s: no thread avaiable: %",
                  delegate->get_thread_string().c_str(),
                  delegate->get_thread_id(),
                  obj->to_string().c_str(),
                  proto_mask.name.c_str());
        abort_connection(delegate, http_conn);
    }
}

http_server_connection* http_server::new_connection(protocol_thread_delegate *delegate)
{
    return get_engine_state(delegate)->new_connection(delegate->get_engine_delegate());
}

http_server_connection* http_server::get_connection(protocol_thread_delegate *delegate, int conn_id)
{
    return get_engine_state(delegate)->get_connection(delegate->get_engine_delegate(), conn_id);
}

void http_server::abort_connection(protocol_thread_delegate *delegate, protocol_object *obj)
{
    get_engine_state(delegate)->stats.connections_aborted++;
    get_engine_state(delegate)->abort_connection(delegate->get_engine_delegate(), obj);
}

void http_server::close_connection(protocol_thread_delegate *delegate, protocol_object *obj)
{
    get_engine_state(delegate)->stats.connections_closed++;
    get_engine_state(delegate)->close_connection(delegate->get_engine_delegate(), obj);
}

http_server_handler_ptr http_server_engine_state::lookup_handler(http_server_connection *http_conn)
{
    // find longest match
    std::string path = http_conn->request.get_request_path();
    ssize_t best_offset = -1;
    http_server_handler_info_ptr *best_match = nullptr;
    for (auto &handler_info : handler_list) {
        ssize_t i = 0;
        while (i < (ssize_t)path.length() &&
               i < (ssize_t)handler_info->path.length() &&
               path[i] == handler_info->path[i]) i++;
        if (i > best_offset) {
            best_offset = i;
            best_match = &handler_info;
        }
    }
    // return best match, or if no match, the default file handler
    if (best_match) {
        return (*best_match)->factory->new_handler();
    } else {
        return std::make_shared<http_server_handler_file>();
    }
}

void http_server_engine_state::bind_function(std::string path, typename http_server::function_type fn)
{
    std::string handler_name = std::string("bind_function(") + path + std::string(")");
    http_server_handler_factory_ptr factory(new http_server_handler_factory_func(handler_name, fn));
    handler_list.push_back(http_server_handler_info_ptr(new http_server_handler_info(path, factory)));
}
