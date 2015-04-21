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
#include "http_tls_shared.h"
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


/* http_server_config */

http_server_config::http_server_config()
{
    http_server::get_proto();
    
    block_start_fn_map["http_server"] =     {1, 1, nullptr, [&] (config *cfg, config_line &line) {
        current_vhost = std::make_shared<http_server_vhost>(cfg->get_config<http_server>());
        vhost_list.push_back(current_vhost);
    }};
    block_start_fn_map["location"] =        {2, 2, "http_server", [&] (config *cfg, config_line &line) {
        current_location = std::make_shared<http_server_location>(current_vhost.get());
        current_location->uri = line[1];
        current_vhost->location_list.push_back(current_location);
    }};
    block_end_fn_map["http_server"] =       {0, 0, nullptr, [&] (config *cfg, config_line &line) {
        if (current_vhost->location_list.size() == 0) {
            log_fatal_exit("configuration error: http_server must contain one or more \"location\" directives");
        }
        current_vhost = http_server_vhost_ptr();
    }};
    block_end_fn_map["location"] =          {0, 0, nullptr, [&] (config *cfg, config_line &line) {
        if (current_location->root.length() == 0 && current_location->handler.length() == 0) {
            log_fatal_exit("configuration error: location \"%s\" must contain \"root\" and or \"handler\" directives", line[0].c_str());
        }
        current_location = http_server_location_ptr();
    }};

    config_fn_map["error_log"] =           {2,  2,  [&] (config *cfg, config_line &line) {
        if (cfg->block.size() == 0) {
            cfg->error_log = line[1];
        } else if (cfg->block.size() > 0 && cfg->block.back()[0] == "http_server") {
            current_vhost->error_log = line[1];
        } else {
            log_fatal_exit("configuration error: error_log must be defined at the toplevel or in a http_server block", line[0].c_str());
        }
    }};
    config_fn_map["access_log"] =          {2,  2,  [&] (config *cfg, config_line &line) {
        if (cfg->block.size() == 0) {
            cfg->access_log = line[1];
        } else if (cfg->block.size() > 0 && cfg->block.back()[0] == "http_server") {
            current_vhost->access_log = line[1];
        } else {
            log_fatal_exit("configuration error: access_log must be defined at the toplevel or in a http_server block", line[0].c_str());
        }
    }};
    config_fn_map["tls_key_file"] =        {2,  2,  [&] (config *cfg, config_line &line) {
        if (cfg->block.size() == 0) {
            cfg->tls_key_file = line[1];
        } else if (cfg->block.size() > 0 && cfg->block.back()[0] == "http_server") {
            current_vhost->tls_key_file = line[1];
        } else {
            log_fatal_exit("configuration error: tls_key_file must be defined at the toplevel or in a http_server block", line[0].c_str());
        }
    }};
    config_fn_map["tls_cert_file"] =       {2,  2,  [&] (config *cfg, config_line &line) {
        if (cfg->block.size() == 0) {
            cfg->tls_cert_file = line[1];
        } else if (cfg->block.size() > 0 && cfg->block.back()[0] == "http_server") {
            current_vhost->tls_cert_file = line[1];
        } else {
            log_fatal_exit("configuration error: tls_cert_file must be defined at the toplevel or in a http_server block", line[0].c_str());
        }
    }};
    config_fn_map["tls_cipher_list"] =       {2,  2,  [&] (config *cfg, config_line &line) {
        if (cfg->block.size() == 0) {
            cfg->tls_cipher_list = line[1];
        } else if (cfg->block.size() > 0 && cfg->block.back()[0] == "http_server") {
            current_vhost->tls_cipher_list = line[1];
        } else {
            log_fatal_exit("configuration error: tls_cipher_list must be defined at the toplevel or in a http_server block", line[0].c_str());
        }
    }};
    config_fn_map["listen"] =               {2,  3,  [&] (config *cfg, config_line &line) {
        if (cfg->block.size() > 0 && cfg->block.back()[0] == "http_server") {
            socket_addr addr;
            if (socket_addr::string_to_addr(line[1], addr) < 0) {
                log_fatal_exit("configuration error: proto_listener: invalid address: %s", line[1].c_str());
            }
            if (line.size() == 3) {
                if (line[2] != "tls") {
                    log_fatal_exit("configuration error: proto_listener: invalid option: %s", line[2].c_str());
                }
                current_vhost->listens.push_back(http_server_listen_spec(addr, socket_mode_tls));
            } else {
                current_vhost->listens.push_back(http_server_listen_spec(addr, socket_mode_plain));
            }
        } else {
            log_fatal_exit("configuration error: listen must be defined at the toplevel or in a http_server block", line[0].c_str());
        }
    }};
    config_fn_map["server_name"] =          {2,  -1,  [&] (config *cfg, config_line &line) {
        if (cfg->block.size() > 0 && cfg->block.back()[0] == "http_server") {
            for (size_t i = 1; i < line.size(); i++) {
                auto &server_names = current_vhost->server_names;
                if (std::find(server_names.begin(), server_names.end(), line[i]) == server_names.end()) {
                    server_names.push_back(line[i]);
                }
            }
        } else {
            log_fatal_exit("configuration error: server_name must be defined at the toplevel or in a http_server block", line[0].c_str());
        }
    }};
    config_fn_map["root"] =                 {2,  2,  [&] (config *cfg, config_line &line) {
        if (cfg->block.size() == 0) {
            cfg->root = line[1];
        } else if (cfg->block.size() > 0 && cfg->block.back()[0] == "location") {
            current_location->root = line[1];
        } else {
            log_fatal_exit("configuration error: root must be defined at the toplevel or in a location block", line[0].c_str());
        }
    }};
    config_fn_map["index"] =                {2,  -1,  [&] (config *cfg, config_line &line) {
        if (cfg->block.size() == 0) {
            auto &index_files = cfg->index_files;
            for (size_t i = 1; i < line.size(); i++) {
                if (std::find(index_files.begin(), index_files.end(), line[i]) == index_files.end()) {
                    index_files.push_back(line[i]);
                }
            }
        } else if (cfg->block.size() > 0 && cfg->block.back()[0] == "location") {
            for (size_t i = 1; i < line.size(); i++) {
                auto &index_files = current_location->index_files;
                if (std::find(index_files.begin(), index_files.end(), line[i]) == index_files.end()) {
                    index_files.push_back(line[i]);
                }
            }
        } else {
            log_fatal_exit("configuration error: index must be defined at the toplevel or in a location block", line[0].c_str());
        }
    }};
    config_fn_map["handler"] =              {2,  2,  [&] (config *cfg, config_line &line) {
        if (cfg->block.size() > 0 && cfg->block.back()[0] == "location") {
            current_location->handler = line[1];
        } else {
            log_fatal_exit("configuration error: handler must be defined at the toplevel or in a location block", line[0].c_str());
        }
    }};
}

std::string http_server_config::to_string()
{
    std::stringstream ss;
    // todo
    return ss.str();
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
        http_server_handler_file::init_handler();
        http_server_handler_stats::init_handler();
    });
}

void http_server::make_default_config(config_ptr cfg) const
{
    static const char* ipv4_localhost_addr = "127.0.0.1:8080";
    static const char* ipv6_localhost_addr = "[]:8080";
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
    cfg->tls_session_timeout = TLS_SESSION_TIMEOUT_DEFAULT;
    cfg->tls_session_count = TLS_SESSION_COUNT_DEFAULT;
    socket_addr ipv4_localhost;
    if (socket_addr::string_to_addr(ipv4_localhost_addr, ipv4_localhost) < 0) {
        log_error("configuration error: unable to decode address: %s", ipv4_localhost);
    } else {
        cfg->proto_listeners.push_back(std::tuple<protocol*,socket_addr,socket_mode>
                                       (http_server::get_proto(), ipv4_localhost, socket_mode_plain));
    }
    socket_addr ipv6_localhost;
    if (socket_addr::string_to_addr(ipv6_localhost_addr, ipv6_localhost) < 0) {
        log_error("configuration error: unable to decode address: %s", ipv6_localhost);
    } else {
        cfg->proto_listeners.push_back(std::tuple<protocol*,socket_addr,socket_mode>
                                       (http_server::get_proto(), ipv6_localhost, socket_mode_plain));
    }
    cfg->proto_threads.push_back(std::pair<std::string,size_t>("http_server/listener", 1));
    cfg->proto_threads.push_back(std::pair<std::string,size_t>("http_server/router,http_server/worker,http_server/keepalive,http_server/linger", std::thread::hardware_concurrency()));
    cfg->root = "html";
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
    
    make_default_vhost(cfg);
}

void http_server::make_default_vhost(config_ptr cfg) const
{
    // configure default virtual host
    auto server_cfg = cfg->get_config<http_server>();
    auto default_vhost = std::make_shared<http_server_vhost>(server_cfg);
    default_vhost->server_names.push_back("default");
    server_cfg->vhost_list.push_back(default_vhost);

    // configure default locations
    auto default_location = std::make_shared<http_server_location>(default_vhost.get());
    default_location->uri = "/";
    default_location->root = cfg->root;
    default_location->handler = "file";
    default_location->index_files.push_back("index.html");
    default_location->index_files.push_back("index.htm");
    default_vhost->location_list.push_back(default_location);

    // configure default locations
    auto stats_location = std::make_shared<http_server_location>(default_vhost.get());
    stats_location->uri = "/stats/";
    stats_location->handler = "stats";
    default_vhost->location_list.push_back(stats_location);
}

protocol_config_ptr http_server::make_protocol_config() const
{
    return protocol_config_ptr(new http_server_config());
}

http_server_engine_state* http_server::get_engine_state(protocol_thread_delegate *delegate) {
    return static_cast<http_server_engine_state*>(delegate->get_engine_delegate()->get_engine_state(get_proto()));
}

http_server_engine_state* http_server::get_engine_state(protocol_engine_delegate *delegate) {
    return static_cast<http_server_engine_state*>(delegate->get_engine_state(get_proto()));
}

protocol_engine_state* http_server::create_engine_state(config_ptr cfg) const
{
    return new http_server_engine_state(cfg);
}

protocol_thread_state* http_server::create_thread_state(config_ptr cfg) const
{
    return new http_server_thread_state(cfg);
}

void http_server::engine_init(protocol_engine_delegate *delegate) const
{
    // get config
    auto cfg = delegate->get_config();
    auto engine_state = get_engine_state(delegate);
    auto server_cfg = cfg->get_config<http_server>();
    
    // check if we have a vhost with the server_name "default"
    bool found_default_vhost = false;
    for (auto &vhost : server_cfg->vhost_list) {
        auto si = std::find(vhost->server_names.begin(), vhost->server_names.end(), "default");
        if (si != vhost->server_names.end()) {
            found_default_vhost = true;
            break;
        }
    }
    // if there are no vhosts, then create "default" vhost using top level root
    if (server_cfg->vhost_list.size() == 0) {
        if (!found_default_vhost) {
            if (cfg->root.length() > 0) {
                make_default_vhost(cfg);
            } else {
                log_fatal_exit("configuration error: no http_server with server_name default and no toplevel root directive defined");
            }
        }
    }
    // otherwise label the first vhost as default
    else if (!found_default_vhost) {
        server_cfg->vhost_list[0]->server_names.push_back("default");
    }

    // initialize virtual hosts
    for (auto &vhost : server_cfg->vhost_list) {
        for (auto &location : vhost->location_list) {
            if (!location->handler_factory) {
                std::string handler_name;
                if (location->handler.length() == 0) {
                    location->handler = "file";
                    handler_name = "http_server_handler_file";
                } else {
                    handler_name = std::string("http_server_handler_") + location->handler;
                }
                auto fi = handler_factory_map.find(handler_name);
                if (fi == handler_factory_map.end()) {
                    log_error("%s couldn't find handler factory: %s", get_proto()->name.c_str(), handler_name.c_str());
                } else {
                    location->handler_factory = fi->second;
                }
            }
            vhost->location_trie.insert(location->uri, location.get());
        }
        for (auto &server_name : vhost->server_names) {
            server_cfg->vhost_map.insert(http_server_vhost_entry(server_name, vhost.get()));
        }
        for (auto &listen : vhost->listens) {
            auto proto_listen = std::tuple<protocol*,socket_addr,socket_mode>(get_proto(), listen.first, listen.second);
            auto &proto_listeners = cfg->proto_listeners;
            if (std::find(proto_listeners.begin(), proto_listeners.end(), proto_listen) == proto_listeners.end()) {
                proto_listeners.push_back(proto_listen);
            }
        }
        // set defaults from root context
        if (vhost->tls_key_file.length() == 0) {
            vhost->tls_key_file = cfg->tls_key_file;
        }
        if (vhost->tls_cert_file.length() == 0) {
            vhost->tls_cert_file = cfg->tls_cert_file;
        }
        if (vhost->tls_cipher_list.length() == 0) {
            vhost->tls_cipher_list = cfg->tls_cipher_list;
        }
        if (vhost->access_log.length() == 0) {
            vhost->access_log = cfg->access_log;
        }
        if (vhost->error_log.length() == 0) {
            vhost->error_log = cfg->access_log;
        }
        // open log files
        if (vhost->access_log.size() > 0 && vhost->access_log != "off") {
            int log_fd = open(vhost->access_log.c_str(), O_WRONLY|O_CREAT|O_APPEND, 0755);
            if (log_fd < 0) {
                log_fatal_exit("unable to open log file: %s: %s",
                               vhost->access_log.c_str(), strerror(errno));
            } else {
                log_info("opened access log file: %s", vhost->access_log.c_str());
            }
            vhost->access_log_file.set_fd(log_fd);
            vhost->access_log_thread = log_thread_ptr(new log_thread(log_fd, cfg->log_buffers));
        }
        if (vhost->error_log.size() > 0 && vhost->error_log != "off") {
            int log_fd = open(vhost->error_log.c_str(), O_WRONLY|O_CREAT|O_APPEND, 0755);
            if (log_fd < 0) {
                log_fatal_exit("unable to open log file: %s: %s",
                               vhost->error_log.c_str(), strerror(errno));
            } else {
                log_info("opened error log file: %s", vhost->error_log.c_str());
            }
            vhost->error_log_file.set_fd(log_fd);
            vhost->error_log_thread = log_thread_ptr(new log_thread(log_fd, cfg->log_buffers));
        }
    }

    // initialize connection table
    engine_state->init(delegate, cfg->server_connections);

    // check for TLS listening sockets
    bool have_tls = false;
    for (size_t i = 0; i < cfg->proto_listeners.size(); i++) {
        auto &proto_listener = cfg->proto_listeners[i];
        protocol *proto = std::get<0>(proto_listener);
        if (proto != get_proto()) continue;
        socket_mode mode = std::get<2>(proto_listener);
        if (mode == socket_mode_tls) {
            have_tls = true;
            break;
        }
    }

    // initialize TLS context
    if (have_tls) {
        engine_state->root_ssl_ctx = http_tls_shared::init_server(get_proto(), cfg);
    }

    // create listening sockets for this protocol
    for (size_t i = 0; i < cfg->proto_listeners.size(); i++) {
        auto &proto_listener = cfg->proto_listeners[i];
        protocol *proto = std::get<0>(proto_listener);
        if (proto != get_proto()) continue;
        socket_addr addr = std::get<1>(proto_listener);
        socket_mode mode = std::get<2>(proto_listener);
        if (mode == socket_mode_tls) {
            engine_state->listens.push_back(connected_socket_ptr(new tls_connected_socket()));
        } else {
            engine_state->listens.push_back(connected_socket_ptr(new tcp_connected_socket()));
        }
        auto &listen = engine_state->listens[i];
        if (listen->start_listening(addr, cfg->listen_backlog)) {
            log_info("%s listening on: %s%s",
                     get_proto()->name.c_str(), listen->to_string().c_str(),
                     (mode == socket_mode_tls ? " tls" : ""));
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
    
    // shutdown log threads
    auto cfg = delegate->get_config();
    auto server_cfg = cfg->get_config<http_server>();
    for (auto vhost : server_cfg->vhost_list) {
        if (vhost->access_log_thread) {
            vhost->access_log_thread->shutdown();
        }
        if (vhost->error_log_thread) {
            vhost->error_log_thread->shutdown();
        }
    }
}

void http_server::thread_init(protocol_thread_delegate *delegate) const
{
    if (delegate->get_thread_mask() & thread_mask_listener.mask) {
        for (auto &listen : get_engine_state(delegate)->listens) {
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
        switch (listen->get_mode()) {
            case socket_mode_plain:
                conn.accept(fd);
                break;
            case socket_mode_tls:
                conn.accept_tls(fd, engine_state->root_ssl_ctx);
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
        memcpy(&conn.get_peer_addr().storage, &addr, sizeof(sockaddr_storage));
        addrlen = sizeof(sockaddr_storage);
        if (getsockname(fd, (sockaddr*)&conn.get_local_addr().storage, &addrlen) < 0) {
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
        if (!process_request_headers(delegate, http_conn)) {
            delegate->remove_events(http_conn);
            abort_connection(delegate, http_conn); // TODO - bad request or lingering close?
        } else {
            delegate->remove_events(http_conn);
            work_connection(delegate, http_conn);
        }
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

    auto http_conn = static_cast<http_server_connection*>(obj);
    if (http_conn->handler && http_conn->handler->vhost && http_conn->handler->vhost->access_log_thread)
    {
        auto &access_log_thread = http_conn->handler->vhost->access_log_thread;
        
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
        access_log_thread->log(current_time, log_buffer);
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
    http_conn->handler = translate_path(delegate, http_conn);
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

bool http_server::process_request_headers(protocol_thread_delegate *delegate, protocol_object *obj)
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
        return false;
    }
    
    // debug request
    if (delegate->get_debug_mask() & protocol_debug_headers) {
        printf("%s", http_conn->request.to_string().c_str());
    }
    return true;
}

http_server_handler_ptr http_server::translate_path(protocol_thread_delegate *delegate, http_server_connection *http_conn)
{
    // TODO - unescape path
    // TODO - valid root path exists in config
    // TODO - handle canonical unescaping of path
    // TODO - windows LFN http://support.microsoft.com/kb/142982 GetShortPathName
    // TODO - windows forks using : or ::$DATA (alternate name for main fork)
    // TODO - case insensitive filesystems
    
    http_server_handler_ptr handler;
    auto cfg = delegate->get_config();
    auto server_cfg = cfg->get_config<http_server>();
    const char* request_path = http_conn->request.get_request_path();
    const char* host_header = http_conn->request.get_header_string(kHTTPHeaderHost);
    int host_port = socket_addr::port(http_conn->conn.get_local_addr());
    
    if (!host_header) host_header = "default";
    auto vi = server_cfg->vhost_map.find(host_header);
    if (vi == server_cfg->vhost_map.end()) {
        vi = server_cfg->vhost_map.find("default");
    }
    
    if (vi != server_cfg->vhost_map.end()) {
        auto vhost = vi->second;
        auto lp = vhost->location_trie.find_nearest(request_path);
        auto prefix = lp.first;
        auto location = lp.second;
        auto root = location->root;
        std::string partial_path = request_path + prefix.length();
        std::string path_translated;
        if (root.length() > 0 && root[root.length() - 1] != '/' && partial_path[0] != '/') {
            path_translated = root + "/" + partial_path;
        } else {
            path_translated = root + partial_path;
        }
        handler = location->handler_factory->new_handler();
        handler->vhost = vhost;
        handler->location = location;
        handler->path_translated = path_translated;
        if (delegate->get_debug_mask() & protocol_debug_handler) {
            log_debug("vhost=%s host_header=%s host_port=%d root=%s path_translated=%s",
                      vhost->server_names[0].c_str(), host_header, host_port, root.c_str(), handler->path_translated.c_str());
        }
    } else {
        log_fatal_exit("%s: default virtual host not found", get_proto());
    }
    
    return handler;
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

void http_server_engine_state::bind_function(config_ptr cfg, std::string path, typename http_server::function_type fn)
{
    auto server_cfg = cfg->get_config<http_server>();
    if (server_cfg->vhost_list.size() == 0) {
        log_fatal_exit("%s: no vhosts defined", __func__);
    }
    auto default_vhost = server_cfg->vhost_list[0];
    
    // bind function to location in default vhost
    std::string handler_name = std::string("bind_function(") + path + std::string(")");
    auto bind_location = std::make_shared<http_server_location>(default_vhost.get());
    bind_location->uri = path;
    bind_location->root = cfg->root;
    bind_location->handler = handler_name;
    bind_location->handler_factory = http_server_handler_factory_ptr(new http_server_handler_factory_func(handler_name, fn));
    default_vhost->location_list.push_back(bind_location);
}
