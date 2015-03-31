//
//  netb.cc
//

#include "latypus.h"

/* netb */

#define NUM_REQUESTS_DEFAULT        1
#define KEEPALIVE_REQUESTS_DEFAULT  0

#define expand(s) quote(s)
#define quote(s) #s

using namespace std::chrono;

struct netb
{
    static cmdline_option options[];
    
    protocol_engine engine;
    
    std::atomic<int>    processed_requests;
    std::atomic<size_t> bytes_transfered;
    int                 client_connections;
    int                 connection_timeout;
    int                 keepalive_requests;
    int                 keepalive_timeout;
    int                 header_buffer_size;
    int                 io_buffer_size;
    int                 num_requests;
    int                 num_threads;
    bool                per_request_stats;
    bool                help_or_error;
    int                 debug_level;
    std::string         bench_url;

    netb();
    bool process_cmdline(int argc, const char *argv[]);
    void run();
};

struct netb_client_handler_file : http_client_handler_file
{
    netb *client;
    std::chrono::high_resolution_clock::time_point t1;
    std::chrono::high_resolution_clock::time_point t2;
    
    netb_client_handler_file(netb *client) : client(client) {}
    
    void init();
    bool end_request();
};

void netb_client_handler_file::init()
{
    t1 = high_resolution_clock::now();
    http_client_handler_file::init();
}

bool netb_client_handler_file::end_request()
{
    http_client_handler_file::end_request();
    t2 = high_resolution_clock::now();
    client->processed_requests++;
    client->bytes_transfered += total_read;
    double secs = duration_cast<microseconds>(t2 - t1).count() / 1000000.0;
    if (client->per_request_stats) {
        printf("%9.6lf secs,  %ld bytes transferred,  %lf MB/sec\n",
               secs,
               total_read,
               total_read / secs / (1 << 20));
    }
    if (client->processed_requests == client->num_requests) {
        client->engine.stop();
    }
    return true;
}

netb::netb() :
    processed_requests(0),
    bytes_transfered(0),
    client_connections(CLIENT_CONNECTIONS_DEFAULT),
    connection_timeout(CONNETION_TIMEOUT_DEFAULT),
    keepalive_requests(KEEPALIVE_REQUESTS_DEFAULT),
    keepalive_timeout(KEEPALIVE_TIMEOUT_DEFAULT),
    header_buffer_size(HEADER_BUFFER_SIZE_DEFAULT),
    io_buffer_size(IO_BUFFER_SIZE_DEFAULT),
    num_requests(NUM_REQUESTS_DEFAULT),
    num_threads(std::thread::hardware_concurrency()),
    per_request_stats(false),
    help_or_error(false),
    debug_level(0)
{}

bool netb::process_cmdline(int argc, const char *argv[])
{
    cmdline_option options[] =
    {
        { "-c", "--client-connections", cmdline_arg_type_int,
            "Maximum number of connections (default " expand(CLIENT_CONNECTIONS_DEFAULT) ")",
            [&](std::string s) { client_connections = atoi(s.c_str()); return true; } },
        { "-C", "--connection-timeout", cmdline_arg_type_int,
            "Connection timeout seconds (default " expand(CONNETION_TIMEOUT_DEFAULT) ")",
            [&](std::string s) { connection_timeout = atoi(s.c_str()); return true; } },
        { "-d", "--debug", cmdline_arg_type_none,
            "Increase debugging information",
            [&](std::string s) { ++debug_level; return true; } },
        { "-h", "--help", cmdline_arg_type_none,
            "Show help",
            [&](std::string s) { return (help_or_error = true); } },
        { "-k", "--keepalive-requests", cmdline_arg_type_int,
            "Keepalive requests per connection (default " expand(KEEPALIVE_REQUESTS_DEFAULT) ")",
            [&](std::string s) { keepalive_requests = atoi(s.c_str()); return true; } },
        { "-K", "--keepalive-timeout", cmdline_arg_type_int,
            "Keepalive timeout seconds (default " expand(KEEPALIVE_TIMEOUT_DEFAULT) ")",
            [&](std::string s) { keepalive_timeout = atoi(s.c_str()); return true; } },
        { "-H", "--header-buffer-size", cmdline_arg_type_int,
            "Header Buffer Size (default " expand(HEADER_BUFFER_SIZE_DEFAULT) ")",
            [&](std::string s) { io_buffer_size = atoi(s.c_str()); return true; } },
        { "-B", "--io-buffer-size", cmdline_arg_type_int,
            "Input Ouput Buffer Size (default " expand(IO_BUFFER_SIZE_DEFAULT) ")",
            [&](std::string s) { header_buffer_size = atoi(s.c_str()); return true; } },
        { "-n", "--num-requests", cmdline_arg_type_int,
            "Number of requests to perform (default " expand(NUM_REQUESTS_DEFAULT) ")",
            [&](std::string s) { num_requests = atoi(s.c_str()); return true; } },
        { "-t", "--num-threads", cmdline_arg_type_int,
            "Number of threads (default hardware concurrency)",
            [&](std::string s) { num_threads = atoi(s.c_str()); return true; } },
        { "-p", "--per-request-stats", cmdline_arg_type_none,
            "Print statistics for every request",
            [&](std::string s) { return (per_request_stats = true); } },
        { nullptr, nullptr, cmdline_arg_type_none, nullptr, nullptr }
    };
    
    auto result = cmdline_option::process_options(options, argc, argv);
    if (!result.second) {
        help_or_error = true;
    } else if (result.first.size() != 1) {
        fprintf(stderr, "%s: wrong number of arguments\n", argv[0]);
        help_or_error = true;
    }
    if (help_or_error) {
        fprintf(stderr, "usage: %s [options] [http[s]://]hostname[:port]/path\n", argv[0]);
        cmdline_option::print_options(options);
        return false;
    }
    bench_url = result.first[0];
    return true;
}

void netb::run()
{
    // setup default config
    engine.cfg = std::make_shared<config>();
    engine.cfg->client_connections = client_connections;
    engine.cfg->connection_timeout = connection_timeout;
    engine.cfg->keepalive_timeout = keepalive_timeout;
    engine.cfg->header_buffer_size = header_buffer_size;
    engine.cfg->io_buffer_size = io_buffer_size;
    engine.cfg->proto_threads.push_back(std::pair<std::string,size_t>("http_client/connect", 1));
    engine.cfg->proto_threads.push_back(std::pair<std::string,size_t>("http_client/processor,http_client/keepalive", num_threads));
    
    // enable debug messages
    if (debug_level >= 1) {
        engine.debug_mask = (protocol_debug_engine |
                             protocol_debug_thread);
    }
    if (debug_level >= 2) {
        engine.debug_mask = (protocol_debug_event |
                             protocol_debug_socket |
                             protocol_debug_headers |
                             protocol_debug_message |
                             protocol_debug_handler |
                             protocol_debug_timeout);
    }
    
    // parse benchmark url
    url_ptr req_url(new url(bench_url));
    if (!req_url->valid) {
        fprintf(stderr, "error: invalid url: %s\n", bench_url.c_str());
        exit(1);
    }
    
    // run client
    const auto t1 = high_resolution_clock::now();
    engine.run();
    for (int i = 0; i < num_requests; i++) {
        auto handler = std::make_shared<netb_client_handler_file>(this);
        auto request = std::make_shared<http_client_request>(HTTPMethodGET, req_url, handler);
        http_client::submit_request(&engine, request, keepalive_requests);
    }
    engine.join();
    const auto t2 = high_resolution_clock::now();
    double secs = duration_cast<microseconds>(t2 - t1).count() / 1000000.0;
    printf("%9.6lf secs,  %d requests,  %lf reqs/sec,  %ld bytes transferred,  %lf MB/sec\n",
           secs,
           processed_requests.load(),
           processed_requests.load() / secs,
           bytes_transfered.load(),
           bytes_transfered.load() / secs / (1 << 20));
}


/* main */

int main(int argc, const char *argv[])
{
    netb bench;
    
    // parse command line arguments
    if (!bench.process_cmdline(argc, argv)) {
        exit(1);
    }
    
    // start benchmark client
    bench.run();
    
    return 0;
}
