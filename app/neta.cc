//
//  neta.cc
//

#include "latypus.h"

/* neta
 *
 * example application server (work in progress)
 */

int main(int argc, const char * argv[])
{
    struct echo_fn : http_server_func {
        std::string operator()(http_server_connection *conn) {
            return std::string("echo ") + conn->request.get_request_path();
        }
    };
    
    protocol_engine engine;
    engine.default_config<http_server>();
    engine.bind_function<http_server,http_server_connection>("/echo/", echo_fn());
    engine.run();
    engine.join();
    
    return 0;
}
