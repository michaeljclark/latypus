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
    http_constants::init();
    protocol::init();
    
    struct fn {
        void operator()(http_server_connection *conn)
        {
            std::string request_path = conn->request.get_request_path();
            //conn->response->set_response(200, "echo " + request_path);
        }
    };
    
    protocol_engine engine;
    engine.default_config("http_server");
    //engine.bind_function("http_server", "/echo/", fn());
    engine.run();
    engine.join();
    
    return 0;
}
