//
//  neta.cc
//

#include "latypus.h"

/* neta */

int main(int argc, const char * argv[])
{
    http_constants::init();
    protocol::init();
    
    protocol_engine engine;
    engine.default_config("http_server");
    engine.run();
    engine.join();
    
    return 0;
}
