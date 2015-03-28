#include "plat_os.h"
#include "plat_net.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cerrno>
#include <cassert>
#include <sstream>
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
#include "netdev.h"

int main(int argc, const char * argv[])
{
    netdev::init();
}
