//
//  config_sys.cc
//

#include "plat_os.h"

#include <cassert>
#include <cstdio>
#include <cerrno>
#include <string>
#include <thread>

#include "log.h"
#include "config_cpu.h"

int config_cpu::hardware_concurrency()
{
    return std::thread::hardware_concurrency();
}
