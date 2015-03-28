#include "plat_os.h"

#include <cassert>
#include <cstdio>
#include <cerrno>
#include <string>

#include "log.h"
#include "config_cpu.h"

int main(int argc, const char * argv[])
{
    printf("hardware_concurrency=%d\n", config_cpu::hardware_concurrency());
}
