/*
 * random_seed.c
 *
 * Copyright (c) 2013 Metaparadigm Pte. Ltd.
 * Michael Clark <michael@metaparadigm.com>
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 *
 */

#include <cstdio>
#include <cstdint>
#include <map>

#include "cpu.h"
#include "random_seed.h"

#define DEBUG_SEED(s)

/* has_rdrand */

#if HAS_X86_CPUID

static int has_rdrand()
{
    // CPUID.01H:ECX.RDRAND[bit 30] == 1
    int regs[4];
    x86_cpuid(regs, 1);
    return (regs[2] & (1 << 30)) != 0;
}

#endif

/* get_rdrand_seed - GCC x86 and X64 */

#if defined __GNUC__ && (defined __i386__ || defined __x86_64__)

#define HAVE_RDRAND 1

static int get_rdrand_seed()
{
    DEBUG_SEED("get_rdrand_seed");
    int _eax;
    // rdrand eax
    __asm__ __volatile__("1: .byte 0x0F\n"
                         "   .byte 0xC7\n"
                         "   .byte 0xF0\n"
                         "   jnc 1b;\n"
                         : "=a" (_eax));
    return _eax;
}

#if defined _MSC_VER

#if _MSC_VER >= 1700
#define HAVE_RDRAND 1

/* get_rdrand_seed - Visual Studio 2012 and above */

static int get_rdrand_seed()
{
    DEBUG_SEED("get_rdrand_seed");
    int r;
    while (_rdrand32_step(&r) == 0);
    return r;
}

#elif defined _M_IX86
#define HAVE_RDRAND 1

/* get_rdrand_seed - Visual Studio 2010 and below - x86 only */

static int get_rdrand_seed()
{
	DEBUG_SEED("get_rdrand_seed");
	int _eax;
retry:
	// rdrand eax
	__asm _emit 0x0F __asm _emit 0xC7 __asm _emit 0xF0
	__asm jnc retry
	__asm mov _eax, eax
	return _eax;
}

#endif
#endif

#endif /* defined ENABLE_RDRAND */


/* has_dev_urandom */

#if defined (__APPLE__) || defined(__unix__) || defined(__linux__)

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>

#define HAVE_DEV_RANDOM 1

static const char *dev_random_file = "/dev/urandom";

static int has_dev_urandom()
{
    struct stat buf;
    if (stat(dev_random_file, &buf)) {
        return 0;
    }
    return ((buf.st_mode & S_IFCHR) != 0);
}


/* get_dev_random_seed */

static int get_dev_random_seed()
{
    DEBUG_SEED("get_dev_random_seed");
    
    int fd = open(dev_random_file, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "error opening %s: %s", dev_random_file, strerror(errno));
        exit(1);
    }
    
    int r;
    ssize_t nread = read(fd, &r, sizeof(r));
    if (nread != sizeof(r)) {
        fprintf(stderr, "error read %s: %s", dev_random_file, strerror(errno));
        exit(1);
    }
    else if (nread != sizeof(r)) {
        fprintf(stderr, "error short read %s", dev_random_file);
        exit(1);
    }
    close(fd);
    return r;
}

#endif


/* get_cryptgenrandom_seed */

#ifdef WIN32

#define HAVE_CRYPTGENRANDOM 1

#include <windows.h>
#pragma comment(lib, "advapi32.lib")

static int get_cryptgenrandom_seed()
{
    DEBUG_SEED("get_cryptgenrandom_seed");
    
    HCRYPTPROV hProvider = 0;
    int r;
    
    if (!CryptAcquireContextW(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        fprintf(stderr, "error CryptAcquireContextW");
        exit(1);
    }
    
    if (!CryptGenRandom(hProvider, sizeof(r), (BYTE*)&r)) {
        fprintf(stderr, "error CryptGenRandom");
        exit(1);
    }
    
    CryptReleaseContext(hProvider, 0);
    
    return r;
}

#endif


/* get_random_seed */

uint32_t random_seed::get()
{
    
#if HAVE_RDRAND
    if (has_rdrand()) return get_rdrand_seed();
#endif
    
#if HAVE_DEV_RANDOM
    if (has_dev_urandom()) return get_dev_random_seed();
#endif
    
#if HAVE_CRYPTGENRANDOM
    return get_cryptgenrandom_seed();
#endif
    
    fprintf(stderr, "%s no entropy sources available\n", __func__);
    exit(9);
}
