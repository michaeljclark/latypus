//
//  plat_os.h
//

#ifndef plat_os_h
#define plat_os_h

#include <ctype.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <poll.h>

#if defined (__FreeBSD__)
#include <pthread_np.h>
#endif

#endif
